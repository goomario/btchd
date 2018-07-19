// Copyright (c) 2017-2018 The BTCHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poc/poc.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <rpc/server.h>
#include <util.h>
#include <utilstrencodings.h>
#include <univalue.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>
#include <rpc/safemode.h>
#include <net.h>
#include <utilmoneystr.h>
#include <consensus/validation.h>
#include <base58.h>
#include <sstream>
#include <iomanip>


void SendMoney(CWallet * const pwallet, const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CCoinControl& coin_control);

namespace poc {
namespace rpc {

static UniValue getMiningInfo(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "getMiningInfo\n"
            "\nGet current mining information.\n"
            "\nResult:\n"
            "{\n"
            "  [ height ]                  (integer) Next block height\n"
            "  [ generationSignature ]     (string) Current block generation signature\n"
            "  [ baseTarget ]              (string) Current block base target \n"
            "}\n"
        );
    }

    if (IsInitialBlockDownload()) {
        throw std::runtime_error("Is initial block downloading!");
    }

    LOCK(cs_main);
    const CBlockIndex *pindexLast = chainActive.Tip();
    if (pindexLast == nullptr) {
        throw std::runtime_error("Block chain tip is empty!");
    }

    if (pindexLast->nHeight >= Params().GetConsensus().BtchdNoMortgageHeight) {
        throw std::runtime_error("This version not support mortgage feature. Please check http://btchd.net.");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("height", pindexLast->nHeight + 1);
    result.pushKV("generationSignature", HexStr(poc::GetBlockGenerationSignature(pindexLast->GetBlockHeader())));
    result.pushKV("baseTarget", std::to_string(pindexLast->nBaseTarget));

    return result;
}

static void SubmitNonce(UniValue &result, const uint64_t &nNonce, const uint64_t &nAccountId)
{
    if (IsInitialBlockDownload()) {
        throw std::runtime_error("Is initial block downloading!");
    }

    LOCK(cs_main);
    const CBlockIndex *pindexLast = chainActive.Tip();
    if (pindexLast == nullptr) {
        throw std::runtime_error("Block chain tip is empty!");
    }

    if (pindexLast->nHeight >= Params().GetConsensus().BtchdNoMortgageHeight) {
        throw std::runtime_error("This version not support mortgage feature. Please check http://btchd.net.");
    }

    uint64_t deadline = std::numeric_limits<uint64_t>::max();
    if (!poc::TryGenerateBlock(*pindexLast, nNonce, nAccountId, deadline, Params().GetConsensus())) {
        result.pushKV("result", "Generate failed");
        return;
    }

    result.pushKV("result", "success");
    result.pushKV("deadline", deadline);
}

static UniValue submitNonceToPool(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "submitNonce \"nonce\" \"accountId\"\n"
            "\nSubmit mining nonce.\n"
            "\nArguments:\n"
            "1. \"nonce\"           (string, required) The digit string of the brust nonce\n"
            "2. \"accountId\"       (string, optional) The digit string of the brust account ID\n"
            "\nResult:\n"
            "{\n"
            "  [ result ]                  (string) Submit result: 'success' or others \n"
            "  [ deadline ]                (integer, optional) Current block generation signature\n"
            "}\n"
        );
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() != 3) {
        result.pushKV("result", "Missing parameters");
        return result;
    }

    SubmitNonce(result, 
        static_cast<uint64_t>(std::stoull(request.params[0].get_str())), 
        static_cast<uint64_t>(std::stoull(request.params[1].get_str())));

    return result;
}

static UniValue submitNonceAsSolo(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "submitNonce \"nonce\" \"passPhrase\"\n"
            "\nSubmit mining nonce.\n"
            "\nArguments:\n"
            "1. \"nonce\"           (string, required) The digit string of the brust nonce\n"
            "2. \"passPhrase\"      (string, optional) The string of the burst account passPhrase\n"
            "\nResult:\n"
            "{\n"
            "  [ result ]                  (string) Submit result: 'success' or others \n"
            "  [ deadline ]                (integer, optional) Current block generation signature\n"
            "}\n"
        );
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() != 2) {
        result.pushKV("result", "Missing parameters");
        return result;
    }

    SubmitNonce(result,
        static_cast<uint64_t>(std::stoull(request.params[0].get_str())),
        poc::GetAccountIdByPassPhrase(request.params[1].get_str()));

    return result;
}

static UniValue getConstants(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ);

    uint64_t blockId = 0, accountId = 0; 
    int height = 0;
    CBlockIndex * pBlockIndex = chainActive[height];

    if (pBlockIndex) {
        blockId = poc::GetBlockId(*pBlockIndex);
        accountId = pBlockIndex->GetBlockHeader().nPlotterId;
    } else {
        LogPrintf("Not find BTCHD fork height block:%ld\n", height);
        auto genesis = Params().GenesisBlock();
        blockId = poc::GetBlockId(genesis);
        accountId = genesis.nPlotterId;
    }

    result.pushKV("genesisBlockId", std::to_string(blockId));
    result.pushKV("genesisAccountId", std::to_string(accountId));
    return result;
}

static UniValue getBlockchainStatus(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ);

    LOCK(cs_main);
    const CBlockIndex *pBlockIndex = chainActive.Tip();
    if (pBlockIndex == nullptr) {
        throw std::runtime_error("Block chain tip is empty!");
    }

    result.push_back(Pair("application", PACKAGE_NAME));
    result.push_back(Pair("version", PACKAGE_VERSION));
    result.push_back(Pair("lastBlock", std::to_string(poc::GetBlockId(*pBlockIndex))));
    result.push_back(Pair("cumulativeDifficulty", pBlockIndex->nChainWork.GetLow64()));
    result.push_back(Pair("numberOfBlocks", pBlockIndex->nHeight + 1));
    result.push_back(Pair("lastBlockchainFeeder", ""));
    result.push_back(Pair("lastBlockchainFeederHeight", 0));
    result.push_back(Pair("isScanning", false));
    return result;
}

static void FillBlockInfo(CBlockIndex* pBlockIndex, UniValue& result)
{
    CBlock block;
    if (!ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())) {
        result.pushKV("result", "Block not found on disk");
        return;
    }

    CBlockIndex *pprevBlockIndex = pBlockIndex->nHeight > 0 ? chainActive[pBlockIndex->nHeight - 1] : nullptr;

    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("block", poc::GetBlockId(block)));
    result.push_back(Pair("blockSignature", "")); // N/A
    result.push_back(Pair("height", pBlockIndex->nHeight));
    result.push_back(Pair("baseTarget", std::to_string(block.nBaseTarget)));
    result.push_back(Pair("nonce", std::to_string(block.nNonce)));
    result.push_back(Pair("timestamp", (uint64_t)block.nTime));
    if (pprevBlockIndex != nullptr) {
        const uint256 genSig = poc::GetBlockGenerationSignature(pprevBlockIndex->GetBlockHeader());
        result.push_back(Pair("scoopNum", (uint64_t)poc::GetBlockScoopNum(genSig, pBlockIndex->nHeight)));
        result.push_back(Pair("generator", std::to_string(poc::GetBlockGenerator(block))));
        result.push_back(Pair("generatorRS", poc::GetBlockGeneratorRS(block)));
        result.push_back(Pair("generationSignature", genSig.GetHex()));
    }
    else {
        result.push_back(Pair("scoopNum", 0));
        result.push_back(Pair("generator", ""));
        result.push_back(Pair("generatorRS", ""));
        result.push_back(Pair("generationSignature", ""));
    }

    result.push_back(Pair("payloadLength", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("payloadHash", "")); // N/A
    result.push_back(Pair("totalAmountNQT", "")); 
    result.push_back(Pair("totalFeeNQT", 0));

    // transaction
    result.push_back(Pair("numberOfTransactions", (uint64_t)block.vtx.size()));
    UniValue txs(UniValue::VARR);
    CAmount coinbaseReward = 0;
    for (const auto& tx : block.vtx)
    {
        if (tx->IsCoinBase()) {
            coinbaseReward = tx->GetValueOut();
        }
        txs.push_back(tx->GetHash().GetHex());
    }

    std::stringstream ss;
    ss << std::fixed << std::setprecision(8) << double(coinbaseReward) / COIN;

    result.push_back(Pair("blockReward", ss.str()));
    result.push_back(Pair("transactions", txs));
    result.push_back(Pair("generatorPublicKey", ""));

    // previous
    if (pBlockIndex->pprev != nullptr) {
        result.push_back(Pair("previousBlockHash", pBlockIndex->pprev->phashBlock->GetHex()));
        result.push_back(Pair("previousBlock", poc::GetBlockId(*(pBlockIndex->pprev))));
    }
}

static UniValue getBlockById(const uint64_t blockId)
{
    CBlockIndex *pBlockIndex = nullptr;
    UniValue result(UniValue::VOBJ);
    for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        if (poc::GetBlockId(*(item.second)) == blockId) {
            pBlockIndex = item.second;
            break;
        }
    }

    if (pBlockIndex == nullptr) {
        result.pushKV("result", "Block not found");
        return result;
    }
    FillBlockInfo(pBlockIndex, result);

    return result;
}

static UniValue getBlockByHeight(int height)
{
    UniValue result(UniValue::VOBJ);
    CBlockIndex *pBlockIndex = chainActive[height];
    if (pBlockIndex == nullptr) {
        result.pushKV("result", "Block height not found ");
        return result;
    }
    FillBlockInfo(pBlockIndex, result);

    return result;
}

static UniValue getLastBlock()
{
    UniValue result(UniValue::VOBJ);
    CBlockIndex *pBlockIndex = chainActive.Tip();
    if (pBlockIndex == nullptr) {
        result.pushKV("result", "Last block not found ");
        return result;
    }
    FillBlockInfo(pBlockIndex, result);

    return result;
}

static UniValue getBlockByTimeStamp(int64_t timestamp)
{
    UniValue result(UniValue::VOBJ);
    //TODO
    return result;
}

static UniValue getBlock(const JSONRPCRequest& request)
{
    if (request.params.size() != 3) {
        UniValue result(UniValue::VOBJ);
        result.pushKV("result", "params size error");
        return result;
    }

    LOCK(cs_main);

    std::string strBlockId = request.params[0].get_str();
    std::string strHeight = request.params[1].get_str();
    std::string strTimestamp = request.params[2].get_str();

    if (!strBlockId.empty()) return getBlockById(static_cast<uint64_t>(std::stoull(strBlockId)));
    if (!strHeight.empty()) return getBlockByHeight(static_cast<int>(std::stol(strHeight)));
    //if (!strTimestamp.empty()) return getBlockByTimeStamp(static_cast<int64_t>(std::stoll(strTimestamp)));
    return getLastBlock();
}

static UniValue getAccountId(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "getAccountId \"passPhrase\"\n"
            "\nGet account digital id from passphrase.\n"
            "\nArguments:\n"
            "1. \"passPhrase\"      (string, required) The string of the burst account passPhrase\n"
            "\nResult:\n"
            "Id\n"
        );
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() != 1) {
        result.pushKV("result", "Missing parameters");
        return result;
    }
    const uint64_t nAccountId = poc::GetAccountIdByPassPhrase(request.params[0].get_str());
    return nAccountId;
}

static UniValue getAccount(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "getAccount \"passPhrase\"\n"
            "\nGet account digital id from passphrase.\n"
            "\nArguments:\n"
            "1. \"passPhrase\"      (string, required) The string of the burst account passPhrase\n"
            "\nResult:\n"
            "Id\n"
        );
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() != 1) {
        result.pushKV("result", "Missing parameters");
        return result;
    }
    uint64_t nAccountId = poc::parseAccountId(request.params[0].get_str());

    //TODO not use account as design meeting
    result.pushKV("unconfirmedBalanceNQT", "");
    result.pushKV("guaranteedBalanceNQT" , "");
    result.pushKV("accountRS", "BURST-");
    result.pushKV("forgedBalanceNQT", "");
    result.pushKV("balanceNQT", "");
    result.pushKV("publicKey", "");
    result.pushKV("effectiveBalanceBURST", "");
    result.pushKV("account" , std::to_string(nAccountId));
    return result;
}

static UniValue getTime(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("time", GetAdjustedTime());
    return result;
}

static bool IsOwnKey(CWallet * const pwallet, const CScript& scriptPubKey)
{
    CTxDestination addr;
    if (!ExtractDestination(scriptPubKey, addr))
        return false;
    if (!IsValidDestination(addr)) {
        return false;
    }
    auto keyid = GetKeyForDestination(*pwallet, addr);
    if (keyid.IsNull()) {
        return false;
    }
    CKey vchSecret;
    if (!pwallet->GetKey(keyid, vchSecret)) {
        return false;
    }
    return true;
}

static bool IsOwnBlockOfHeight(CWallet * const pwallet, int height)
{
    CBlockIndex *pBlockIndex = chainActive[height];
    if (pBlockIndex == nullptr) return false;

    CBlock block;
    if (!ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())) 
        return false;

    for (const auto& tx : block.vtx)
    {
        if (tx->IsCoinBase())
            return IsOwnKey(pwallet, tx->vout[0].scriptPubKey);
    }
    return false;
}

static UniValue getRewardRecipient(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() != 2) {
        result.pushKV("result", "Missing parameters");
        return result;
    }
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strHeight = request.params[1].get_str();
    bool bOwn = IsOwnBlockOfHeight(pwallet, static_cast<int>(std::stol(strHeight.c_str())));
    uint64_t pubkey = 0;
    if( bOwn) 
        pubkey = poc::GetAccountIdByPassPhrase(request.params[0].get_str());

    result.pushKV("rewardRecipient", std::to_string(pubkey));

    return result;
}

static UniValue sendMoney(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        LogPrintf("Get wallet fail\n");
        return NullUniValue;
    }

    if (request.fHelp) {
        throw std::runtime_error(
            "sendMoney parameter help\n"
        );
    }

    if (request.params.size() != 4) {
        throw std::runtime_error(
            "sendMoney parameter size error\n"
        );
    }
    // "recipient", "recipaddr", "feeNQT" , "amountNQT"
    std::string recipaddr = request.params[1].get_str();

    CAmount feeNQT = AmountFromValue(request.params[2]);

    CAmount amountNQT = AmountFromValue(request.params[3]);

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(recipaddr);
    if (!IsValidDestination(dest)) {
        LogPrintf("%s invalid\n", recipaddr.c_str());
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    CAmount nAmount = amountNQT;
    if (nAmount <= 0) {
        LogPrintf("Amount %ld invalid\n", nAmount);
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    }

    CWalletTx wtx;
    CCoinControl coin_control;

    EnsureWalletIsUnlocked(pwallet);

    // Substract fee from receiver
    bool fSubtractFeeFromAmount = true; 
    ::SendMoney(pwallet, dest, nAmount, fSubtractFeeFromAmount, wtx, coin_control);

    UniValue res(UniValue::VOBJ);
    res.pushKV("transaction", wtx.GetHash().GetHex());
    return res;
}

static UniValue getGuaranteedBalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error("getGuaranteedBalance param error!");

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue result(UniValue::VOBJ);
    result.pushKV("guaranteedBalanceNQT", std::to_string(pwallet->GetBalance()));
    return result;
}

static UniValue checkAddressValid(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "checkAddressValid parameter help\n"
        );
    }
    if (request.params.size() != 1) {
        throw std::runtime_error(
            "checkAddressValid parameter size != 1\n"
        );
    }

    std::string addr = request.params[0].get_str();
    CTxDestination dest = DecodeDestination(addr);

    UniValue res(UniValue::VOBJ);
    res.pushKV("valid", IsValidDestination(dest) );
    return res;
}
}// namespace rpc
}// namespace poc

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)                  argNames
  //  --------------------- ------------------------  -----------------------           ----------
    { "poc",              "getMiningInfo",            &poc::rpc::getMiningInfo,         { } },
    { "poc",              "submitNonceToPool",        &poc::rpc::submitNonceToPool,     { "nonce", "accountId" } },
    { "poc",              "submitNonceAsSolo",        &poc::rpc::submitNonceAsSolo,     { "nonce", "secretPhrase"} },
    { "poc",              "getConstants",             &poc::rpc::getConstants,          { } },
    { "poc",              "getBlockchainStatus",      &poc::rpc::getBlockchainStatus,   { } },
    { "poc",              "getBlock",                 &poc::rpc::getBlock,              { "block", "height", "timestamp"} },
    { "poc",              "getAccountId",             &poc::rpc::getAccountId,          { "passPhrase" } },
    { "poc",              "getAccount",               &poc::rpc::getAccount,            { "account" } },
    { "poc",              "getTime",                  &poc::rpc::getTime,               { } },
    { "poc",              "getRewardRecipient",       &poc::rpc::getRewardRecipient,    { "account", "height" } },
    { "poc",              "sendMoney",                &poc::rpc::sendMoney,             { "recipient", "recipaddr", "feeNQT" , "amountNQT"} },
    { "poc",              "getGuaranteedBalance",     &poc::rpc::getGuaranteedBalance,  { "account", "numberOfConfirmations" } },
    { "poc",              "checkAddressValid",        &poc::rpc::checkAddressValid,     { "addr" } },
};

void RegisterBurstRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
