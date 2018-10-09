// Copyright (c) 2017-2018 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poc/poc.h>
#include <base58.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <net.h>
#include <poc/passphrase.h>
#include <rpc/safemode.h>
#include <rpc/server.h>
#include <util.h>
#include <utilstrencodings.h>
#include <univalue.h>
#include <validation.h>

#include <iomanip>
#include <sstream>

namespace poc { namespace rpc {

static UniValue getMinerAccount(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "getmineraccount\n"
            "\nGet new miner account.\n"
            "\nResult:\n"
            "{\n"
            "  [ passphrase ]              (string) Passphrase\n"
            "  [ accountId ]               (string) Account ID\n"
            "}\n"
        );
    }

    std::string passphrase = poc::generatePassPhrase();
    uint64_t nAccountId = poc::GetAccountIdByPassPhrase(passphrase);

    UniValue result(UniValue::VOBJ);
    result.pushKV("passphrase", passphrase);
    result.pushKV("accountId", std::to_string(nAccountId));
    return result;
}

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

    UniValue result(UniValue::VOBJ);
    result.pushKV("height", pindexLast->nHeight + 1);
    result.pushKV("generationSignature", HexStr(poc::GetBlockGenerationSignature(pindexLast->GetBlockHeader())));
    result.pushKV("baseTarget", std::to_string(pindexLast->nBaseTarget));
    result.pushKV("targetDeadline", poc::MAX_TARGET_DEADLINE);

    return result;
}

static void SubmitNonce(UniValue &result, const uint64_t &nNonce, const uint64_t &nAccountId, int nTargetHeight, const std::string &address)
{
    if (IsInitialBlockDownload()) {
        throw std::runtime_error("Is initial block downloading!");
    }

    LOCK(cs_main);
    const CBlockIndex *pBlockIndex = chainActive[nTargetHeight < 1 ? chainActive.Height() : (nTargetHeight - 1)];
    if (pBlockIndex == nullptr) {
        throw std::runtime_error("Invalid block!");
    }

    uint64_t bestDeadline = 0;
    uint64_t deadline = AddNonce(bestDeadline, *pBlockIndex, nNonce, nAccountId, address, Params().GetConsensus());

    result.pushKV("result", "success");
    result.pushKV("deadline", deadline);
    result.pushKV("targetDeadline", (bestDeadline == 0 ? poc::MAX_TARGET_DEADLINE : bestDeadline));
    result.pushKV("height", pBlockIndex->nHeight + 1);
}

static UniValue submitNonceToPool(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "submitNonceToPool \"nonce\" \"accountId\" height \"address\"\n"
            "\nSubmit mining nonce.\n"
            "\nArguments:\n"
            "1. \"nonce\"           (string, required) The digit string of the brust nonce\n"
            "2. \"accountId\"       (string, required) The digit string of the brust account ID\n"
            "3. \"height\"          (integer, optional) Target height for mining\n"
            "4. \"address\"         (string, optional) Target address for mining\n"
            "\nResult:\n"
            "{\n"
            "  [ result ]                  (string) Submit result: 'success' or others \n"
            "  [ deadline ]                (integer, optional) Current block generation signature\n"
            "  [ height ]                  (integer, optional) Target block height\n"
            "}\n"
        );
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() < 2 || request.params.size() > 4) {
        result.pushKV("result", "Missing parameters");
        return result;
    }

    uint64_t nNonce = static_cast<uint64_t>(std::stoull(request.params[0].get_str()));
    uint64_t nAccountId = static_cast<uint64_t>(std::stoull(request.params[1].get_str()));

    int nTargetHeight = 0;
    if (request.params.size() >= 3) {
        nTargetHeight = request.params[2].isNum() ? request.params[2].get_int() : std::stoi(request.params[2].get_str());
    }

    std::string address;
    if (request.params.size() >= 4) {
        address = request.params[3].get_str();
    }

    SubmitNonce(result, nNonce, nAccountId, nTargetHeight, address);
    return result;
}

static UniValue submitNonceAsSolo(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "submitNonceAsSolo \"nonce\" \"passphrase\" height \"address\"\n"
            "\nSubmit mining nonce.\n"
            "\nArguments:\n"
            "1. \"nonce\"           (string, required) The digit string of the brust nonce\n"
            "2. \"passphrase\"      (string, optional) The string of the passphrase.\n"
            "3. \"height\"          (integer, optional) Target height for mining\n"
            "4. \"address\"         (string, optional) Target address for mining\n"
            "\nResult:\n"
            "{\n"
            "  [ result ]                  (string) Submit result: 'success' or others \n"
            "  [ deadline ]                (integer, optional) Current block generation signature\n"
            "  [ height ]                  (integer, optional) Target block height\n"
            "}\n"
        );
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() < 2 || request.params.size() > 4) {
        result.pushKV("result", "Missing parameters");
        return result;
    }

    uint64_t nNonce = static_cast<uint64_t>(std::stoull(request.params[0].get_str()));
    uint64_t nAccountId = poc::GetAccountIdByPassPhrase(request.params[1].get_str());

    int nTargetHeight = 0;
    if (request.params.size() >= 3) {
        nTargetHeight = request.params[2].isNum() ? request.params[2].get_int() : std::stoi(request.params[2].get_str());
    }

    std::string address;
    if (request.params.size() >= 4) {
        address = request.params[3].get_str();
    }

    SubmitNonce(result, nNonce, nAccountId, nTargetHeight, address);
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
        LogPrintf("Not find BitcoinHD fork height block:%ld\n", height);
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
            coinbaseReward = tx->vout[0].nValue;
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
    return getLastBlock();
}

static UniValue getPlotterId(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "getPlotterId \"passphrase\"\n"
            "\nGet potter id from passphrase.\n"
            "\nArguments:\n"
            "1. \"passphrase\"      (string, required) The string of the passphrase\n"
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

}}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)                  argNames
  //  --------------------- ------------------------  -----------------------           ----------
    { "hidden",           "getmineraccount",          &poc::rpc::getMinerAccount,       { } },
    { "hidden",           "getMinerAccount",          &poc::rpc::getMinerAccount,       { } },
    { "hidden",           "getMiningInfo",            &poc::rpc::getMiningInfo,         { } },
    { "hidden",           "submitNonceToPool",        &poc::rpc::submitNonceToPool,     { "nonce", "accountId", "height", "address" } },
    { "hidden",           "submitNonceAsSolo",        &poc::rpc::submitNonceAsSolo,     { "nonce", "secretPhrase", "height", "address" } },
    { "hidden",           "getConstants",             &poc::rpc::getConstants,          { } },
    { "hidden",           "getBlockchainStatus",      &poc::rpc::getBlockchainStatus,   { } },
    { "hidden",           "getBlock",                 &poc::rpc::getBlock,              { "block", "height", "timestamp"} },
    { "hidden",           "getPlotterId",             &poc::rpc::getPlotterId,          { "passPhrase" } },
};

void RegisterPoCRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
