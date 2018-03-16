// Copyright (c) 2018 bitconore.org

#include <poc/poc.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <rpc/server.h>
#include <util.h>
#include <utilstrencodings.h>
#include <univalue.h>
#include <validation.h>

// Burst `getMiningInfo`
static UniValue GetMiningInfo(const JSONRPCRequest& request)
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

    LOCK(cs_main);
    const CBlockIndex *pindexLast = chainActive.Tip();
    if (pindexLast == nullptr) {
        throw std::runtime_error("Block chain tip is empty!");
    }
    if (pindexLast->nHeight + 1 < Params().GetConsensus().BCOHeight) {
        throw std::runtime_error("Not yet to the BCO fork height!");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("height", pindexLast->nHeight + 1);
    result.pushKV("generationSignature", HexStr(poc::GetBlockGenerationSignature(pindexLast->GetBlockHeader())));
    result.pushKV("baseTarget", std::to_string(pindexLast->nBits));

    return result;
}

// Burst `submitNonce`
static UniValue SubmitNonce(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "submitNonce \"nonce\" \"passPhrase\"\n"
            "\nSubmit mining nonce.\n"
            "\nArguments:\n"
            "1. \"nonce\"           (string, required) The digit string of the brust nonce\n"
            "2. \"passPhrase\"      (string, required) The string of the burst account passPhrase\n"
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

    LOCK(cs_main);
    const CBlockIndex *pBlockIndex = chainActive.Tip();
    if (pBlockIndex == nullptr) {
        throw std::runtime_error("Block chain tip is empty!");
    }

    if (pBlockIndex->nHeight + 1 < Params().GetConsensus().BCOHeight) {
        result.pushKV("result", "Not yet to the BCO fork height");
        return result;
    }

    const uint64_t nNonce = static_cast<uint64_t>(std::stoul(request.params[0].get_str()));
    const uint64_t nAccountId = poc::GetAccountIdByPassPhrase(request.params[1].get_str());

    uint64_t deadline;
    if (!poc::TryGenerateBlock(*pBlockIndex, nNonce, nAccountId, deadline)) {
        result.pushKV("result", "Generate failed");
        return result;
    }

    result.pushKV("result", "success");
    result.pushKV("deadline", deadline);
    return result;
}

// Burst `GetBlockchainStatus`
static UniValue GetBlockchainStatus(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ);

    LOCK(cs_main);
    const CBlockIndex *pBlockIndex = chainActive.Tip();
    if (pBlockIndex == nullptr) {
        throw std::runtime_error("Block chain tip is empty!");
    }

    result.push_back(Pair("application", PACKAGE_NAME));
    result.push_back(Pair("version", PACKAGE_VERSION));
    result.push_back(Pair("time", poc::GetEpochTime()));
    result.push_back(Pair("lastBlock", std::to_string(poc::GetBlockId(*pBlockIndex))));
    result.push_back(Pair("cumulativeDifficulty", pBlockIndex->nChainWork.GetLow64()));
    result.push_back(Pair("numberOfBlocks", pBlockIndex->nHeight + 1));
    result.push_back(Pair("lastBlockchainFeeder", ""));
    result.push_back(Pair("lastBlockchainFeederHeight", 0));
    result.push_back(Pair("isScanning", false));
    return result;
}

// Burst `getBlock`
static UniValue GetBlock(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ);
    if (request.params.size() == 0) {
        result.pushKV("result", "Missing block id");
        return result;
    }

    LOCK(cs_main);

    const uint64_t blockId = static_cast<uint64_t>(std::stoul(request.params[0].get_str()));

    CBlockIndex *pBlockIndex = nullptr;
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

    /*if (pBlockIndex->nHeight < Params().GetConsensus().BCOHeight) {
        result.pushKV("result", "Not yet to the BCO fork height");
        return result;
    }*/

    CBlock block;
    if (!ReadBlockFromDisk(block, pBlockIndex, Params().GetConsensus())) {
        result.pushKV("result", "Block not found on disk");
        return result;
    }

    CBlockIndex *pprevBlockIndex = pBlockIndex->nHeight > 0 ? chainActive[pBlockIndex->nHeight - 1] : nullptr;

    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("block", poc::GetBlockId(block)));
    result.push_back(Pair("blockSignature", "")); // N/A
    result.push_back(Pair("height", pBlockIndex->nHeight));
    result.push_back(Pair("baseTarget", std::to_string(block.nBits)));
    result.push_back(Pair("nonce", std::to_string(block.nNonce)));
    result.push_back(Pair("timestamp", (uint64_t)block.nTime));
    if (pprevBlockIndex != nullptr && pBlockIndex->nHeight >= Params().GetConsensus().BCOHeight) {
        const uint256 genSig = poc::GetBlockGenerationSignature(pprevBlockIndex->GetBlockHeader());
        result.push_back(Pair("scoopNum", (uint64_t)poc::GetBlockScoopNum(genSig, pBlockIndex->nHeight)));
        result.push_back(Pair("generator", std::to_string(poc::GetBlockGenerator(block))));
        result.push_back(Pair("generatorRS", poc::GetBlockGeneratorRS(block)));
        result.push_back(Pair("generatorPublicKey", ""));
        result.push_back(Pair("generationSignature", genSig.GetHex()));
    } else {
        result.push_back(Pair("scoopNum", 0));
        result.push_back(Pair("generator", ""));
        result.push_back(Pair("generatorRS", ""));
        result.push_back(Pair("generatorPublicKey", ""));
        result.push_back(Pair("generationSignature", ""));
    }

    result.push_back(Pair("payloadLength", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("payloadHash", "")); // N/A
    result.push_back(Pair("totalAmountNQT", ""));
    result.push_back(Pair("totalFeeNQT", 0));
    result.push_back(Pair("blockReward", ""));

    // transaction
    result.push_back(Pair("numberOfTransactions", (uint64_t)block.vtx.size()));
    UniValue txs(UniValue::VARR);
    for(const auto& tx : block.vtx)
    {
        txs.push_back(tx->GetHash().GetHex());
    }
    result.push_back(Pair("transactions", txs));

    result.push_back(Pair("requestProcessingTime", 0));

    // previous
    if (pBlockIndex->pprev != nullptr) {
        result.push_back(Pair("previousBlockHash", pBlockIndex->pprev->phashBlock->GetHex()));
        result.push_back(Pair("previousBlock", poc::GetBlockId(*(pBlockIndex->pprev))));
    }

    return result;
}

static UniValue GetAccountId(const JSONRPCRequest& request)
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


static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "burst",              "getMiningInfo",            &GetMiningInfo,      {} },
    { "burst",              "submitNonce",              &SubmitNonce,        {"nonce", "secretPhrase"} },
    { "burst",              "getBlockchainStatus",      &GetBlockchainStatus, {} },
    { "burst",              "getBlock",                 &GetBlock,           {"block"} },
    { "burst",              "getAccountId",             &GetAccountId,       {"id"} },
    
};

void RegisterBurstRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
