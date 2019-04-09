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
    result.pushKV("generationSignature", HexStr(pindexLast->GetNextGenerationSignature()));
    result.pushKV("baseTarget", std::to_string(pindexLast->nBaseTarget));

    return result;
}

static void SubmitNonce(UniValue &result, const uint64_t &nNonce, const uint64_t &nPlotterId, int nTargetHeight, const std::string &address, bool fCheckBind)
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
    uint64_t deadline = AddNonce(bestDeadline, *pBlockIndex, nNonce, nPlotterId, address, fCheckBind, Params().GetConsensus());
    if (deadline == poc::INVALID_DEADLINE) {
        result.pushKV("result", "error");
        result.pushKV("errorCode", "001");
        result.pushKV("errorDescription", "Invalid plotter ID");
    } else if (deadline == poc::INVALID_DEADLINE_NOTBIND) {
        result.pushKV("result", "error");
        result.pushKV("errorCode", "002");
        result.pushKV("errorDescription", "Not active bind plotter ID to address");
    } else {
        result.pushKV("result", "success");
        result.pushKV("deadline", deadline);
        result.pushKV("targetDeadline", (bestDeadline == 0 ? poc::MAX_TARGET_DEADLINE : bestDeadline));
        result.pushKV("height", pBlockIndex->nHeight + 1);
    }
}

static UniValue submitNonce(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "submitNonce \"nonce\" \"plotterId\" (height \"address\" checkBind)\n"
            "\nSubmit mining nonce.\n"
            "\nArguments:\n"
            "1. \"nonce\"           (string, required) Nonce\n"
            "2. \"plotterId\"       (string, required) Plotter ID\n"
            "3. \"height\"          (integer, optional) Target height for mining\n"
            "4. \"address\"         (string, optional) Target address for mining\n"
            "5. \"checkBind\"       (boolean, optional, true) Check bind for BHDIP006\n"
            "\nResult:\n"
            "{\n"
            "  [ result ]                  (string) Submit result: 'success' or others \n"
            "  [ deadline ]                (integer, optional) Current block generation signature\n"
            "  [ height ]                  (integer, optional) Target block height\n"
            "}\n"
        );
    }

    UniValue result(UniValue::VOBJ);
    if (request.params.size() < 2 || request.params.size() > 5) {
        result.pushKV("result", "Missing parameters");
        return result;
    }

    uint64_t nNonce = static_cast<uint64_t>(std::stoull(request.params[0].get_str()));
    uint64_t nPlotterId = static_cast<uint64_t>(std::stoull(request.params[1].get_str()));

    int nTargetHeight = 0;
    if (request.params.size() >= 3) {
        nTargetHeight = request.params[2].isNum() ? request.params[2].get_int() : std::stoi(request.params[2].get_str());
    }

    std::string address;
    if (request.params.size() >= 4) {
        address = request.params[3].get_str();
    }

    bool fCheckBind = true;
    if (request.params.size() >= 5) {
        fCheckBind = request.params[4].get_bool();
    }

    SubmitNonce(result, nNonce, nPlotterId, nTargetHeight, address, fCheckBind);
    return result;
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

    return PocLegacy::GeneratePlotterId(request.params[0].get_str());;
}

static UniValue getMinerAccount(const JSONRPCRequest& request)
{
    if (request.fHelp) {
        throw std::runtime_error(
            "getmineraccount\n"
            "\nGet new miner account.\n"
            "\nResult:\n"
            "{\n"
            "  [ passphrase ]              (string) The passphrase\n"
            "  [ plotterId ]               (string) The plotter ID from passphrase\n"
            "}\n"
        );
    }

    std::string passphrase = poc::generatePassPhrase();
    uint64_t plotterID = PocLegacy::GeneratePlotterId(passphrase);

    UniValue result(UniValue::VOBJ);
    result.pushKV("passphrase", passphrase);
    result.pushKV("plotterId", std::to_string(plotterID));
    return result;
}

}}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)                  argNames
  //  --------------------- ------------------------  -----------------------           ----------
    { "hidden",           "getMiningInfo",            &poc::rpc::getMiningInfo,         { } },
    { "hidden",           "submitNonce",              &poc::rpc::submitNonce,           { "nonce", "plotterId", "height", "address", "checkBind" } },
    { "hidden",           "getPlotterId",             &poc::rpc::getPlotterId,          { "passPhrase" } },
    { "hidden",           "getmineraccount",          &poc::rpc::getMinerAccount,       { } },
};

void RegisterPoCRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++) {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
