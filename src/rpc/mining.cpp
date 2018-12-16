// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <init.h>
#include <validation.h>
#include <miner.h>
#include <net.h>
#include <poc/poc.h>
#include <policy/fees.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <txdb.h>
#include <txmempool.h>
#include <util.h>
#include <utilstrencodings.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <map>
#include <memory>
#include <string>
#include <stdint.h>

unsigned int ParseConfirmTarget(const UniValue& value)
{
    int target = value.get_int();
    unsigned int max_target = ::feeEstimator.HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    if (target < 1 || (unsigned int)target > max_target) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid conf_target, must be between %u - %u", 1, max_target));
    }
    return (unsigned int)target;
}

UniValue generateBlocks(std::shared_ptr<CReserveScript> coinbaseScript, int nGenerate, bool keepScript)
{
    const uint64_t nNonce = 0, nPlotterId = 0, nDeadline = 0;

    int nHeightEnd = 0;
    int nHeight = 0;
    
    {   // Don't keep cs_main locked
        LOCK(cs_main);
        nHeight = chainActive.Height();
        nHeightEnd = nHeight + nGenerate;
    }
    while (nHeight < nHeightEnd) {
        ++nHeight;

        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript, true, nNonce, nPlotterId, nDeadline));
        if (!pblocktemplate.get())
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        CBlock *pblock = &pblocktemplate->block;
        
        CMutableTransaction txCoinbase(*pblock->vtx[0]);
        txCoinbase.vin[0].scriptSig = (CScript() << nHeight<< CScriptNum(static_cast<int64_t>(nNonce)) << CScriptNum(static_cast<int64_t>(nPlotterId))) + COINBASE_FLAGS;
        assert(txCoinbase.vin[0].scriptSig.size() <= 100);

        pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

        if (nHeight <= Params().GetConsensus().BHDIP001StartMingingHeight) {
            // Update nBaseTarget because nTime has changed
            LOCK(cs_main);
            pblock->nTime = chainActive.Tip()->nTime + 1;
            pblock->nBaseTarget = GetNextWorkRequired(chainActive.Tip(), pblock, Params().GetConsensus());
        }

        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");

        //mark script as important because it was used at least for one coinbase output if the script came from the wallet
        if (keepScript)
        {
            coinbaseScript->KeepScript();
        }
    }

    return UniValue();
}

UniValue generatetoaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "generatetoaddress nblocks address\n"
            "\nMine blocks immediately to a specified address (before the RPC call returns)\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. address      (string, required) The address to send the newly generated BitcoinHD to.\n"
            "\nResult:\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
        );

    int nGenerate = request.params[0].get_int();

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    std::shared_ptr<CReserveScript> coinbaseScript = std::make_shared<CReserveScript>();
    coinbaseScript->reserveScript = GetScriptForDestination(destination);

    return generateBlocks(coinbaseScript, nGenerate, false);
}

UniValue getmininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getmininginfo\n"
            "\nReturns a json object containing mining-related information."
            "\nResult:\n"
            "{\n"
            "  \"blocks\": nnn,             (numeric) The current block\n"
            "  \"currentblockweight\": nnn, (numeric) The last block weight\n"
            "  \"currentblocktx\": nnn,     (numeric) The last block transaction\n"
            "  \"difficulty\": xxx.xxxxx    (numeric) The current difficulty\n"
            "  \"pooledtx\": n              (numeric) The size of the mempool\n"
            "  \"chain\": \"xxxx\",           (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"warnings\": \"...\"          (string) any network and blockchain warnings\n"
            "  \"errors\": \"...\"            (string) DEPRECATED. Same as warnings. Only shown when bitcoind is started with -deprecatedrpc=getmininginfo\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
        );


    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("blocks",           (int)chainActive.Height()));
    obj.push_back(Pair("currentblockweight", (uint64_t)nLastBlockWeight));
    obj.push_back(Pair("currentblocktx",   (uint64_t)nLastBlockTx));
    obj.push_back(Pair("difficulty",       (double)GetDifficulty()));
    obj.push_back(Pair("pooledtx",         (uint64_t)mempool.size()));
    obj.push_back(Pair("chain",            Params().NetworkIDString()));
    if (IsDeprecatedRPCEnabled("getmininginfo")) {
        obj.push_back(Pair("errors",       GetWarnings("statusbar")));
    } else {
        obj.push_back(Pair("warnings",     GetWarnings("statusbar")));
    }
    return obj;
}


// NOTE: Unlike wallet RPC (which use BitcoinHD values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
UniValue prioritisetransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
            "prioritisetransaction <txid> <dummy value> <fee delta>\n"
            "Accepts the transaction into mined blocks at a higher (or lower) priority\n"
            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id.\n"
            "2. dummy          (numeric, optional) API-Compatibility for previous API. Must be zero or null.\n"
            "                  DEPRECATED. For forward compatibility use named arguments and omit this parameter.\n"
            "3. fee_delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee.\n"
            "\nResult:\n"
            "true              (boolean) Returns true\n"
            "\nExamples:\n"
            + HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
        );

    LOCK(cs_main);

    uint256 hash = ParseHashStr(request.params[0].get_str(), "txid");
    CAmount nAmount = request.params[2].get_int64();

    if (!(request.params[1].isNull() || request.params[1].get_real() == 0)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.");
    }

    mempool.PrioritiseTransaction(hash, nAmount);
    return true;
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid())
    {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

std::string gbt_vb_name(const Consensus::DeploymentPos pos) {
    const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
    std::string s = vbinfo.name;
    if (!vbinfo.gbt_force) {
        s.insert(s.begin(), '!');
    }
    return s;
}

UniValue getblocktemplate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getblocktemplate ( TemplateRequest )\n"
            "\nIf the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.\n"
            "It returns data needed to construct a block to work on.\n"
            "For full specification, see BIPs 22, 23, 9, and 145:\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0022.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0023.mediawiki\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki#getblocktemplate_changes\n"
            "    https://github.com/bitcoin/bips/blob/master/bip-0145.mediawiki\n"

            "\nArguments:\n"
            "1. template_request         (json object, optional) A json object in the following spec\n"
            "     {\n"
            "       \"mode\":\"template\"    (string, optional) This must be set to \"template\", \"proposal\" (see BIP 23), or omitted\n"
            "       \"capabilities\":[     (array, optional) A list of strings\n"
            "           \"support\"          (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'\n"
            "           ,...\n"
            "       ],\n"
            "       \"rules\":[            (array, optional) A list of strings\n"
            "           \"support\"          (string) client side supported softfork deployment\n"
            "           ,...\n"
            "       ]\n"
            "     }\n"
            "\n"

            "\nResult:\n"
            "{\n"
            "  \"version\" : n,                    (numeric) The preferred block version\n"
            "  \"rules\" : [ \"rulename\", ... ],    (array of strings) specific block rules that are to be enforced\n"
            "  \"vbavailable\" : {                 (json object) set of pending, supported versionbit (BIP 9) softfork deployments\n"
            "      \"rulename\" : bitnumber          (numeric) identifies the bit number as indicating acceptance and readiness for the named softfork rule\n"
            "      ,...\n"
            "  },\n"
            "  \"vbrequired\" : n,                 (numeric) bit mask of versionbits the server requires set in submissions\n"
            "  \"previousblockhash\" : \"xxxx\",     (string) The hash of current highest block\n"
            "  \"transactions\" : [                (array) contents of non-coinbase transactions that should be included in the next block\n"
            "      {\n"
            "         \"data\" : \"xxxx\",             (string) transaction data encoded in hexadecimal (byte-for-byte)\n"
            "         \"txid\" : \"xxxx\",             (string) transaction id encoded in little-endian hexadecimal\n"
            "         \"hash\" : \"xxxx\",             (string) hash encoded in little-endian hexadecimal (including witness data)\n"
            "         \"depends\" : [                (array) array of numbers \n"
            "             n                          (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is\n"
            "             ,...\n"
            "         ],\n"
            "         \"fee\": n,                    (numeric) difference in value between transaction inputs and outputs (in satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one\n"
            "         \"sigops\" : n,                (numeric) total SigOps cost, as counted for purposes of block limits; if key is not present, sigop cost is unknown and clients MUST NOT assume it is zero\n"
            "         \"weight\" : n,                (numeric) total transaction weight, as counted for purposes of block limits\n"
            "         \"required\" : true|false      (boolean) if provided and true, this transaction must be in the final block\n"
            "      }\n"
            "      ,...\n"
            "  ],\n"
            "  \"coinbaseaux\" : {                 (json object) data that should be included in the coinbase's scriptSig content\n"
            "      \"flags\" : \"xx\"                  (string) key name is to be ignored, and value included in scriptSig\n"
            "  },\n"
            "  \"coinbasevalue\" : n,              (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in satoshis)\n"
            "  \"coinbasetxn\" : { ... },          (json object) information for coinbase transaction\n"
            "  \"target\" : \"xxxx\",                (string) The hash target\n"
            "  \"mintime\" : xxx,                  (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mutable\" : [                     (array of string) list of ways the block template may be changed \n"
            "     \"value\"                          (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'\n"
            "     ,...\n"
            "  ],\n"
            "  \"noncerange\" : \"00000000ffffffff\",(string) A range of valid nonces\n"
            "  \"sigoplimit\" : n,                 (numeric) limit of sigops in blocks\n"
            "  \"sizelimit\" : n,                  (numeric) limit of block size\n"
            "  \"weightlimit\" : n,                (numeric) limit of block weight\n"
            "  \"curtime\" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"bits\" : \"xxxxxxxx\",              (string) compressed target of next block\n"
            "  \"height\" : n                      (numeric) The height of the next block\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getblocktemplate", "")
            + HelpExampleRpc("getblocktemplate", "")
         );

    LOCK(cs_main);

    std::string strMode = "template";
    UniValue lpval = NullUniValue;
    std::set<std::string> setClientRules;
    int64_t nMaxVersionPreVB = -1;
    if (!request.params[0].isNull())
    {
        const UniValue& oparam = request.params[0].get_obj();
        const UniValue& modeval = find_value(oparam, "mode");
        if (modeval.isStr())
            strMode = modeval.get_str();
        else if (modeval.isNull())
        {
            /* Do nothing */
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
        lpval = find_value(oparam, "longpollid");

        if (strMode == "proposal")
        {
            const UniValue& dataval = find_value(oparam, "data");
            if (!dataval.isStr())
                throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");

            CBlock block;
            if (!DecodeHexBlk(block, dataval.get_str()))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

            uint256 hash = block.GetHash();
            BlockMap::iterator mi = mapBlockIndex.find(hash);
            if (mi != mapBlockIndex.end()) {
                CBlockIndex *pindex = mi->second;
                if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                    return "duplicate";
                if (pindex->nStatus & BLOCK_FAILED_MASK)
                    return "duplicate-invalid";
                return "duplicate-inconclusive";
            }

            CBlockIndex* const pindexPrev = chainActive.Tip();
            // TestBlockValidity only supports blocks built on the current Tip
            if (block.hashPrevBlock != pindexPrev->GetBlockHash())
                return "inconclusive-not-best-prevblk";
            CValidationState state;
            TestBlockValidity(state, Params(), block, pindexPrev, false, true);
            return BIP22ValidationResult(state);
        }

        const UniValue& aClientRules = find_value(oparam, "rules");
        if (aClientRules.isArray()) {
            for (unsigned int i = 0; i < aClientRules.size(); ++i) {
                const UniValue& v = aClientRules[i];
                setClientRules.insert(v.get_str());
            }
        } else {
            // NOTE: It is important that this NOT be read if versionbits is supported
            const UniValue& uvMaxVersion = find_value(oparam, "maxversion");
            if (uvMaxVersion.isNum()) {
                nMaxVersionPreVB = uvMaxVersion.get_int64();
            }
        }
    }

    if (strMode != "template")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");

    if(!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0)
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "BitcoinHD is not connected!");

    if (IsInitialBlockDownload())
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "BitcoinHD is downloading blocks...");

    static unsigned int nTransactionsUpdatedLast;

    if (!lpval.isNull())
    {
        // Wait to respond until either the best block changes, OR a minute has passed and there are more transactions
        uint256 hashWatchedChain;
        std::chrono::steady_clock::time_point checktxtime;
        unsigned int nTransactionsUpdatedLastLP;

        if (lpval.isStr())
        {
            // Format: <hashBestChain><nTransactionsUpdatedLast>
            std::string lpstr = lpval.get_str();

            hashWatchedChain.SetHex(lpstr.substr(0, 64));
            nTransactionsUpdatedLastLP = atoi64(lpstr.substr(64));
        }
        else
        {
            // NOTE: Spec does not specify behaviour for non-string longpollid, but this makes testing easier
            hashWatchedChain = chainActive.Tip()->GetBlockHash();
            nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
        }

        // Release the wallet and main lock while waiting
        LEAVE_CRITICAL_SECTION(cs_main);
        {
            checktxtime = std::chrono::steady_clock::now() + std::chrono::minutes(1);

            WaitableLock lock(csBestBlock);
            while (chainActive.Tip()->GetBlockHash() == hashWatchedChain && IsRPCRunning())
            {
                if (cvBlockChange.wait_until(lock, checktxtime) == std::cv_status::timeout)
                {
                    // Timeout: Check transactions for update
                    if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLastLP)
                        break;
                    checktxtime += std::chrono::seconds(10);
                }
            }
        }
        ENTER_CRITICAL_SECTION(cs_main);

        if (!IsRPCRunning())
            throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Shutting down");
        // TODO: Maybe recheck connections/IBD and (if something wrong) send an expires-immediately template to stop miners?
    }

    const struct VBDeploymentInfo& segwit_info = VersionBitsDeploymentInfo[Consensus::DEPLOYMENT_SEGWIT];
    // If the caller is indicating segwit support, then allow CreateNewBlock()
    // to select witness transactions, after segwit activates (otherwise
    // don't).
    bool fSupportsSegwit = setClientRules.find(segwit_info.name) != setClientRules.end();

    // Update block
    static CBlockIndex* pindexPrev;
    static int64_t nStart;
    static std::unique_ptr<CBlockTemplate> pblocktemplate;
    // Cache whether the last invocation was with segwit support, to avoid returning
    // a segwit-block to a non-segwit caller.
    static bool fLastTemplateSupportsSegwit = true;
    if (pindexPrev != chainActive.Tip() ||
        (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 5) ||
        fLastTemplateSupportsSegwit != fSupportsSegwit)
    {
        // Clear pindexPrev so future calls make a new block, despite any failures from here on
        pindexPrev = nullptr;

        // Store the pindexBest used before CreateNewBlock, to avoid races
        nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrevNew = chainActive.Tip();
        nStart = GetTime();
        fLastTemplateSupportsSegwit = fSupportsSegwit;

        // Create new block
        CScript scriptDummy = GetScriptForDestination(DecodeDestination(Params().GetConsensus().BHDFundAddress));
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(scriptDummy, fSupportsSegwit);
        if (!pblocktemplate)
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");

        // Need to update only after we know CreateNewBlock succeeded
        pindexPrev = pindexPrevNew;
    }
    CBlock* pblock = &pblocktemplate->block; // pointer for convenience
    const Consensus::Params& consensusParams = Params().GetConsensus();

    // NOTE: If at some point we support pre-segwit miners post-segwit-activation, this needs to take segwit support into consideration
    const bool fPreSegWit = (THRESHOLD_ACTIVE != VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache));

    UniValue aCaps(UniValue::VARR); aCaps.push_back("proposal");

    UniValue transactions(UniValue::VARR);
    std::map<uint256, int64_t> setTxIndex;
    int i = 0;
    for (const auto& it : pblock->vtx) {
        const CTransaction& tx = *it;
        uint256 txHash = tx.GetHash();
        setTxIndex[txHash] = i++;

        if (tx.IsCoinBase())
            continue;

        UniValue entry(UniValue::VOBJ);

        entry.push_back(Pair("data", EncodeHexTx(tx)));
        entry.push_back(Pair("txid", txHash.GetHex()));
        entry.push_back(Pair("hash", tx.GetWitnessHash().GetHex()));

        UniValue deps(UniValue::VARR);
        for (const CTxIn &in : tx.vin)
        {
            if (setTxIndex.count(in.prevout.hash))
                deps.push_back(setTxIndex[in.prevout.hash]);
        }
        entry.push_back(Pair("depends", deps));

        int index_in_template = i - 1;
        entry.push_back(Pair("fee", pblocktemplate->vTxFees[index_in_template]));
        int64_t nTxSigOps = pblocktemplate->vTxSigOpsCost[index_in_template];
        if (fPreSegWit) {
            assert(nTxSigOps % WITNESS_SCALE_FACTOR == 0);
            nTxSigOps /= WITNESS_SCALE_FACTOR;
        }
        entry.push_back(Pair("sigops", nTxSigOps));
        entry.push_back(Pair("weight", GetTransactionWeight(tx)));

        transactions.push_back(entry);
    }

    UniValue aux(UniValue::VOBJ);
    aux.push_back(Pair("flags", HexStr(COINBASE_FLAGS.begin(), COINBASE_FLAGS.end())));

    arith_uint256 hashTarget = arith_uint256().SetCompact(pblock->nBaseTarget);

    UniValue aMutable(UniValue::VARR);
    aMutable.push_back("time");
    aMutable.push_back("transactions");
    aMutable.push_back("prevblock");

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("capabilities", aCaps));

    UniValue aRules(UniValue::VARR);
    UniValue vbavailable(UniValue::VOBJ);
    for (int j = 0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
        Consensus::DeploymentPos pos = Consensus::DeploymentPos(j);
        ThresholdState state = VersionBitsState(pindexPrev, consensusParams, pos, versionbitscache);
        switch (state) {
            case THRESHOLD_DEFINED:
            case THRESHOLD_FAILED:
                // Not exposed to GBT at all
                break;
            case THRESHOLD_LOCKED_IN:
                // Ensure bit is set in block version
                pblock->nVersion |= VersionBitsMask(consensusParams, pos);
                // FALL THROUGH to get vbavailable set...
            case THRESHOLD_STARTED:
            {
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                vbavailable.push_back(Pair(gbt_vb_name(pos), consensusParams.vDeployments[pos].bit));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    if (!vbinfo.gbt_force) {
                        // If the client doesn't support this, don't indicate it in the [default] version
                        pblock->nVersion &= ~VersionBitsMask(consensusParams, pos);
                    }
                }
                break;
            }
            case THRESHOLD_ACTIVE:
            {
                // Add to rules only
                const struct VBDeploymentInfo& vbinfo = VersionBitsDeploymentInfo[pos];
                aRules.push_back(gbt_vb_name(pos));
                if (setClientRules.find(vbinfo.name) == setClientRules.end()) {
                    // Not supported by the client; make sure it's safe to proceed
                    if (!vbinfo.gbt_force) {
                        // If we do anything other than throw an exception here, be sure version/force isn't sent to old clients
                        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Support for '%s' rule requires explicit client support", vbinfo.name));
                    }
                }
                break;
            }
        }
    }
    result.push_back(Pair("version", pblock->nVersion));
    result.push_back(Pair("rules", aRules));
    result.push_back(Pair("vbavailable", vbavailable));
    result.push_back(Pair("vbrequired", int(0)));

    if (nMaxVersionPreVB >= 2) {
        // If VB is supported by the client, nMaxVersionPreVB is -1, so we won't get here
        // Because BIP 34 changed how the generation transaction is serialized, we can only use version/force back to v2 blocks
        // This is safe to do [otherwise-]unconditionally only because we are throwing an exception above if a non-force deployment gets activated
        // Note that this can probably also be removed entirely after the first BIP9 non-force deployment (ie, probably segwit) gets activated
        aMutable.push_back("version/force");
    }

    result.push_back(Pair("previousblockhash", pblock->hashPrevBlock.GetHex()));
    result.push_back(Pair("transactions", transactions));
    result.push_back(Pair("coinbaseaux", aux));
    result.push_back(Pair("coinbasevalue", (int64_t)pblock->vtx[0]->vout[0].nValue));
    result.push_back(Pair("longpollid", chainActive.Tip()->GetBlockHash().GetHex() + i64tostr(nTransactionsUpdatedLast)));
    result.push_back(Pair("target", hashTarget.GetHex()));
    result.push_back(Pair("mintime", (int64_t)pindexPrev->GetMedianTimePast()+1));
    result.push_back(Pair("mutable", aMutable));
    result.push_back(Pair("noncerange", "00000000ffffffff"));
    int64_t nSigOpLimit = (int64_t)MAX_BLOCK_SIGOPS_COST;
    int64_t nSizeLimit = (int64_t)MAX_BLOCK_WEIGHT;
    if (fPreSegWit) {
        assert(nSigOpLimit % WITNESS_SCALE_FACTOR == 0);
        nSigOpLimit /= WITNESS_SCALE_FACTOR;
        assert(nSizeLimit % WITNESS_SCALE_FACTOR == 0);
        nSizeLimit /= WITNESS_SCALE_FACTOR;
    }
    result.push_back(Pair("sigoplimit", (int64_t)MAX_BLOCK_SIGOPS_COST));
    result.push_back(Pair("sizelimit", (int64_t)MAX_BLOCK_WEIGHT));
    if (!fPreSegWit) {
        result.push_back(Pair("weightlimit", (int64_t)MAX_BLOCK_WEIGHT));
    }
    result.push_back(Pair("curtime", pblock->GetBlockTime()));
    result.push_back(Pair("baseTarget", (uint64_t)pblock->nBaseTarget));
    result.push_back(Pair("height", (int64_t)(pindexPrev->nHeight+1)));

    if (!pblocktemplate->vchCoinbaseCommitment.empty() && fSupportsSegwit) {
        result.push_back(Pair("default_witness_commitment", HexStr(pblocktemplate->vchCoinbaseCommitment.begin(), pblocktemplate->vchCoinbaseCommitment.end())));
    }

    return result;
}

class submitblock_StateCatcher : public CValidationInterface
{
public:
    uint256 hash;
    bool found;
    CValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), found(false), state() {}

protected:
    void BlockChecked(const CBlock& block, const CValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

UniValue submitblock(const JSONRPCRequest& request)
{
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "submitblock \"hexdata\"  ( \"dummy\" )\n"
            "\nAttempts to submit new block to network.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments\n"
            "1. \"hexdata\"        (string, required) the hex-encoded block data to submit\n"
            "2. \"dummy\"          (optional) dummy value, for compatibility with BIP22. This value is ignored.\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
        );
    }

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex *pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi != mapBlockIndex.end()) {
            UpdateUncommittedBlockStructures(block, mi->second, Params().GetConsensus());
        }
    }

    submitblock_StateCatcher sc(block.GetHash());
    RegisterValidationInterface(&sc);
    bool fAccepted = ProcessNewBlock(Params(), blockptr, true, nullptr);
    UnregisterValidationInterface(&sc);
    if (fBlockPresent) {
        if (fAccepted && !sc.found) {
            return "duplicate-inconclusive";
        }
        return "duplicate";
    }
    if (!sc.found) {
        return "inconclusive";
    }
    return BIP22ValidationResult(sc.state);
}

UniValue listbindplotterofaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 4)
        throw std::runtime_error(
            "listbindplotterofaddress address plotterId\n"
            "\nReturns up to binded plotter of address.\n"
            "\nArguments:\n"
            "1. address             (string, required) The BitcoinHD address\n"
            "2. plotterId           (string, optional) The filter plotter ID. If 0 or not set then output all binded plotter ID\n"
            "3. count               (numeric, optional) The result of count binded to list. If not set then output all binded plotter ID\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"address\":\"address\",               (string) The BitcoinHD address of the binded.\n"
            "    \"amount\": x.xxx,                     (numeric) The amount in " + CURRENCY_UNIT + ".\n"
            "    \"plotter_id\": plotter_id,            (string) The binded plotter ID.\n"
            "    \"txid\": \"transactionid\",           (string) The transaction id.\n"
            "    \"blockhash\": \"hashvalue\",          (string) The block hash containing the transaction.\n"
            "    \"blocktime\": xxx,                    (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"height\": xxx,                       (numeric) The block height.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList binded plotter of address\n"
            + HelpExampleCli("listbindplotterofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\" \"0\" 10")
            + HelpExampleRpc("listbindplotterofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\", \"0\" 10")
        );

    if (!request.params[0].isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CAccountID accountID = GetAccountIDByAddress(request.params[0].get_str());
    if (accountID == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address");
    uint64_t plotterId = 0;
    if (request.params.size() >= 2) {
        if (!request.params[1].isStr())
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid plotter ID");
        try {
            plotterId = static_cast<uint64_t>(std::stoull(request.params[1].get_str()));
        } catch(...) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid plotter ID");
        }
    }
    int count = std::numeric_limits<int>::max();
    if (request.params.size() >= 3)
        count = request.params[2].get_int();

    LOCK(cs_main);

    UniValue ret(UniValue::VARR);

    FlushStateToDisk();
    for (CCoinsViewCursorRef pcursor = pcoinsdbview->BindPlotterCursor(accountID, plotterId); pcursor->Valid(); pcursor->Next()) {
        if (--count < 0)
            break;

        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            assert(key.n == 0);
            assert(!coin.IsSpent());
            assert(coin.extraData && coin.extraData->type == DATACARRIER_TYPE_BINDPLOTTER);
            UniValue item(UniValue::VOBJ);
            {
                CTxDestination fromDest;
                ExtractDestination(coin.out.scriptPubKey, fromDest);
                item.push_back(Pair("address", EncodeDestination(fromDest)));
            }
            item.push_back(Pair("amount", ValueFromAmount(coin.out.nValue)));
            item.push_back(Pair("plotter_id", std::to_string(BindPlotterPayload::As(coin.extraData)->GetId())));
            item.push_back(Pair("blockhash", chainActive[(int)coin.nHeight]->GetBlockHash().GetHex()));
            item.push_back(Pair("blocktime", chainActive[(int)coin.nHeight]->GetBlockTime()));
            item.push_back(Pair("height", (int)coin.nHeight));

            ret.push_back(item);
        } else {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }
    }

    return ret;
}

UniValue GetPledge(const std::string &address, uint64_t nPlotterId, bool fVerbose)
{
    CAccountID accountID = GetAccountIDByAddress(address);
    if (accountID == 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address, must from BitcoinHD wallet (P2SH address)");
    }

    typedef struct {
        int lastForgeHeight;
        int forgeCount;
        int forgeCountAdditional;
        std::map<CAccountID, int> bindedMinerAtLastHeight; // miner => height
    } PlotterItem;
    std::map<uint64_t, PlotterItem> mapBindPlotter; // Plotter ID => PlotterItem
    int64_t nNetCapacityTB = 0;
    int nTotalForgeCount = 0;

    // Calc
    int nHeight = chainActive.Height() + 1; // For next block
    int nEndHeight = nHeight - 1;
    int nBeginHeight = std::max(nEndHeight - static_cast<int>(Params().GetConsensus().nMinerConfirmationWindow) + 1, Params().GetConsensus().BHDIP001StartMingingHeight + 1);
    if (nEndHeight >= nBeginHeight) {
        uint64_t nAvgBaseTarget = 0;
        // Current account
        for (int index = nEndHeight; index >= nBeginHeight; index--) {
            CBlockIndex *pblockIndex = chainActive[index];
            nAvgBaseTarget += pblockIndex->nBaseTarget;

            if (pblockIndex->minerAccountID == accountID) {
                nTotalForgeCount++;

                // Bind plotter to miner
                auto itPlotter = mapBindPlotter.find(pblockIndex->nPlotterId);
                if (itPlotter == mapBindPlotter.end()) {
                    mapBindPlotter.insert(std::make_pair(pblockIndex->nPlotterId, PlotterItem{index, 1, 0, {}}));
                } else {
                    itPlotter->second.forgeCount++;
                }
            } else if (pblockIndex->nPlotterId == nPlotterId) {
                nTotalForgeCount++;
            }
        }
        // Other account
        for (int index = nEndHeight; index >= nBeginHeight; index--) {
            CBlockIndex *pblockIndex = chainActive[index];
            auto itPlotter = mapBindPlotter.find(pblockIndex->nPlotterId);
            if (itPlotter == mapBindPlotter.end())
                continue;
            if (pblockIndex->minerAccountID != accountID && pblockIndex->nPlotterId == itPlotter->first)
                itPlotter->second.forgeCountAdditional++;
            if (itPlotter->second.bindedMinerAtLastHeight.find(pblockIndex->minerAccountID) == itPlotter->second.bindedMinerAtLastHeight.end()) {
                itPlotter->second.bindedMinerAtLastHeight[pblockIndex->minerAccountID] = index;
            }
        }

        nAvgBaseTarget /= (nEndHeight - nBeginHeight + 1);
        nNetCapacityTB = std::max(static_cast<int64_t>(poc::MAX_BASE_TARGET / nAvgBaseTarget), static_cast<int64_t>(1));
    }

    CAmount totalBalance = 0, bindPlotterBalance = 0, pledgeLoanBalance = 0, pledgeDebitBalance = 0;
    totalBalance = pcoinsTip->GetAccountBalance(accountID, &bindPlotterBalance, &pledgeLoanBalance, &pledgeDebitBalance);

    UniValue result(UniValue::VOBJ);
    //! This balance belong to your
    result.pushKV("balance", ValueFromAmount(totalBalance));
    //! This balance freeze in bind plotter and pledge loan
    result.pushKV("lockedBalance", ValueFromAmount(bindPlotterBalance + pledgeLoanBalance));
    //! This balance available spend
    result.pushKV("availableBalance", ValueFromAmount(totalBalance - bindPlotterBalance - pledgeLoanBalance));
    //! This balance freeze in pledge loan
    result.pushKV("pledgeLoanBalance", ValueFromAmount(pledgeLoanBalance));
    //! This balance recevied from pledge debit. YOUR CANNOT SPENT IT.
    result.pushKV("pledgeDebitBalance", ValueFromAmount(pledgeDebitBalance));
    //! This balance include pledge debit and avaliable balance. For mining pledge
    result.pushKV("availablePledgeBalance", ValueFromAmount(totalBalance - pledgeLoanBalance + pledgeDebitBalance));
    if (nHeight < Params().GetConsensus().BHDIP001NoPledgeHeight + 1) {
        result.pushKV("start", Params().GetConsensus().BHDIP001NoPledgeHeight + 1);
    }
    if (nTotalForgeCount == 0) {
        result.pushKV("pledge", ValueFromAmount(0));
        result.pushKV("maxAdditionalPledge", ValueFromAmount(0));
        result.pushKV("capacity", "0 TB");
    } else {
        assert(nEndHeight >= nBeginHeight);
        int64_t nCapacityTB;

        // Miner
        nCapacityTB = std::max((nNetCapacityTB * nTotalForgeCount) / (nEndHeight - nBeginHeight + 1), static_cast<int64_t>(1));
        result.pushKV("pledge", ValueFromAmount(Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB));
        result.pushKV("capacity", std::to_string(nCapacityTB) + " TB");

        // Bind plotter
        CAmount maxAdditionalPledge = 0;
        if (fVerbose) {
            UniValue objBindPlotters(UniValue::VOBJ);
            for (auto it = mapBindPlotter.cbegin(); it != mapBindPlotter.cend(); it++) {
                CBlockIndex *plastForgeblockIndex = chainActive[it->second.lastForgeHeight];
                nCapacityTB = std::max((nNetCapacityTB * it->second.forgeCount) / (nEndHeight - nBeginHeight + 1), static_cast<int64_t>(1));

                UniValue item(UniValue::VOBJ);
                item.pushKV("capacity", std::to_string(nCapacityTB) + " TB");
                item.pushKV("pledge", ValueFromAmount(Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB));
                {
                    UniValue lastBlock(UniValue::VOBJ);
                    lastBlock.pushKV("blockhash", plastForgeblockIndex->GetBlockHash().GetHex());
                    lastBlock.pushKV("blockheight", it->second.lastForgeHeight);
                    item.pushKV("lastBlock", lastBlock);
                }

                if (it->second.forgeCountAdditional > 0) {
                    nCapacityTB = std::max((nNetCapacityTB * it->second.forgeCountAdditional) / (nEndHeight - nBeginHeight + 1), static_cast<int64_t>(1));
                    UniValue objAdditional(UniValue::VOBJ);
                    objAdditional.pushKV("capacity", std::to_string(nCapacityTB) + " TB");
                    objAdditional.pushKV("pledge", ValueFromAmount(Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB));
                    item.pushKV("additional", objAdditional);
                    maxAdditionalPledge = std::max(maxAdditionalPledge, Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB);
                }

                // Multi mining
                if (it->second.bindedMinerAtLastHeight.size() > 1) {
                    UniValue objMultiMining(UniValue::VOBJ);
                    for (auto itBinded = it->second.bindedMinerAtLastHeight.cbegin(); itBinded != it->second.bindedMinerAtLastHeight.cend(); itBinded++) {
                        CBlockIndex *plastblockIndex = chainActive[itBinded->second];
                        // Get coinbase output address
                        std::string address;
                        CBlock block;
                        if (plastblockIndex->nTx > 0 && ReadBlockFromDisk(block, plastblockIndex, Params().GetConsensus())) {
                            CTxDestination dest;
                            if (ExtractDestination(block.vtx[0]->vout[0].scriptPubKey, dest)) {
                                address = EncodeDestination(dest);
                            }
                        }

                        UniValue item(UniValue::VOBJ);
                        {
                            int forgeCount = 0;
                            for (int index = nEndHeight; index >= nBeginHeight; index--) {
                                CBlockIndex *pblockIndex = chainActive[index];
                                if (pblockIndex->minerAccountID == plastblockIndex->minerAccountID && pblockIndex->nPlotterId == it->first)
                                    forgeCount++;
                            }
                            nCapacityTB = std::max((nNetCapacityTB * forgeCount) / (nEndHeight - nBeginHeight + 1), static_cast<int64_t>(1));
                            item.pushKV("capacity", std::to_string(nCapacityTB) + " TB");
                            item.pushKV("pledge", ValueFromAmount(Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB));
                        }
                        {
                            UniValue lastBlock(UniValue::VOBJ);
                            lastBlock.pushKV("blockhash", plastblockIndex->GetBlockHash().GetHex());
                            lastBlock.pushKV("blockheight", plastblockIndex->nHeight);
                            item.pushKV("lastBlock", lastBlock);
                        }
                        objMultiMining.pushKV(address, item);
                    }
                    item.pushKV("multiMining", objMultiMining);
                }
                objBindPlotters.pushKV(std::to_string(it->first), item);
            }
            result.pushKV("maxAdditionalPledge", ValueFromAmount(maxAdditionalPledge));
            result.pushKV("bindPlotters", objBindPlotters);
        } else {
            for (auto it = mapBindPlotter.cbegin(); it != mapBindPlotter.cend(); it++) {
                if (it->second.forgeCountAdditional > 0) {
                    nCapacityTB = std::max((nNetCapacityTB * it->second.forgeCountAdditional) / (nEndHeight - nBeginHeight + 1), static_cast<int64_t>(1));
                    maxAdditionalPledge = std::max(maxAdditionalPledge, Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB);
                }
            }
            result.pushKV("maxAdditionalPledge", ValueFromAmount(maxAdditionalPledge));
        }
    }
    result.pushKV("height", nHeight);
    result.pushKV("address", address);

    return result;
}

UniValue getpledgeofaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "getpledgeofaddress address (plotterId)\n"
            "Get mortage amount of address.\n"
            "\nArguments:\n"
            "1. address         (string, required) The BitcoinHD address.\n"
            "2. plotterId       (string, optional) Plotter ID\n"
            "3. verbose         (bool, optional, default=true) If true, return detail pledge\n"
            "\nResult:\n"
            "The mortage information of address\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getpledgeofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\" \"0\" true")
            + HelpExampleRpc("getpledgeofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\", \"0\", true")
            );

    LOCK(cs_main);

    if (!request.params[0].isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    uint64_t plotterId = 0;
    if (!request.params[1].isNull()) {
        if (!request.params[1].isStr())
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid plotter ID");
        try {
            plotterId = static_cast<uint64_t>(std::stoull(request.params[1].get_str()));
        } catch(...) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid plotter ID");
        }
    }

    bool fVerbose = true;
    if (!request.params[2].isNull()) {
        fVerbose = request.params[2].isNum() ? (request.params[2].get_int() != 0) : request.params[2].get_bool();
    }

    return GetPledge(request.params[0].get_str(), plotterId, fVerbose);
}

UniValue getplottermininginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "getplottermininginfo plotterId height\n"
            "Get mining information of plotter.\n"
            "\nArguments:\n"
            "1. plotterId       (string, required) Plotter\n"
            "2. verbose         (bool, optional, default=true) If true, return detail plotter mining information\n"
            "\nResult:\n"
            "The mining information of plotter\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getplottermininginfo", "\"1234567890\" true")
            + HelpExampleRpc("getplottermininginfo", "\"1234567890\", true")
            );

    LOCK(cs_main);

    uint64_t nPlotterId;
    if (!request.params[0].isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid plotter ID");
    try {
        nPlotterId = static_cast<uint64_t>(std::stoull(request.params[0].get_str()));
    } catch(...) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid plotter ID");
    }

    bool fVerbose = true;
    if (!request.params[1].isNull()) {
        fVerbose = request.params[1].isNum() ? (request.params[1].get_int() != 0) : request.params[1].get_bool();
    }

    typedef struct {
        int lastForgeHeight;
        int forgeCount;
    } BindInfo;
    std::map<CAccountID, BindInfo> mapBindInfo;
    int nTotalForgeCount = 0;
    int64_t nNetCapacityTB = 0, nCapacityTB = 0;

    int nHeight = chainActive.Height() + 1;
    int nEndHeight = nHeight - 1;
    int nBeginHeight = std::max(nEndHeight - static_cast<int>(Params().GetConsensus().nMinerConfirmationWindow) + 1, Params().GetConsensus().BHDIP001StartMingingHeight + 1);
    if (nEndHeight >= nBeginHeight) {
        uint64_t nAvgBaseTarget = 0;
        for (int index = nEndHeight; index >= nBeginHeight; index--) {
            CBlockIndex *pblockIndex = chainActive[index];
            nAvgBaseTarget += pblockIndex->nBaseTarget;
            if (pblockIndex->nPlotterId != nPlotterId) continue;

            nTotalForgeCount++;

            auto it = mapBindInfo.find(pblockIndex->minerAccountID);
            if (it == mapBindInfo.end()) {
                mapBindInfo.insert(std::make_pair(pblockIndex->minerAccountID, BindInfo{index, 1}));
            } else {
                it->second.forgeCount++;
            }
        }

        nAvgBaseTarget /= (nEndHeight - nBeginHeight + 1);
        nNetCapacityTB = std::max(static_cast<int64_t>(poc::MAX_BASE_TARGET / nAvgBaseTarget), static_cast<int64_t>(1));
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("plotterId", std::to_string(nPlotterId));
    if (nTotalForgeCount == 0) {
        result.pushKV("pledge", ValueFromAmount(0));
        result.pushKV("capacity", "0 TB");
    } else {
        nCapacityTB = std::max((nNetCapacityTB * nTotalForgeCount) / (nEndHeight - nBeginHeight + 1), static_cast<int64_t>(1));
        result.pushKV("pledge", ValueFromAmount(Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB));
        result.pushKV("capacity", std::to_string(nCapacityTB) + " TB");
    }

    if (fVerbose) {
        UniValue objBindAddress(UniValue::VOBJ);
        for (auto it = mapBindInfo.cbegin(); it != mapBindInfo.end(); it++) {
            CBlockIndex *plastForgeblockIndex = chainActive[it->second.lastForgeHeight];

            // Get coinbase output address
            std::string address;
            CBlock block;
            if (plastForgeblockIndex->nTx > 0 && ReadBlockFromDisk(block, plastForgeblockIndex, Params().GetConsensus())) {
                CTxDestination dest;
                if (ExtractDestination(block.vtx[0]->vout[0].scriptPubKey, dest)) {
                    address = EncodeDestination(dest);
                }
            }

            UniValue item(UniValue::VOBJ);
            nCapacityTB = std::max((nNetCapacityTB * it->second.forgeCount) / (nEndHeight - nBeginHeight + 1), static_cast<int64_t>(1));
            item.pushKV("capacity", std::to_string(nCapacityTB) + " TB");
            item.pushKV("pledge", ValueFromAmount(Params().GetConsensus().BHDIP001PledgeAmountPerTB * nCapacityTB));
            {
                UniValue lastBlock(UniValue::VOBJ);
                lastBlock.pushKV("blockhash", plastForgeblockIndex->GetBlockHash().GetHex());
                lastBlock.pushKV("blockheight", plastForgeblockIndex->nHeight);
                item.pushKV("lastBlock", lastBlock);
            }
            objBindAddress.pushKV(address, item);
        }
        result.pushKV("bindAddresses", objBindAddress);
    }

    return result;
}

static UniValue ListPledges(CCoinsViewCursorRef pcursor) {
    assert(pcursor != nullptr);
    UniValue ret(UniValue::VARR);
    for (; pcursor->Valid(); pcursor->Next()) {
        COutPoint key;
        Coin coin;
        if (pcursor->GetKey(key) && pcursor->GetValue(coin)) {
            assert(key.n == 0);
            assert(!coin.IsSpent());
            assert(coin.extraData && coin.extraData->type == DATACARRIER_TYPE_PLEDGE);
            UniValue item(UniValue::VOBJ);
            {
                CTxDestination fromDest;
                ExtractDestination(coin.out.scriptPubKey, fromDest);
                item.push_back(Pair("from", EncodeDestination(fromDest)));
            }
            {
                item.push_back(Pair("to", EncodeDestination(PledgePayload::As(coin.extraData)->scriptID)));
            }
            item.push_back(Pair("amount", ValueFromAmount(coin.out.nValue)));
            item.push_back(Pair("txid", key.hash.GetHex()));
            item.push_back(Pair("blockhash", chainActive[(int)coin.nHeight]->GetBlockHash().GetHex()));
            item.push_back(Pair("blocktime", chainActive[(int)coin.nHeight]->GetBlockTime()));
            item.push_back(Pair("height", (int)coin.nHeight));

            ret.push_back(item);
        } else {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read UTXO set");
        }
    }

    return ret;
}

UniValue listpledgeloanofaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listpledgeloanofaddress address\n"
            "\nReturns up to pledge loan coins.\n"
            "\nArguments:\n"
            "1. address             (string, required) The BitcoinHD address\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"from\":\"address\",                  (string) The BitcoinHD address of the pledge source.\n"
            "    \"to\":\"address\",                    (string) The BitcoinHD address of the pledge destination\n"
            "    \"amount\": x.xxx,                     (numeric) The amount in " + CURRENCY_UNIT + ".\n"
            "    \"txid\": \"transactionid\",           (string) The transaction id.\n"
            "    \"blockhash\": \"hashvalue\",          (string) The block hash containing the transaction.\n"
            "    \"blocktime\": xxx,                    (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"height\": xxx,                       (numeric) The block height.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the pledge loan coins from UTXOs\n"
            + HelpExampleCli("listpledgeloanofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\"")
            + HelpExampleRpc("listpledgeloanofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\"")
        );

    if (!request.params[0].isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CAccountID accountID = GetAccountIDByAddress(request.params[0].get_str());
    if (accountID == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address");

    LOCK(cs_main);

    FlushStateToDisk();
    return ListPledges(pcoinsdbview->PledgeCreditCursor(accountID));
}

UniValue listpledgedebitofaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "listpledgedebitofaddress address\n"
            "\nReturns up to pledge debit coins.\n"
            "\nArguments:\n"
            "1. address             (string, required) The BitcoinHD address\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"from\":\"address\",                  (string) The BitcoinHD address of the pledge source.\n"
            "    \"to\":\"address\",                    (string) The BitcoinHD address of the pledge destination\n"
            "    \"amount\": x.xxx,                     (numeric) The amount in " + CURRENCY_UNIT + ".\n"
            "    \"txid\": \"transactionid\",           (string) The transaction id.\n"
            "    \"blockhash\": \"hashvalue\",          (string) The block hash containing the transaction.\n"
            "    \"blocktime\": xxx,                    (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"height\": xxx,                       (numeric) The block height.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the pledge debit coins from UTXOs\n"
            + HelpExampleCli("listpledgedebitofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\"")
            + HelpExampleRpc("listpledgedebitofaddress", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\"")
        );

    if (!request.params[0].isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    CAccountID accountID = GetAccountIDByAddress(request.params[0].get_str());
    if (accountID == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address");

    LOCK(cs_main);

    FlushStateToDisk();
    return ListPledges(pcoinsdbview->PledgeDebitCursor(accountID));
}

UniValue estimatefee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "estimatefee nblocks\n"
            "\nDEPRECATED. Please use estimatesmartfee for more intelligent estimates."
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks. Uses virtual transaction size of transaction\n"
            "as defined in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. nblocks     (numeric, required)\n"
            "\nResult:\n"
            "n              (numeric) estimated fee-per-kilobyte\n"
            "\n"
            "A negative value is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate.\n"
            "-1 is always returned for nblocks == 1 as it is impossible to calculate\n"
            "a fee that is high enough to get reliably included in the next block.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatefee", "6")
            );

    if (!IsDeprecatedRPCEnabled("estimatefee")) {
        throw JSONRPCError(RPC_METHOD_DEPRECATED, "estimatefee is deprecated and will be fully removed in v0.17. "
            "To use estimatefee in v0.16, restart bitcoind with -deprecatedrpc=estimatefee.\n"
            "Projects should transition to using estimatesmartfee before upgrading to v0.17");
    }

    RPCTypeCheck(request.params, {UniValue::VNUM});

    int nBlocks = request.params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

    CFeeRate feeRate = ::feeEstimator.estimateFee(nBlocks);
    if (feeRate == CFeeRate(0))
        return -1.0;

    return ValueFromAmount(feeRate.GetFeePerK());
}

UniValue estimatesmartfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "estimatesmartfee conf_target (\"estimate_mode\")\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within conf_target blocks if possible and return the number of blocks\n"
            "for which the estimate is valid. Uses virtual transaction size as defined\n"
            "in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. conf_target     (numeric) Confirmation target in blocks (1 - 1008)\n"
            "2. \"estimate_mode\" (string, optional, default=CONSERVATIVE) The fee estimate mode.\n"
            "                   Whether to return a more conservative estimate which also satisfies\n"
            "                   a longer history. A conservative estimate potentially returns a\n"
            "                   higher feerate and is more likely to be sufficient for the desired\n"
            "                   target, but is not as responsive to short term drops in the\n"
            "                   prevailing fee market.  Must be one of:\n"
            "       \"UNSET\" (defaults to CONSERVATIVE)\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\"\n"
            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric, optional) estimate fee rate in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": [ str... ] (json array of strings, optional) Errors encountered during processing\n"
            "  \"blocks\" : n         (numeric) block number where estimate was found\n"
            "}\n"
            "\n"
            "The request target will be clamped between 2 and the highest target\n"
            "fee estimation is able to return based on how long it has been running.\n"
            "An error is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "\nExample:\n"
            + HelpExampleCli("estimatesmartfee", "6")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VSTR});
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int conf_target = ParseConfirmTarget(request.params[0]);
    bool conservative = true;
    if (!request.params[1].isNull()) {
        FeeEstimateMode fee_mode;
        if (!FeeModeFromString(request.params[1].get_str(), fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
        if (fee_mode == FeeEstimateMode::ECONOMICAL) conservative = false;
    }

    UniValue result(UniValue::VOBJ);
    UniValue errors(UniValue::VARR);
    FeeCalculation feeCalc;
    CFeeRate feeRate = ::feeEstimator.estimateSmartFee(conf_target, &feeCalc, conservative);
    if (feeRate != CFeeRate(0)) {
        result.push_back(Pair("feerate", ValueFromAmount(feeRate.GetFeePerK())));
    } else {
        errors.push_back("Insufficient data or no feerate found");
        result.push_back(Pair("errors", errors));
    }
    result.push_back(Pair("blocks", feeCalc.returnedTarget));
    return result;
}

UniValue estimaterawfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "estimaterawfee conf_target (threshold)\n"
            "\nWARNING: This interface is unstable and may disappear or change!\n"
            "\nWARNING: This is an advanced API call that is tightly coupled to the specific\n"
            "         implementation of fee estimation. The parameters it can be called with\n"
            "         and the results it returns will change if the internal implementation changes.\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within conf_target blocks if possible. Uses virtual transaction size as\n"
            "defined in BIP 141 (witness data is discounted).\n"
            "\nArguments:\n"
            "1. conf_target (numeric) Confirmation target in blocks (1 - 1008)\n"
            "2. threshold   (numeric, optional) The proportion of transactions in a given feerate range that must have been\n"
            "               confirmed within conf_target in order to consider those feerates as high enough and proceed to check\n"
            "               lower buckets.  Default: 0.95\n"
            "\nResult:\n"
            "{\n"
            "  \"short\" : {            (json object, optional) estimate for short time horizon\n"
            "      \"feerate\" : x.x,        (numeric, optional) estimate fee rate in " + CURRENCY_UNIT + "/kB\n"
            "      \"decay\" : x.x,          (numeric) exponential decay (per block) for historical moving average of confirmation data\n"
            "      \"scale\" : x,            (numeric) The resolution of confirmation targets at this time horizon\n"
            "      \"pass\" : {              (json object, optional) information about the lowest range of feerates to succeed in meeting the threshold\n"
            "          \"startrange\" : x.x,     (numeric) start of feerate range\n"
            "          \"endrange\" : x.x,       (numeric) end of feerate range\n"
            "          \"withintarget\" : x.x,   (numeric) number of txs over history horizon in the feerate range that were confirmed within target\n"
            "          \"totalconfirmed\" : x.x, (numeric) number of txs over history horizon in the feerate range that were confirmed at any point\n"
            "          \"inmempool\" : x.x,      (numeric) current number of txs in mempool in the feerate range unconfirmed for at least target blocks\n"
            "          \"leftmempool\" : x.x,    (numeric) number of txs over history horizon in the feerate range that left mempool unconfirmed after target\n"
            "      },\n"
            "      \"fail\" : { ... },       (json object, optional) information about the highest range of feerates to fail to meet the threshold\n"
            "      \"errors\":  [ str... ]   (json array of strings, optional) Errors encountered during processing\n"
            "  },\n"
            "  \"medium\" : { ... },    (json object, optional) estimate for medium time horizon\n"
            "  \"long\" : { ... }       (json object) estimate for long time horizon\n"
            "}\n"
            "\n"
            "Results are returned for any horizon which tracks blocks up to the confirmation target.\n"
            "\nExample:\n"
            + HelpExampleCli("estimaterawfee", "6 0.9")
            );

    RPCTypeCheck(request.params, {UniValue::VNUM, UniValue::VNUM}, true);
    RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
    unsigned int conf_target = ParseConfirmTarget(request.params[0]);
    double threshold = 0.95;
    if (!request.params[1].isNull()) {
        threshold = request.params[1].get_real();
    }
    if (threshold < 0 || threshold > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold");
    }

    UniValue result(UniValue::VOBJ);

    for (FeeEstimateHorizon horizon : {FeeEstimateHorizon::SHORT_HALFLIFE, FeeEstimateHorizon::MED_HALFLIFE, FeeEstimateHorizon::LONG_HALFLIFE}) {
        CFeeRate feeRate;
        EstimationResult buckets;

        // Only output results for horizons which track the target
        if (conf_target > ::feeEstimator.HighestTargetTracked(horizon)) continue;

        feeRate = ::feeEstimator.estimateRawFee(conf_target, threshold, horizon, &buckets);
        UniValue horizon_result(UniValue::VOBJ);
        UniValue errors(UniValue::VARR);
        UniValue passbucket(UniValue::VOBJ);
        passbucket.push_back(Pair("startrange", round(buckets.pass.start)));
        passbucket.push_back(Pair("endrange", round(buckets.pass.end)));
        passbucket.push_back(Pair("withintarget", round(buckets.pass.withinTarget * 100.0) / 100.0));
        passbucket.push_back(Pair("totalconfirmed", round(buckets.pass.totalConfirmed * 100.0) / 100.0));
        passbucket.push_back(Pair("inmempool", round(buckets.pass.inMempool * 100.0) / 100.0));
        passbucket.push_back(Pair("leftmempool", round(buckets.pass.leftMempool * 100.0) / 100.0));
        UniValue failbucket(UniValue::VOBJ);
        failbucket.push_back(Pair("startrange", round(buckets.fail.start)));
        failbucket.push_back(Pair("endrange", round(buckets.fail.end)));
        failbucket.push_back(Pair("withintarget", round(buckets.fail.withinTarget * 100.0) / 100.0));
        failbucket.push_back(Pair("totalconfirmed", round(buckets.fail.totalConfirmed * 100.0) / 100.0));
        failbucket.push_back(Pair("inmempool", round(buckets.fail.inMempool * 100.0) / 100.0));
        failbucket.push_back(Pair("leftmempool", round(buckets.fail.leftMempool * 100.0) / 100.0));

        // CFeeRate(0) is used to indicate error as a return value from estimateRawFee
        if (feeRate != CFeeRate(0)) {
            horizon_result.push_back(Pair("feerate", ValueFromAmount(feeRate.GetFeePerK())));
            horizon_result.push_back(Pair("decay", buckets.decay));
            horizon_result.push_back(Pair("scale", (int)buckets.scale));
            horizon_result.push_back(Pair("pass", passbucket));
            // buckets.fail.start == -1 indicates that all buckets passed, there is no fail bucket to output
            if (buckets.fail.start != -1) horizon_result.push_back(Pair("fail", failbucket));
        } else {
            // Output only information that is still meaningful in the event of error
            horizon_result.push_back(Pair("decay", buckets.decay));
            horizon_result.push_back(Pair("scale", (int)buckets.scale));
            horizon_result.push_back(Pair("fail", failbucket));
            errors.push_back("Insufficient data or no feerate found which meets threshold");
            horizon_result.push_back(Pair("errors",errors));
        }
        result.push_back(Pair(StringForFeeEstimateHorizon(horizon), horizon_result));
    }
    return result;
}

UniValue getbalanceofheight(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "DEPRECATED.getbalanceofheight \"address\" (\"height\")\n"
            "\nArguments:\n"
            "1. address           (string,optional) The BitcoinHD address\n"
            "2. height            (numeric,optional) DEPRECATED.The height of blockchain\n"
            "\nResult:\n"
            "Balance\n"
            "\n"
            "\nExample:\n"
            + HelpExampleCli("getbalanceofheight", Params().GetConsensus().BHDFundAddress + " 9000")
            + HelpExampleRpc("getbalanceofheight", std::string("\"") + Params().GetConsensus().BHDFundAddress + "\", 9000")
            );

    LOCK(cs_main);

    if (!request.params[0].isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CAccountID accountID = GetAccountIDByAddress(request.params[0].get_str());
    if (accountID == 0) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address, BitcoinHD address of P2SH");
    }

    return ValueFromAmount(pcoinsTip->GetAccountBalance(accountID));
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "mining",             "getmininginfo",                &getmininginfo,             {} },
    { "mining",             "prioritisetransaction",        &prioritisetransaction,     {"txid","dummy","fee_delta"} },
    { "mining",             "getblocktemplate",             &getblocktemplate,          {"template_request"} },
    { "mining",             "submitblock",                  &submitblock,               {"hexdata","dummy"} },
    { "mining",             "listbindplotterofaddress",     &listbindplotterofaddress,  {"address", "plotterId", "count"} },
    { "mining",             "getpledgeofaddress",           &getpledgeofaddress,        {"address", "plotterId", "verbose"} },
    { "mining",             "getplottermininginfo",         &getplottermininginfo,      {"plotterId", "verbose"} },
    { "mining",             "listpledgeloanofaddress",      &listpledgeloanofaddress,   {"address"} },
    { "mining",             "listpledgedebitofaddress",     &listpledgedebitofaddress,  {"address"} },

    { "generating",         "generatetoaddress",            &generatetoaddress,         {"nblocks","address","maxtries"} },

    { "util",               "estimatefee",                  &estimatefee,               {"nblocks"} },
    { "util",               "estimatesmartfee",             &estimatesmartfee,          {"conf_target", "estimate_mode"} },
    { "util",               "getbalanceofheight",           &getbalanceofheight,        {"address", "height"} },

    { "hidden",             "estimaterawfee",               &estimaterawfee,            {"conf_target", "threshold"} },
};

void RegisterMiningRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
