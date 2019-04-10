// Copyright (c) 2017-2018 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poc/poc.h>
#include <base58.h>
#include <chainparams.h>
#include <compat/endian.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/shabal256.h>
#include <miner.h>
#include <rpc/protocol.h>
#include <ui_interface.h>
#include <util.h>
#include <utiltime.h>
#include <validation.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif
#include <timedata.h>
#include <threadinterrupt.h>

#include <cinttypes>
#include <exception>
#include <limits>
#include <string>
#include <tuple>
#include <unordered_map>

#include <event2/thread.h>

namespace {

// Generator
struct GeneratorState {
    uint64_t nonce;
    uint64_t plotterId;
    uint64_t deadline;
    int height;

    CTxDestination dest;
    std::shared_ptr<CKey> privKey;

    GeneratorState() : deadline(poc::INVALID_DEADLINE) { }
};
typedef std::unordered_map<uint64_t, GeneratorState> Generators; // blockHash low 64bits -> GeneratorState
Generators mapGenerators;

std::shared_ptr<CBlock> CreateBlock(const GeneratorState &generateState)
{
    AssertLockHeld(cs_main);

    std::unique_ptr<CBlockTemplate> pblocktemplate;
    try {
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(GetScriptForDestination(generateState.dest), true,
            generateState.nonce, generateState.plotterId, generateState.deadline, generateState.privKey);
    } catch (std::exception &e) {
        const char *what = e.what();
        LogPrintf("CreateBlock() fail: %s\n", what ? what : "Catch unknown exception");
    }
    if (!pblocktemplate.get()) 
        return nullptr;

    CBlock *pblock = &pblocktemplate->block;
    return std::make_shared<CBlock>(*pblock);
}

// Mining loop
CThreadInterrupt interruptCheckDeadline;
std::thread threadCheckDeadline;
void CheckDeadlineThread()
{
    RenameThread("bitcoin-checkdeadline");
    while (!interruptCheckDeadline) {
        if (!interruptCheckDeadline.sleep_for(std::chrono::milliseconds(500)))
            break;
        
        std::shared_ptr<CBlock> pblock;
        bool fReActivateBestChain = false;
        {
            LOCK(cs_main);
            if (!mapGenerators.empty()) {
                if (GetTimeOffset() > MAX_FUTURE_BLOCK_TIME) {
                    LogPrintf("Your computer time maybe abnormal (offset %" PRId64 "). " \
                        "Check your computer time or add -maxtimeadjustment=0 \n", GetTimeOffset());
                }
                CBlockIndex *pindexTip = chainActive.Tip();
                int64_t nAdjustedTime = GetAdjustedTime();
                auto it = mapGenerators.begin();
                while (it != mapGenerators.end() && !pblock) {
                    if (pindexTip->GetBlockHash().GetUint64(0) == it->first) {
                        // Current round
                        if (nAdjustedTime + 1 >= (int64_t)pindexTip->nTime + (int64_t)it->second.deadline) {
                            // Forge
                            LogPrint(BCLog::POC, "Generate block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                it->second.height, it->second.nonce, it->second.plotterId, it->second.deadline);
                            pblock = CreateBlock(it->second);
                            if (!pblock) {
                                LogPrintf("Generate block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                    it->second.height, it->second.nonce, it->second.plotterId, it->second.deadline);
                            } else {
                                LogPrint(BCLog::POC, "Created block: %s/%d\n", pblock->GetHash().ToString(), pblock->nTime);
                            }
                        } else {
                            // Continue wait forge time
                            ++it;
                            continue;
                        }
                    } else if (pindexTip->pprev && pindexTip->pprev->GetBlockHash().GetUint64(0) == it->first) {
                        // Previous round
                        // Process future post block (MAX_FUTURE_BLOCK_TIME). My deadline is best(highest chainwork).
                        uint64_t myForgeTime = (uint64_t) pindexTip->pprev->GetBlockTime() + it->second.deadline + 1;
                        uint64_t currentForgeTime = (uint64_t) pindexTip->GetBlockTime();
                        if (myForgeTime <= currentForgeTime) {
                            // My deadline maybe best. Forge new block
                            // Try snatch block and post block not wait
                            LogPrint(BCLog::POC, "Begin snatch block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "(%" PRIu64 " <= %" PRIu64 ")\n",
                                it->second.height, it->second.nonce, it->second.plotterId, it->second.deadline, myForgeTime, currentForgeTime);
                            // Invalidate tip block
                            CValidationState state;
                            if (!InvalidateBlock(state, Params(), pindexTip)) {
                                LogPrint(BCLog::POC, "Snatch block: invalidate current tip block error, %s\n", state.GetRejectReason());
                                LogPrint(BCLog::POC, "Snatch block: current tip, %s\n", pindexTip->ToString());
                                LogPrint(BCLog::POC, "End snatch block\n");
                            } else {
                                fReActivateBestChain = true;
                                pblock = CreateBlock(it->second);
                                if (!pblock) {
                                    LogPrintf("Snatch block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                        it->second.height, it->second.nonce, it->second.plotterId, it->second.deadline);
                                } else if (mapBlockIndex.count(pblock->GetHash())) {
                                    // Exist block
                                    LogPrintf("Snatch block give up: Exist block %s\n", pblock->GetHash().ToString());
                                } else {
                                    arith_uint256 mineBlockWork = GetBlockProof(*pblock, Params().GetConsensus());
                                    arith_uint256 tipBlockWork = GetBlockProof(*pindexTip, Params().GetConsensus());
                                    if (mineBlockWork < tipBlockWork || pblock->nTime > pindexTip->nTime) {
                                        // Low chainwork
                                        LogPrintf("Snatch block give up: Low chainwork, mine/%s/%d < tip/%s/%d\n",
                                            mineBlockWork.ToString(), pblock->nTime, tipBlockWork.ToString(), pindexTip->nTime);
                                    } else {
                                        // Snatch block
                                        LogPrint(BCLog::POC, "Snatch block: mine/%s/%d <-> tip/%s/%d %d\n",
                                            pblock->GetHash().ToString(), pblock->nTime,
                                            pindexTip->phashBlock->ToString(), pindexTip->nTime, pindexTip->nHeight);

                                        // Set best block chainwork small then mine.
                                        if (mineBlockWork == tipBlockWork && pblock->nTime == pindexTip->nTime) {
                                            pindexTip->nChainWork = pindexTip->pprev->nChainWork + tipBlockWork - 1;
                                        }
                                    }
                                }

                                ResetBlockFailureFlags(pindexTip);
                            }
                        } else {
                            // Not better tip, give up!
                            LogPrint(BCLog::POC, "Snatch block give up: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "(%" PRIu64 " > %" PRIu64 ")\n",
                                it->second.height, it->second.nonce, it->second.plotterId, it->second.deadline, myForgeTime, currentForgeTime);
                        }
                    }

                    it = mapGenerators.erase(it);
                }
            }
        }

        // Update best. Not hold cs_main
        if (fReActivateBestChain) {
            CValidationState state;
            ActivateBestChain(state, Params());
            assert (state.IsValid());
            LogPrint(BCLog::POC, "End snatch block\n");
        }

        // Broadcast. Not hold cs_main
        if (pblock && !ProcessNewBlock(Params(), pblock, true, nullptr)) {
            LogPrintf("Process new block fail %s\n", pblock->ToString());
        }
    }

    LogPrintf("Exit PoC forge thread\n");
}

// Save block signature require private key
typedef std::unordered_map< uint64_t, std::shared_ptr<CKey> > CPrivKeyMap;
CPrivKeyMap mapSignaturePrivKeys;

}

namespace poc {

static constexpr int HASH_SIZE = 32;
static constexpr int HASHES_PER_SCOOP = 2;
static constexpr int SCOOP_SIZE = HASHES_PER_SCOOP * HASH_SIZE; // 2 hashes per scoop
static constexpr int SCOOPS_PER_PLOT = 4096;
static constexpr int PLOT_SIZE = SCOOPS_PER_PLOT * SCOOP_SIZE; // 256KB
static std::unique_ptr<unsigned char> calcDLDataCache(new unsigned char[PLOT_SIZE + 16]); // Global calc cache

//! Thread unsafe
static uint64_t CalcDL(const CBlockIndex &prev, const CBlockHeader &block, const Consensus::Params &params) {
    CShabal256 shabal256;
    uint256 temp;

    const uint256 &generationSignature = prev.GetNextGenerationSignature();

    // Scoop
    const uint64_t flipHeight = htobe64(static_cast<uint64_t>(prev.nHeight + 1));
    shabal256
        .Write(generationSignature.begin(), generationSignature.size())
        .Write((const unsigned char*)&flipHeight, sizeof(flipHeight))
        .Finalize((unsigned char*)temp.begin());
    const uint32_t scoop = (uint32_t) (temp.begin()[31] + 256 * temp.begin()[30]) % 4096;

    // Row data
    const uint64_t addr = htobe64(block.nPlotterId);
    const uint64_t nonce = htobe64(block.nNonce);
    unsigned char *const data = calcDLDataCache.get();
    memcpy(data + PLOT_SIZE, (const unsigned char*)&addr, 8);
    memcpy(data + PLOT_SIZE + 8, (const unsigned char*)&nonce, 8);
    for (int i = PLOT_SIZE; i > 0; i -= HASH_SIZE) {
        int len = PLOT_SIZE + 16 - i;
        if (len > SCOOPS_PER_PLOT) {
            len = SCOOPS_PER_PLOT;
        }

        shabal256
            .Write(data + i, len)
            .Finalize(data + i - HASH_SIZE);
    }
    shabal256
        .Write(data, PLOT_SIZE + 16)
        .Finalize(temp.begin());
    for (int i = 0; i < PLOT_SIZE; i++) {
        data[i] = (unsigned char) (data[i] ^ (temp.begin()[i % HASH_SIZE]));
    }

    // PoC2 Rearrangement. Swap high hash
    //
    // [0] [1] [2] [3] ... [N-1]
    // [1] <-> [N-1]
    // [2] <-> [N-2]
    // [3] <-> [N-3]
    //
    // Only care hash data of scoop index
    memcpy(data + scoop * SCOOP_SIZE + HASH_SIZE, data + (SCOOPS_PER_PLOT - scoop) * SCOOP_SIZE - HASH_SIZE, HASH_SIZE);

    // Result
    shabal256
        .Write(generationSignature.begin(), generationSignature.size())
        .Write(data + scoop * SCOOP_SIZE, SCOOP_SIZE)
        .Finalize(temp.begin());
    return temp.GetUint64(0) / prev.nBaseTarget;
}

// Require hold cs_main
uint64_t CalculateDeadline(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params, bool fEnableCache)
{
    // Fund
    if (prevBlockIndex.nHeight + 1 <= params.BHDIP001StartMingingHeight)
        return 0;

    // BHDIP006 disallow plotter 0
    if (block.nPlotterId == 0 && prevBlockIndex.nHeight + 1 >= params.BHDIP006Height)
        return poc::INVALID_DEADLINE;

    // Regtest
    if (params.fPocAllowMinDifficultyBlocks)
        return block.nNonce;

    if (fEnableCache) {
        // From cache
        const uint256 hash = block.GetHash();
        BlockDeadlineCacheMap::iterator itCache;
        bool inserted;
        std::tie(itCache, inserted) = mapBlockDeadlineCache.emplace(hash, poc::INVALID_DEADLINE);
        if (inserted) {
            itCache->second = CalcDL(prevBlockIndex, block, params);
            
            // Prune deadline cache
            if (mapBlockDeadlineCache.size() > chainActive.Height() + params.nMinerConfirmationWindow) {
                LogPrint(BCLog::POC, "%s: Pruning deadline cache (size %u)\n", __func__, mapBlockDeadlineCache.size());

                uint64_t deadline = itCache->second;
                for (auto it = mapBlockDeadlineCache.begin(); it != mapBlockDeadlineCache.end();) {
                    if (it->first != hash) {
                        auto mi = mapBlockIndex.find(it->first);
                        if (mi == mapBlockIndex.end() || chainActive[mi->second->nHeight] != mi->second) {
                            it = mapBlockDeadlineCache.erase(it);
                            continue;
                        }
                    }

                    ++it;
                }

                return deadline;
            }
        } else {
            LogPrint(BCLog::POC, "%s: Hit %d(%s) from deadline cache\n", __func__, prevBlockIndex.nHeight + 1, block.GetHash().GetHex());
        }
        return itCache->second;
    } else {
        return CalcDL(prevBlockIndex, block, params);
    }
}

uint64_t CalculateBaseTarget(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params)
{
    int nHeight = prevBlockIndex.nHeight + 1;
    if (nHeight <= params.BHDIP001StartMingingHeight) {
        // genesis block & pre-mining block
        return INITIAL_BASE_TARGET;
    } else if (nHeight < params.BHDIP001StartMingingHeight + 4) {
        return INITIAL_BASE_TARGET;
    } else if (nHeight < params.BHDIP001StartMingingHeight + 2700) {
        // [N-1,N-2,N-3,N-4]
        uint64_t avgBaseTarget = prevBlockIndex.nBaseTarget;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        for (int i = nHeight - 2; i >= nHeight - 4; i--) {
            pLastindex = pLastindex->pprev;
            avgBaseTarget += pLastindex->nBaseTarget;
        }
        avgBaseTarget /= 4;

        uint64_t curBaseTarget = avgBaseTarget;
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        uint64_t newBaseTarget = (curBaseTarget * diffTime) / (params.nPowTargetSpacing * 4); // 5m * 4blocks
        if (newBaseTarget > MAX_BASE_TARGET) {
            newBaseTarget = MAX_BASE_TARGET;
        }
        if (newBaseTarget < (curBaseTarget * 9 / 10)) {
            newBaseTarget = curBaseTarget * 9 / 10;
        }
        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }
        if (newBaseTarget > (curBaseTarget * 11 / 10)) {
            newBaseTarget = curBaseTarget * 11 / 10;
        }

        return newBaseTarget;
    } else {
        // Algorithm:
        //   B(0) = prevBlock, B(1) = B(0).prev, ..., B(n) = B(n-1).prev
        //   Y(0) = B(0).nBaseTarget
        //   Y(n) = (Y(n-1) * (n-1) + B(n).nBaseTarget) / (n + 1); n > 0
        const int N = nHeight < params.BHDIP006Height ? 25 : (24 * 3600 / params.nPowTargetSpacing);
        const CBlockIndex *pLastindex = &prevBlockIndex;
        uint64_t avgBaseTarget = prevBlockIndex.nBaseTarget;
        for (int n = 1; n < N; n++) {
            pLastindex = pLastindex->pprev;
            avgBaseTarget = (avgBaseTarget * n + pLastindex->nBaseTarget) / (n + 1);
        }
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        int64_t targetTimespan = params.nPowTargetSpacing * (N - 1); // 5m * (N-1)blocks. Because "time1 = time0 + deadline + 1" about 288s, so we -1
        if (diffTime < targetTimespan / 2) {
            diffTime = targetTimespan / 2;
        }
        if (diffTime > targetTimespan * 2) {
            diffTime = targetTimespan * 2;
        }
        uint64_t curBaseTarget = prevBlockIndex.nBaseTarget;
        uint64_t newBaseTarget = avgBaseTarget * diffTime / targetTimespan;
        if (newBaseTarget > MAX_BASE_TARGET) {
            newBaseTarget = MAX_BASE_TARGET;
        }
        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }
        if (newBaseTarget < curBaseTarget * 8 / 10) {
            newBaseTarget = curBaseTarget * 8 / 10;
        }
        if (newBaseTarget > curBaseTarget * 12 / 10) {
            newBaseTarget = curBaseTarget * 12 / 10;
        }

        return newBaseTarget;
    }
}

uint64_t AddNonce(uint64_t &bestDeadline, const CBlockIndex &prevBlockIndex, const uint64_t &nNonce, const uint64_t &nPlotterId,
    const std::string &generateTo, bool fCheckBind, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);

    if (interruptCheckDeadline)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Not run in mining mode, restart by -server");

    CBlockHeader block;
    block.nVersion   = ComputeBlockVersion(&prevBlockIndex, params);
    block.nNonce     = nNonce;
    block.nPlotterId = nPlotterId;
    uint64_t calcDeadline = CalculateDeadline(prevBlockIndex, block, params, false);
    if (calcDeadline == INVALID_DEADLINE)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid deadline");

    LogPrint(BCLog::POC, "Add nonce: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
        prevBlockIndex.nHeight + 1, nNonce, nPlotterId, calcDeadline);

    uint64_t blockId = prevBlockIndex.GetBlockHash().GetUint64(0);
    bool fBest = false;
    if (mapGenerators.count(blockId)) {
        GeneratorState &generatorState = mapGenerators[blockId];
        if (generatorState.deadline > calcDeadline) {
            fBest = true;
            bestDeadline = calcDeadline;
        } else {
            bestDeadline = generatorState.deadline;
        }
    } else {
        fBest = true;
        bestDeadline = calcDeadline;
    }

    if (fBest) {
        CTxDestination dest;
        std::shared_ptr<CKey> privKey;
        if (generateTo.empty()) {
            // Update generate address from wallet
        #ifdef ENABLE_WALLET
            CWalletRef pwallet = vpwallets.empty() ? nullptr : vpwallets[0];
            if (!pwallet)
                throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Require wallet");
            dest = pwallet->GetPrimaryDestination();
            if (!boost::get<CScriptID>(&dest))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid primary address");
        #else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Require wallet");
        #endif
        } else {
            dest = DecodeDestination(generateTo);
            if (!boost::get<CScriptID>(&dest)) {
                // Maybe privkey
                CBitcoinSecret vchSecret;
                if (!vchSecret.SetString(generateTo))
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address or private key");
                CKey key = vchSecret.GetKey();
                if (!key.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address or private key");
                } else {
                    privKey = std::make_shared<CKey>(key);
                    // P2SH-Segwit
                    CKeyID keyid = privKey->GetPubKey().GetID();
                    CTxDestination segwit = WitnessV0KeyHash(keyid);
                    dest = CScriptID(GetScriptForDestination(segwit));
                }
            }
        }
        if (!boost::get<CScriptID>(&dest))
            throw JSONRPCError(RPC_METHOD_NOT_FOUND, "Invalid BitcoinHD address");

        // Check bind
        if (prevBlockIndex.nHeight + 1 >= params.BHDIP006Height) {
            CAccountID accountID = GetAccountIDByTxDestination(dest);
            if (accountID == 0)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BitcoinHD address");
            if (!pcoinsTip->HaveActiveBindPlotter(accountID, nPlotterId))
                throw JSONRPCError(RPC_INVALID_REQUEST, "Not bind to address");
        }

        // Update private key for signature
        if (prevBlockIndex.nHeight + 1 >= params.BHDIP007Height) {
            uint64_t destId = boost::get<CScriptID>(&dest)->GetUint64(0);

            if (!privKey) {
                // From cache
                if (mapSignaturePrivKeys.count(destId)) {
                    privKey = mapSignaturePrivKeys[destId];
                }

            #ifdef ENABLE_WALLET
                // From wallets
                if (!privKey) {
                    for (CWalletRef pwallet : vpwallets) {
                        CKeyID keyid = GetKeyForDestination(*pwallet, dest);
                        if (!keyid.IsNull()) {
                            privKey = std::make_shared<CKey>();
                            if (!pwallet->GetKey(keyid, *privKey)) {
                                privKey.reset();
                            } else {
                                mapSignaturePrivKeys[destId] = privKey;
                                break;
                            }
                        }
                    }
                }
            #endif
            } else if (!mapSignaturePrivKeys.count(destId)) {
                mapSignaturePrivKeys[destId] = privKey;
            }

            if (!privKey)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not found private key for signature");
        }

        GeneratorState &generatorState = mapGenerators[blockId];
        generatorState.nonce     = nNonce;
        generatorState.plotterId = nPlotterId;
        generatorState.deadline  = calcDeadline;
        generatorState.height    = prevBlockIndex.nHeight + 1;
        generatorState.dest      = dest;
        generatorState.privKey   = privKey;

        LogPrint(BCLog::POC, "New best deadline %" PRIu64 ".\n", calcDeadline);

        uiInterface.NotifyBestDeadlineChanged(generatorState.height, generatorState.nonce, generatorState.plotterId, calcDeadline);
    }

    return calcDeadline;
}

CAmount GetMinerForgePledge(const CAccountID &minerAccountID, const uint64_t &plotterId, int nMiningHeight, const CCoinsViewCache &view,
    const Consensus::Params &consensusParams, CAmount *pMinerPledgeOldConsensus)
{
    AssertLockHeld(cs_main);
    assert(nMiningHeight > 0);
    assert(nMiningHeight <= chainActive.Height() + 1);
    assert(GetSpendHeight(view) == nMiningHeight);
    if (pMinerPledgeOldConsensus != nullptr)
        *pMinerPledgeOldConsensus = 0;

    // Calc range
    int nBeginHeight = std::max(nMiningHeight - static_cast<int>(consensusParams.nMinerConfirmationWindow), consensusParams.BHDIP001StartMingingHeight + 1);
    if (nMiningHeight <= nBeginHeight)
        return 0;

    uint64_t nAvgBaseTarget = 0; // Average BaseTarget
    int nTotalForgeCount = 0, nTotalForgeCountOldConsensus = 0;
    if (nMiningHeight < consensusParams.BHDIP006BindPlotterActiveHeight) {
        // Forged by plotter ID
        for (int index = nMiningHeight - 1; index >= nBeginHeight; index--) {
            CBlockIndex *pblockIndex = chainActive[index];
            nAvgBaseTarget += pblockIndex->nBaseTarget;

            // 1. Multi plotter generate to same wallet (like pool)
            // 2. Same plotter generate to multi wallets (for decrease pledge)
            if (pblockIndex->minerAccountID == minerAccountID || pblockIndex->nPlotterId == plotterId) {
                ++nTotalForgeCount;

                if (pblockIndex->minerAccountID != minerAccountID) {
                    // Old consensus: multi mining. Plotter ID bind to multi miner (also multi wallet)
                    nTotalForgeCountOldConsensus = -1;
                } else if (nTotalForgeCountOldConsensus != -1) {
                    nTotalForgeCountOldConsensus++;
                }
            }
            assert(nTotalForgeCount >= nTotalForgeCountOldConsensus);
        }
    } else {
        // Bind plotter actived
        std::set<uint64_t> plotters;
        view.GetAccountBindPlotters(minerAccountID, plotters);
        for (int index = nMiningHeight - 1; index >= nBeginHeight; index--) {
            CBlockIndex *pblockIndex = chainActive[index];
            nAvgBaseTarget += pblockIndex->nBaseTarget;

            if (plotters.count(pblockIndex->nPlotterId))
                ++nTotalForgeCount;
        }
        if (nTotalForgeCount < nMiningHeight - nBeginHeight)
            nTotalForgeCount++;
    }
    if (nTotalForgeCount == 0)
        return 0;

    // Net capacity
    nAvgBaseTarget /= (nMiningHeight - nBeginHeight);
    int64_t nNetCapacityTB = std::max(static_cast<int64_t>(poc::MAX_BASE_TARGET / nAvgBaseTarget), static_cast<int64_t>(1));

    // Old consensus pledge
    if (pMinerPledgeOldConsensus != nullptr) {
        if (nTotalForgeCountOldConsensus == -1) {
            *pMinerPledgeOldConsensus = MAX_MONEY;
        } else if (nTotalForgeCountOldConsensus > 0) {
            int64_t nMinerCapacityTBOldConsensus = std::max((nNetCapacityTB * nTotalForgeCountOldConsensus) / (nMiningHeight - nBeginHeight), static_cast<int64_t>(1));
            *pMinerPledgeOldConsensus = consensusParams.BHDIP001PledgeAmountPerTB * nMinerCapacityTBOldConsensus;
        }
    }

    // New consensus pledge
    int64_t nMinerCapacityTB = std::max((nNetCapacityTB * nTotalForgeCount) / (nMiningHeight - nBeginHeight), static_cast<int64_t>(1));
    return consensusParams.BHDIP001PledgeAmountPerTB * nMinerCapacityTB;
}

bool CheckProofOfCapacity(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params)
{
    // Check deadline
    uint64_t deadline = CalculateDeadline(prevBlockIndex, block, params);
    if (deadline > poc::MAX_TARGET_DEADLINE)
        return false; 

    if (prevBlockIndex.nHeight + 1 < params.BHDIP007Height) {
        return deadline == 0 || block.GetBlockTime() > prevBlockIndex.GetBlockTime() + (int64_t)deadline;
    } else {
        // Strict check time interval
        return block.GetBlockTime() == prevBlockIndex.GetBlockTime() + (int64_t)deadline + 1;
    }
}

bool AddMiningSignaturePrivkey(const std::string &privkey, std::string *newAddress)
{
    CBitcoinSecret vchSecret;
    if (vchSecret.SetString(privkey)) {
        CKey key = vchSecret.GetKey();
        if (key.IsValid()) {
            // P2SH-Segwit
            std::shared_ptr<CKey> privKeyPtr = std::make_shared<CKey>(key);
            CKeyID keyid = privKeyPtr->GetPubKey().GetID();
            CTxDestination segwit = WitnessV0KeyHash(keyid);
            CTxDestination dest = CScriptID(GetScriptForDestination(segwit));
            if (newAddress)
                *newAddress = EncodeDestination(dest);

            LOCK(cs_main);
            mapSignaturePrivKeys[boost::get<CScriptID>(&dest)->GetUint64(0)] = privKeyPtr;
            return true;
        }
    }

    return false;
}

std::vector<std::string> GetMiningSignatureAddresses()
{
    LOCK(cs_main);

    std::vector<std::string> addresses;
    addresses.reserve(mapSignaturePrivKeys.size());
    for (auto it = mapSignaturePrivKeys.cbegin(); it != mapSignaturePrivKeys.cend(); it++) {
        CKeyID keyid = it->second->GetPubKey().GetID();
        CTxDestination segwit = WitnessV0KeyHash(keyid);
        CTxDestination dest = CScriptID(GetScriptForDestination(segwit));
        addresses.push_back(EncodeDestination(dest));
    }

    return addresses;
}

}

bool StartPOC()
{
    LogPrintf("Starting PoC module\n");
    interruptCheckDeadline.reset();
    if (gArgs.GetBoolArg("-server", false)) {
        LogPrintf("Starting PoC forge thread\n");
        threadCheckDeadline = std::thread(CheckDeadlineThread);

        // import private key
        for (const std::string &privkey : gArgs.GetArgs("-miningsign")) {
            std::string strkeyLog = (privkey.size() > 5 ? privkey.substr(0, 5) : privkey) +
                                    "******************************************" +
                                    (privkey.size() > 5 ? privkey.substr(privkey.size() - 5, 5) : privkey);
            std::string address;
            if (poc::AddMiningSignaturePrivkey(privkey, &address)) {
                LogPrintf("Import mining-sign address %s from %s\n", address, strkeyLog);
            } else {
                LogPrintf("Import invalid mining-sign private key from -miningsign=\"%s\"\n", strkeyLog);
            }
        }

    #ifdef ENABLE_WALLET
        // From current wallet
        for (CWalletRef pwallet : vpwallets) {
            CTxDestination dest = pwallet->GetPrimaryDestination();
            CKeyID keyid = GetKeyForDestination(*pwallet, dest);
            if (!keyid.IsNull()) {
                std::shared_ptr<CKey> privKey = std::make_shared<CKey>();
                if (pwallet->GetKey(keyid, *privKey)) {
                    LOCK(cs_main);
                    mapSignaturePrivKeys[boost::get<CScriptID>(&dest)->GetUint64(0)] = privKey;

                    LogPrintf("Import mining-sign from wallet primary address %s\n", EncodeDestination(dest));
                }
            }
        }
    #endif

    } else {
        LogPrintf("Skip PoC forge thread\n");
    }
    
    return true;
}

void InterruptPOC()
{
    LogPrintf("Interrupting PoC module\n");
    interruptCheckDeadline();
}

void StopPOC()
{
    if (threadCheckDeadline.joinable())
        threadCheckDeadline.join();

    mapSignaturePrivKeys.clear();

    LogPrintf("Stopped PoC module\n");
}