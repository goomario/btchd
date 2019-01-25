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
#include <ui_interface.h>
#include <util.h>
#include <utiltime.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <timedata.h>
#include <threadinterrupt.h>

#include <inttypes.h>

#include <exception>
#include <limits>
#include <string>
#include <tuple>

#include <event2/thread.h>

namespace {

std::shared_ptr<CBlock> CreateBlock(CBlockIndex &prevBlockIndex, const uint64_t &nNonce, const uint64_t &nPlotterId, const uint64_t &nDeadline, const std::string &address)
{
    AssertLockHeld(cs_main);

    CScript scriptPubKey;
    if (address.empty()) {
        // From wallet
        if (::vpwallets.empty())
            return nullptr;

        std::shared_ptr<CReserveScript> coinbaseScript;
        ::vpwallets[0]->GetScriptForMining(coinbaseScript);
        if (!coinbaseScript) {
            LogPrintf("Cannot load script from wallet\n");
            return nullptr;
        }
        scriptPubKey = coinbaseScript->reserveScript;
    } else {
        // From address
        CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest)) {
            LogPrintf("Invalidate BitcoinHD address: %s\n", address);
            return nullptr;
        }
        scriptPubKey = GetScriptForDestination(dest);
    }
    if (scriptPubKey.empty()) {
        return nullptr;
    }

    std::unique_ptr<CBlockTemplate> pblocktemplate;
    try {
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(scriptPubKey, true, nNonce, nPlotterId, nDeadline);
    } catch (std::exception &e) {
        const char *what = e.what();
        LogPrintf("%s\n", what ? what : "CreateBlock(): Catch unknown exception");
    }
    if (!pblocktemplate.get()) 
        return nullptr;

    CBlock *pblock = &pblocktemplate->block;

    unsigned int nHeight = prevBlockIndex.nHeight + 1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(static_cast<int64_t>(nNonce)) << CScriptNum(static_cast<int64_t>(nPlotterId))) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    return std::make_shared<CBlock>(*pblock);
}

// Generator
struct GeneratorState {
    uint64_t nonce;
    uint64_t plotterId;
    uint64_t deadline;
    std::string address; // Generate to

    GeneratorState() : deadline(poc::INVALID_DEADLINE) { }
};
typedef std::unordered_map<int, GeneratorState> Generators; // height -> GeneratorState
Generators mapGenerators;

CThreadInterrupt interruptCheckDeadline;
std::thread threadCheckDeadline;
void CheckDeadlineThread()
{
    RenameThread("bitcoin-checkdeadline");
    while (!interruptCheckDeadline) {
        if (!interruptCheckDeadline.sleep_for(std::chrono::milliseconds(500)))
            break;
        
        std::shared_ptr<CBlock> pblock;
        uint64_t deadline = std::numeric_limits<uint64_t>::max();
        int height = 0;
        bool fReActivateBestChain = false;
        {
            LOCK(cs_main);
            if (!mapGenerators.empty()) {
                CBlockIndex *pindexTip = chainActive.Tip();
                int64_t nAdjustedTime = GetAdjustedTime();
                auto it = mapGenerators.begin();
                while (it != mapGenerators.end() && !pblock) {
                    if (pindexTip->nHeight + 1 == it->first) {
                        // Current height
                        if (nAdjustedTime + 1 >= (int64_t)pindexTip->nTime + (int64_t)it->second.deadline) {
                            // forge
                            LogPrint(BCLog::POC, "Generate block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                it->first, it->second.nonce, it->second.plotterId, it->second.deadline);
                            pblock = CreateBlock(*pindexTip, it->second.nonce, it->second.plotterId, it->second.deadline, it->second.address);
                            if (!pblock) {
                                LogPrintf("Generate block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                    it->first, it->second.nonce, it->second.plotterId, it->second.deadline);
                            } else {
                                LogPrint(BCLog::POC, "Created block: %s/%d\n", pblock->GetHash().ToString(), pblock->nTime);
                                height = it->first;
                                deadline = it->second.deadline;
                            }
                        } else {
                            // Continue wait forge time
                            ++it;
                            continue;
                        }
                    } else if (pindexTip->nHeight == it->first) {
                        // Process future post block (MAX_FUTURE_BLOCK_TIME). My deadline is best(highest chainwork). Try snatch block and post block not wait
                        assert(pindexTip->pprev != nullptr);
                        uint64_t nBestDeadline;
                        if (it->second.plotterId == pindexTip->nPlotterId && it->second.nonce == pindexTip->nNonce) {
                            nBestDeadline = it->second.deadline;
                        } else {
                            nBestDeadline = poc::CalculateDeadline(*(pindexTip->pprev), pindexTip->GetBlockHeader(), Params().GetConsensus());
                        }
                        if (it->second.deadline <= nBestDeadline) {
                            // My deadline maybe best. Forge new block
                            LogPrint(BCLog::POC, "Begin snatch block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 ", preDeadline=%" PRIu64 "\n",
                                it->first, it->second.nonce, it->second.plotterId, it->second.deadline, nBestDeadline);
                            // Invalidate tip block
                            CValidationState state;
                            if (!InvalidateBlock(state, Params(), pindexTip)) {
                                LogPrint(BCLog::POC, "Snatch block: invalidate current tip block error, %s\n", state.GetRejectReason());
                                LogPrint(BCLog::POC, "Snatch block: current tip, %s\n", pindexTip->ToString());
                                LogPrint(BCLog::POC, "End snatch block\n");
                            } else {
                                fReActivateBestChain = true;
                                pblock = CreateBlock(*(pindexTip->pprev), it->second.nonce, it->second.plotterId, it->second.deadline, it->second.address);
                                if (!pblock) {
                                    LogPrintf("Snatch block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 ", preDeadline=%" PRIu64 "\n",
                                        it->first, it->second.nonce, it->second.plotterId, it->second.deadline, nBestDeadline);
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
                                            pblock->GetHash().ToString(), pblock->nTime, pindexTip->phashBlock->ToString(), pindexTip->nTime, pindexTip->nHeight);
                                        height = it->first;
                                        deadline = it->second.deadline;

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
                            LogPrint(BCLog::POC, "Snatch block give up: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline (mine=%" PRIu64 ") > (tip=%" PRIu64 ")\n",
                                it->first, it->second.nonce, it->second.plotterId, it->second.deadline, nBestDeadline);
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
        if (deadline != std::numeric_limits<uint64_t>::max() && pblock && !ProcessNewBlock(Params(), pblock, true, nullptr)) {
            LogPrintf("Process new block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                height, pblock->nNonce, pblock->nPlotterId, deadline);
        }
    }

    LogPrintf("Exit PoC forge thread\n");
}

}

namespace poc {

uint64_t GetBlockGenerator(const CBlockHeader &block)
{
    return block.nPlotterId;
}

std::string GetBlockGeneratorRS(const CBlockHeader &block)
{
    return std::to_string(GetBlockGenerator(block));
}

uint256 GetBlockGenerationSignature(const CBlockHeader &prevBlock)
{
    // hashMerkleRoot + nPlotterId
    uint256 result;
    CShabal256()
        .Write((const unsigned char*)prevBlock.hashMerkleRoot.begin(), prevBlock.hashMerkleRoot.size())
        .Write((const unsigned char*)&prevBlock.nPlotterId, sizeof(prevBlock.nPlotterId))
        .Finalize((unsigned char*)result.begin());
    return result;
}

uint64_t GetBlockId(const CBlockHeader &block)
{
    return block.GetHash().GetUint64(0);
}

uint64_t GetBlockId(const CBlockIndex &blockIndex)
{
    return GetBlockId(blockIndex.GetBlockHeader());
}

uint32_t GetBlockScoopNum(const uint256 &genSig, int nHeight)
{
    uint64_t flipHeight = htobe64(static_cast<uint64_t>(nHeight));

    unsigned char result[32];
    CShabal256()
        .Write((const unsigned char*)genSig.begin(), genSig.size())
        .Write((const unsigned char*)&flipHeight, sizeof(flipHeight))
        .Finalize(result);
    // Low 2 bytes mod 2^14
    return (uint32_t) (result[31] + 256 * result[30]) % 4096;
}

static constexpr int HASH_SIZE = 32;
static constexpr int HASHES_PER_SCOOP = 2;
static constexpr int SCOOP_SIZE = HASHES_PER_SCOOP * HASH_SIZE; // 2 hashes per column
static constexpr int SCOOPS_PER_PLOT = 4096;
static constexpr int PLOT_SIZE = SCOOPS_PER_PLOT * SCOOP_SIZE; // 256KB
static std::unique_ptr<uint8_t> calcDLDataCache(new uint8_t[PLOT_SIZE + 16]); // Global calc cache

static uint64_t CalcDL(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params) {
    const uint256 genSig = poc::GetBlockGenerationSignature(prevBlockIndex.GetBlockHeader());
    const uint32_t scopeNum = poc::GetBlockScoopNum(genSig, prevBlockIndex.nHeight + 1);
    const uint64_t addr = htobe64(poc::GetBlockGenerator(block));
    const uint64_t nonce = htobe64(block.nNonce);

    uint8_t *const data = calcDLDataCache.get();
    memcpy(data + PLOT_SIZE, (const unsigned char*)&addr, 8);
    memcpy(data + PLOT_SIZE + 8, (const unsigned char*)&nonce, 8);
    for (int i = PLOT_SIZE; i > 0; i -= HASH_SIZE) {
        int len = PLOT_SIZE + 16 - i;
        if (len > SCOOPS_PER_PLOT) {
            len = SCOOPS_PER_PLOT;
        }

        CShabal256()
            .Write((const unsigned char*)data + i, len)
            .Finalize((unsigned char*)(data + i - HASH_SIZE));
    }
    uint256 fullHash;
    CShabal256()
        .Write((const unsigned char*)data, PLOT_SIZE + 16)
        .Finalize((unsigned char*)fullHash.begin());
    for (int i = 0; i < PLOT_SIZE; i++) {
        data[i] = (uint8_t) (data[i] ^ (fullHash.begin()[i % HASH_SIZE]));
    }

    // PoC2 Rearrangement. Swap high hash
    //
    // [0] [1] [2] [3] ... [N-1]
    // [1] <-> [N-1]
    // [2] <-> [N-2]
    // [3] <-> [N-3]
    //
    // Only care hash data of scopeNum index
    memcpy(data + scopeNum * SCOOP_SIZE + HASH_SIZE, data + (SCOOPS_PER_PLOT - scopeNum) * SCOOP_SIZE - HASH_SIZE, HASH_SIZE);

    // Result
    uint256 target;
    CShabal256()
        .Write((const unsigned char*)genSig.begin(), genSig.size())
        .Write((const unsigned char*)data + scopeNum * SCOOP_SIZE, SCOOP_SIZE)
        .Finalize((unsigned char*)target.begin());
    return target.GetUint64(0) / prevBlockIndex.nBaseTarget;
}

// Require hold cs_main
uint64_t CalculateDeadline(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params, bool fEnableCache)
{
    // Fund
    if (prevBlockIndex.nHeight + 1 <= params.BHDIP001StartMingingHeight)
        return 0;

    // BHDIP006 disallow plotter ID equal 0
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
        // genesis block & god mode block
        return INITIAL_BASE_TARGET;
    } else if (nHeight < params.BHDIP001StartMingingHeight + 4) {
        return INITIAL_BASE_TARGET;
    } else if (nHeight < params.BHDIP001StartMingingHeight + 2700) {
        // [N-1,N-2,N-3,N-4]
        uint64_t avgBaseTarget = prevBlockIndex.nBaseTarget;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        for (int i = nHeight - 2; i >= nHeight - 4; i--) {
            pLastindex = pLastindex->pprev;
            if (pLastindex == nullptr) {
                break;
            }
            avgBaseTarget += pLastindex->nBaseTarget;
        }
        avgBaseTarget /= 4;
        assert(pLastindex != nullptr);

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
        const int N = nHeight < params.BHDIP006Height ? 25 : (24 * 3600 / params.nPowTargetSpacing);
        // [X-1,X-2,...,X-N]
        uint64_t avgBaseTarget = prevBlockIndex.nBaseTarget;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        for (int i = nHeight - 2, blockCounter = 1; i >= nHeight - N; i--,blockCounter++) {
            pLastindex = pLastindex->pprev;
            if (pLastindex == nullptr) {
                break;
            }
            avgBaseTarget = (avgBaseTarget * blockCounter + pLastindex->nBaseTarget) / (blockCounter + 1);
        }
        assert(pLastindex != nullptr);

        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        int64_t targetTimespan = params.nPowTargetSpacing * (N - 1); // 5m * (N-1)blocks

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
    const std::string &address, bool fCheckBind, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);
    LogPrint(BCLog::POC, "Add nonce: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 "\n", prevBlockIndex.nHeight + 1, nNonce, nPlotterId);

    // Check bind
    if (fCheckBind && prevBlockIndex.nHeight + 1 >= params.BHDIP006BindPlotterActiveHeight) {
        CAccountID accountID;
        if (address.empty()) {
            if (::vpwallets.empty())
                return INVALID_DEADLINE_NOTBIND;
            accountID = GetAccountIDByTxDestination(::vpwallets[0]->GetPrimaryDestination());
        } else {
            accountID = GetAccountIDByAddress(address);
        }
        if (!pcoinsTip->HaveActiveBindPlotter(accountID, nPlotterId))
            return INVALID_DEADLINE_NOTBIND;
    }

    CBlockHeader block;
    block.nVersion   = ComputeBlockVersion(&prevBlockIndex, params);
    block.nNonce     = nNonce;
    block.nPlotterId = nPlotterId;

    uint64_t calcDeadline = CalculateDeadline(prevBlockIndex, block, params, false);
    if (calcDeadline > MAX_TARGET_DEADLINE) {
        LogPrint(BCLog::POC, "Cann't accept deadline %5.1fday, more than %" PRIu64 "day.\n",
            calcDeadline / (24 * 60 * 60 * 1.0f), MAX_TARGET_DEADLINE / (24 * 60 * 60));

        auto it = mapGenerators.find(prevBlockIndex.nHeight + 1);
        if (it != mapGenerators.end()) {
            bestDeadline = it->second.deadline;
        } else {
            bestDeadline = 0;
        }
    } else {
        GeneratorState &generator = mapGenerators[prevBlockIndex.nHeight + 1];
        if (calcDeadline < generator.deadline) {
            generator.nonce     = nNonce;
            generator.plotterId = nPlotterId;
            generator.deadline  = calcDeadline;
            generator.address   = address;

            uiInterface.NotifyBestDeadlineChanged(prevBlockIndex.nHeight + 1, nNonce, nPlotterId, calcDeadline);
        }

        bestDeadline = generator.deadline;
    }

    return calcDeadline;
}

int64_t GetForgeEscape()
{
    LOCK(cs_main);
    auto it = mapGenerators.cbegin();
    if (it == mapGenerators.cend()) {
        return -1;
    } else {
        const CBlockIndex *pindexTip = chainActive.Tip();
        int64_t nTime = std::max(pindexTip->GetMedianTimePast() + 1, GetAdjustedTime());
        int64_t nEscapeTime = (int64_t)pindexTip->nTime + (int64_t)it->second.deadline - nTime;
        if (nEscapeTime < 0) {
            nEscapeTime = 0;
        }
        return nEscapeTime;
    }
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

}

bool StartPOC()
{
    LogPrintf("Starting PoC module\n");
    interruptCheckDeadline.reset();
    if (gArgs.GetBoolArg("-server", false)) {
        LogPrintf("Starting PoC forge thread\n");
        threadCheckDeadline = std::thread(CheckDeadlineThread);
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

    LogPrintf("Stopped PoC module\n");
}