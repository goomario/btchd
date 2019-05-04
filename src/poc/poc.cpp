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
#include <cmath>
#include <exception>
#include <limits>
#include <string>
#include <tuple>
#include <unordered_map>

#include <event2/thread.h>

namespace {

// Generator
struct GeneratorState {
    uint64_t plotterId;
    uint64_t nonce;
    uint64_t best;
    int height;

    CTxDestination dest;
    std::shared_ptr<CKey> privKey;

    GeneratorState() : best(poc::INVALID_DEADLINE) { }
};
typedef std::unordered_map<uint64_t, GeneratorState> Generators; // Generation low 64bits -> GeneratorState
Generators mapGenerators;

std::shared_ptr<CBlock> CreateBlock(const GeneratorState &generateState)
{
    AssertLockHeld(cs_main);

    std::unique_ptr<CBlockTemplate> pblocktemplate;
    try {
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(GetScriptForDestination(generateState.dest), true,
            generateState.plotterId, generateState.nonce, generateState.best / chainActive.Tip()->nBaseTarget,
            generateState.privKey);
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
        if (!interruptCheckDeadline.sleep_for(std::chrono::milliseconds(200)))
            break;

        std::shared_ptr<CBlock> pblock;
        bool fProcessNewBlock = false;
        bool fReActivateBestChain = false;
        {
            LOCK(cs_main);
            if (!mapGenerators.empty()) {
                if (GetTimeOffset() > MAX_FUTURE_BLOCK_TIME) {
                    LogPrintf("Your computer time maybe abnormal (offset %" PRId64 "). " \
                        "Check your computer time or add -maxtimeadjustment=0 \n", GetTimeOffset());
                }
                int64_t nAdjustedTime = GetAdjustedTime();
                CBlockIndex *pindexTip = chainActive.Tip();
                auto it = mapGenerators.cbegin();
                while (it != mapGenerators.cend() && !pblock) {
                    if (pindexTip->GetNextGenerationSignature().GetUint64(0) == it->first) {
                        // Current round
                        uint64_t deadline = it->second.best / pindexTip->nBaseTarget;
                        if (nAdjustedTime + 1 >= (int64_t)pindexTip->nTime + (int64_t)deadline) {
                            // Forge
                            LogPrint(BCLog::POC, "Generate block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                it->second.height, it->second.nonce, it->second.plotterId, deadline);
                            pblock = CreateBlock(it->second);
                            if (!pblock) {
                                LogPrintf("Generate block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                    it->second.height, it->second.nonce, it->second.plotterId, deadline);
                            } else {
                                LogPrint(BCLog::POC, "Created block: hash=%s, time=%d\n", pblock->GetHash().ToString(), pblock->nTime);
                                fProcessNewBlock = true;
                            }
                        } else {
                            // Continue wait forge time
                            ++it;
                            continue;
                        }
                    } else if (pindexTip->GetGenerationSignature().GetUint64(0) == it->first) {
                        // Previous round
                        // Process future post block (MAX_FUTURE_BLOCK_TIME). My deadline is best(highest chainwork).
                        uint64_t mineDeadline = it->second.best / pindexTip->pprev->nBaseTarget;
                        uint64_t tipDeadline = (uint64_t) (pindexTip->GetBlockTime() - pindexTip->pprev->GetBlockTime() - 1);
                        if (mineDeadline <= tipDeadline) {
                            LogPrint(BCLog::POC, "Snatch block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 " <= %" PRIu64 "\n",
                                it->second.height, it->second.nonce, it->second.plotterId, mineDeadline, tipDeadline);

                            // Invalidate tip block
                            CValidationState state;
                            if (!InvalidateBlock(state, Params(), pindexTip)) {
                                LogPrint(BCLog::POC, "Snatch block fail: invalidate %s got\n\t%s\n", pindexTip->ToString(), state.GetRejectReason());
                            } else {
                                fReActivateBestChain = true;
                                ResetBlockFailureFlags(pindexTip);

                                pblock = CreateBlock(it->second);
                                if (!pblock) {
                                    LogPrintf("Snatch block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                        it->second.height, it->second.nonce, it->second.plotterId, mineDeadline);
                                } else if (GetBlockProof(*pblock, Params().GetConsensus()) > GetBlockProof(*pindexTip, Params().GetConsensus())) {
                                    LogPrint(BCLog::POC, "Snatch block success: height=%d, hash=%s\n", it->second.height, pblock->GetHash().ToString());
                                    fProcessNewBlock = true;
                                }
                            }
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
        }

        // Broadcast. Not hold cs_main
        if (fProcessNewBlock && !ProcessNewBlock(Params(), pblock, true, nullptr))
            LogPrintf("Process new block fail %s\n", pblock->ToString());
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

//! Thread safe
static uint64_t CalcDL(int nHeight, const uint256& generationSignature, const uint64_t& nPlotterId, const uint64_t& nNonce, const Consensus::Params& params) {
    CShabal256 shabal256;
    uint256 temp;

    // Scoop
    const uint64_t flipHeight = htobe64(static_cast<uint64_t>(nHeight));
    shabal256
        .Write(generationSignature.begin(), generationSignature.size())
        .Write((const unsigned char*)&flipHeight, sizeof(flipHeight))
        .Finalize((unsigned char*)temp.begin());
    const uint32_t scoop = (uint32_t) (temp.begin()[31] + 256 * temp.begin()[30]) % 4096;

    // Row data
    const uint64_t addr = htobe64(nPlotterId);
    const uint64_t nonce = htobe64(nNonce);
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
    return temp.GetUint64(0);
}

//! Thread unsafe
static uint64_t CalculateUnformattedDeadline(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    // Fund
    if (prevBlockIndex.nHeight + 1 <= params.BHDIP001StartMingingHeight)
        return 0;

    // BHDIP006 disallow plotter 0
    if (block.nPlotterId == 0 && prevBlockIndex.nHeight + 1 >= params.BHDIP006Height)
        return poc::INVALID_DEADLINE;

    // Regtest use nonce as deadline
    if (params.fPocAllowMinDifficultyBlocks)
        return block.nNonce * prevBlockIndex.nBaseTarget;

    return CalcDL(prevBlockIndex.nHeight + 1, prevBlockIndex.GetNextGenerationSignature(), block.nPlotterId, block.nNonce, params);
}

// Require hold cs_main
uint64_t CalculateDeadline(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    return CalculateUnformattedDeadline(prevBlockIndex, block, params) / prevBlockIndex.nBaseTarget;
}

uint64_t CalculateBaseTarget(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    int nHeight = prevBlockIndex.nHeight + 1;
    if (nHeight <= params.BHDIP001StartMingingHeight) {
        // genesis block & pre-mining block
        return BHD_BASE_TARGET_240;
    } else if (nHeight < params.BHDIP001StartMingingHeight + 4) {
        return BHD_BASE_TARGET_240;
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
        if (newBaseTarget > BHD_BASE_TARGET_240) {
            newBaseTarget = BHD_BASE_TARGET_240;
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
        if (newBaseTarget > BHD_BASE_TARGET_240) {
            newBaseTarget = BHD_BASE_TARGET_240;
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

uint64_t AddNonce(uint64_t& bestDeadline, const CBlockIndex& miningBlockIndex,
    const uint64_t& nNonce, const uint64_t& nPlotterId, const std::string& generateTo,
    bool fCheckBind, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);

    if (interruptCheckDeadline)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Not run in mining mode, restart by -server");

    CBlockHeader block;
    block.nPlotterId = nPlotterId;
    block.nNonce     = nNonce;
    const uint64_t calcUnformattedDeadline = CalculateUnformattedDeadline(miningBlockIndex, block, params);
    if (calcUnformattedDeadline == INVALID_DEADLINE)
        throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid deadline");

    const uint64_t calcDeadline = calcUnformattedDeadline / miningBlockIndex.nBaseTarget;
    LogPrint(BCLog::POC, "Add nonce: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
        miningBlockIndex.nHeight + 1, nNonce, nPlotterId, calcDeadline);
    bestDeadline = calcDeadline;
    bool fNewBest = false;
    if (miningBlockIndex.nHeight >= chainActive.Height() - 1) {
        // Only tip and previous block
        auto it = mapGenerators.find(miningBlockIndex.GetNextGenerationSignature().GetUint64(0));
        if (it != mapGenerators.end()) {
            if (it->second.best > calcUnformattedDeadline) {
                fNewBest = true;
            } else {
                fNewBest = false;
                bestDeadline = it->second.best / miningBlockIndex.nBaseTarget;
            }
        } else {
            fNewBest = true;
        }
    }

    if (fNewBest) {
        CTxDestination dest;
        std::shared_ptr<CKey> privKey;
        if (generateTo.empty()) {
            // Update generate address from wallet
        #ifdef ENABLE_WALLET
            CWalletRef pwallet = vpwallets.empty() ? nullptr : vpwallets[0];
            if (!pwallet)
                throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Require generate destination address or private key");
            dest = pwallet->GetPrimaryDestination();
        #else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Require generate destination address or private key");
        #endif
        } else {
            dest = DecodeDestination(generateTo);
            if (!boost::get<CScriptID>(&dest)) {
                // Maybe privkey
                CBitcoinSecret vchSecret;
                if (!vchSecret.SetString(generateTo))
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid generate destination address or private key");
                CKey key = vchSecret.GetKey();
                if (!key.IsValid()) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid generate destination address or private key");
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
            throw JSONRPCError(RPC_INVALID_REQUEST, "Invalid BitcoinHD address");

        // Check bind
        if (miningBlockIndex.nHeight + 1 >= params.BHDIP006Height) {
            CAccountID accountID = GetAccountIDByTxDestination(dest);
            if (accountID == 0)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BitcoinHD address");
            if (!pcoinsTip->HaveActiveBindPlotter(accountID, nPlotterId))
                throw JSONRPCError(RPC_INVALID_REQUEST, strprintf("%" PRIu64 " with %s not active bind", nPlotterId, EncodeDestination(dest)));
        }

        // Update private key for signature
        if (miningBlockIndex.nHeight + 1 >= params.BHDIP007Height) {
            uint64_t destId = boost::get<CScriptID>(&dest)->GetUint64(0);

            // From cache
            if (!privKey && mapSignaturePrivKeys.count(destId))
                privKey = mapSignaturePrivKeys[destId];

            // From wallets
        #ifdef ENABLE_WALLET
            if (!privKey) {
                for (CWalletRef pwallet : vpwallets) {
                    CKeyID keyid = GetKeyForDestination(*pwallet, dest);
                    if (!keyid.IsNull()) {
                        CKey key;
                        if (pwallet->GetKey(keyid, key)) {
                            privKey = std::make_shared<CKey>(key);
                            break;
                        }
                    }
                }
            }
        #endif

            if (!privKey)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Require private key for block signature");

            if (!mapSignaturePrivKeys.count(destId))
                mapSignaturePrivKeys[destId] = privKey;
        }

        // Update best
        GeneratorState &generatorState = mapGenerators[miningBlockIndex.GetNextGenerationSignature().GetUint64(0)];
        generatorState.plotterId = nPlotterId;
        generatorState.nonce     = nNonce;
        generatorState.best      = calcUnformattedDeadline;
        generatorState.height    = miningBlockIndex.nHeight + 1;
        generatorState.dest      = dest;
        generatorState.privKey   = privKey;

        LogPrint(BCLog::POC, "New best deadline %" PRIu64 ".\n", calcDeadline);

        uiInterface.NotifyBestDeadlineChanged(generatorState.height, generatorState.plotterId, generatorState.nonce, calcDeadline);
    }

    return calcDeadline;
}

CBlockList GetEvalBlocks(int nHeight, bool fAscent, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);
    assert(nHeight >= 0 && nHeight <= chainActive.Height());

    CBlockList vBlocks;
    int nBeginHeight = std::max(nHeight - params.nCapacityEvalWindow + 1, params.BHDIP001StartMingingHeight + 1);
    if (nHeight >= nBeginHeight) {
        vBlocks.reserve(nHeight - nBeginHeight + 1);
        if (fAscent) {
            for (int height = nBeginHeight; height <= nHeight; height++) {
                vBlocks.push_back(std::cref(*(chainActive[height])));
            }
        } else {
            for (int height = nHeight; height >= nBeginHeight; height--) {
                vBlocks.push_back(std::cref(*(chainActive[height])));
            }
        }
    }
    return vBlocks;
}

int64_t GetNetCapacity(int nHeight, const Consensus::Params& params)
{
    AssertLockHeld(cs_main);
    assert(nHeight >= 0 && nHeight <= chainActive.Height());

    uint64_t nBaseTarget = 0;
    int nBlockCount = 0;
    for (const CBlockIndex& block : GetEvalBlocks(nHeight, true, params)) {
        nBaseTarget += block.nBaseTarget;
        nBlockCount++;
    }

    if (nBlockCount != 0) {
        nBaseTarget /= nBlockCount;
        if (nBaseTarget > 0) {
            return std::max(static_cast<int64_t>(poc::BHD_BASE_TARGET / nBaseTarget), (int64_t) 1);
        }
    }

    return (int64_t) 1;
}

template <uint64_t BaseTarget>
static int64_t GetNetCapacity(int nHeight, const Consensus::Params& params, std::function<void(const CBlockIndex&)> associateBlock)
{
    uint64_t nBaseTarget = 0;
    int nBlockCount = 0;
    for (const CBlockIndex& block : GetEvalBlocks(nHeight, true, params)) {
        associateBlock(block);
        nBaseTarget += block.nBaseTarget;
        nBlockCount++;
    }

    if (nBlockCount != 0) {
        nBaseTarget /= nBlockCount;
        if (nBaseTarget > 0) {
            return std::max(static_cast<int64_t>(BaseTarget / nBaseTarget), (int64_t) 1);
        }
    }

    return (int64_t) 1;
}

int64_t GetNetCapacity(int nHeight, const Consensus::Params& params, std::function<void(const CBlockIndex&)> associateBlock)
{
    AssertLockHeld(cs_main);
    assert(nHeight >= 0 && nHeight <= chainActive.Height());

    return GetNetCapacity<BHD_BASE_TARGET>(nHeight, params, associateBlock);
}

// Round to cent coin
static inline CAmount RoundPledgeRatio(CAmount amount)
{
    const CAmount percise = COIN / 10000;
    return ((amount + percise / 2) / percise) * percise;
}

CAmount EvalPledgeRatio(int nHeight, int64_t nNetCapacityTB, const Consensus::Params& params, int* pRatioStage)
{
    if (nHeight < params.BHDIP007Height) {
        // Legacy
        if (pRatioStage) *pRatioStage = -2;

        CAmount nLegacyRatio = RoundPledgeRatio(params.BHDIP001PledgeRatio * BHD_BASE_TARGET_240 / BHD_BASE_TARGET);
        return nLegacyRatio;
    } else if (nHeight <= params.BHDIP007SmoothEndHeight) {
        // Smooth
        if (pRatioStage) *pRatioStage = -1;

        CAmount nLegacyRatio = RoundPledgeRatio(params.BHDIP001PledgeRatio * BHD_BASE_TARGET_240 / BHD_BASE_TARGET);
        int step = params.BHDIP007SmoothEndHeight - params.BHDIP007Height + 1;
        int current = nHeight - params.BHDIP007Height + 1;
        return RoundPledgeRatio(nLegacyRatio - ((nLegacyRatio - params.BHDIP001PledgeRatio) * current) / step);
    } else {
        // Dynamic
        if (nNetCapacityTB <= params.BHDIP007DynPledgeStage) {
            if (pRatioStage) *pRatioStage = -1;
            return params.BHDIP001PledgeRatio;
        }

        int nStage = std::min((int) (std::log2((float) (nNetCapacityTB / params.BHDIP007DynPledgeStage)) + 0.000005f), 40);
        CAmount nStartRatio = RoundPledgeRatio((CAmount) (std::pow(0.666667f, (float) nStage) * params.BHDIP001PledgeRatio));
        CAmount nTargetRatio =  RoundPledgeRatio((CAmount) (std::pow(0.666667f, (float) (nStage + 1)) * params.BHDIP001PledgeRatio));
        int64_t nStartCapacityTB = (((int64_t)1) << nStage) * params.BHDIP007DynPledgeStage;
        int64_t nEndCapacityTB = nStartCapacityTB * 2;
        assert (nStartCapacityTB <= nNetCapacityTB && nNetCapacityTB <= nEndCapacityTB);

        if (pRatioStage) *pRatioStage = nStage;

        int64_t nPartCapacityTB = std::max(nEndCapacityTB - nNetCapacityTB, (int64_t) 0);
        return nTargetRatio + RoundPledgeRatio(((nStartRatio - nTargetRatio) * nPartCapacityTB) / (nEndCapacityTB - nStartCapacityTB));
    }
}

CAmount GetPledgeRatio(int nHeight, const Consensus::Params& params, int* pRatioStage, int64_t* pRatioCapacityTB)
{
    AssertLockHeld(cs_main);
    assert(nHeight >= 0 && nHeight <= chainActive.Height() + 1);

    int64_t nNetCapacityTB = 0;
    if (nHeight > params.BHDIP007SmoothEndHeight) {
        int nAdjustHeight = ((nHeight - 1) / params.nCapacityEvalWindow) * params.nCapacityEvalWindow;
        nNetCapacityTB = GetNetCapacity(nAdjustHeight, params);
        if (pRatioCapacityTB) *pRatioCapacityTB = nNetCapacityTB;
    } else {
        if (pRatioCapacityTB) *pRatioCapacityTB = params.BHDIP007DynPledgeStage;
    }

    return EvalPledgeRatio(nHeight, nNetCapacityTB, params, pRatioStage);
}

CAmount GetCapacityPledgeAmount(int64_t nCapacityTB, CAmount pledgeRatio)
{
    return ((pledgeRatio * nCapacityTB + COIN/2) / COIN) * COIN;
}

// Compatible BHD007 before consensus
static inline CAmount GetCompatiblePledgeRatio(int nMiningHeight, const Consensus::Params& params)
{
    return nMiningHeight < params.BHDIP007Height ? params.BHDIP001PledgeRatio : GetPledgeRatio(nMiningHeight, params);
}

// Compatible BHD007 before consensus
static inline int64_t GetCompatibleNetCapacity(int nMiningHeight, const Consensus::Params& params, std::function<void(const CBlockIndex&)> associateBlock)
{
    if (nMiningHeight < params.BHDIP007Height)
        return GetNetCapacity<BHD_BASE_TARGET_240>(nMiningHeight - 1, params, associateBlock);
    else
        return GetNetCapacity<BHD_BASE_TARGET>(nMiningHeight - 1, params, associateBlock);
}

CAmount GetMiningPledgeAmount(const CAccountID& minerAccountID, const uint64_t& nPlotterId, int nMiningHeight,
    const CCoinsViewCache& view, int64_t* pMinerCapacity, CAmount* pOldMinerPledge,
    const Consensus::Params& params)
{
    AssertLockHeld(cs_main);
    assert(nMiningHeight > 0 && nMiningHeight <= chainActive.Height() + 1);
    assert(GetSpendHeight(view) == nMiningHeight);

    if (pMinerCapacity != nullptr) *pMinerCapacity = 0;
    if (pOldMinerPledge != nullptr) *pOldMinerPledge = 0;

    const CAmount pledgeRatio = GetCompatiblePledgeRatio(nMiningHeight, params);

    int64_t nNetCapacityTB = 0;
    int nBlockCount = 0, nMinedCount = 0;
    if (nMiningHeight < params.BHDIP006BindPlotterActiveHeight) {
        // Mined by plotter ID
        int nOldMinedCount = 0;
        nNetCapacityTB = GetCompatibleNetCapacity(nMiningHeight, params,
            [&nBlockCount, &nMinedCount, &nOldMinedCount, &minerAccountID, &nPlotterId] (const CBlockIndex &block) {
                nBlockCount++;

                // 1. Multi plotter generate to same wallet (like pool)
                // 2. Same plotter generate to multi wallets (for decrease pledge)
                if (block.minerAccountID == minerAccountID || block.nPlotterId == nPlotterId) {
                    nMinedCount++;

                    if (block.minerAccountID != minerAccountID) {
                        // Old consensus: multi mining. Plotter ID bind to multi miner
                        nOldMinedCount = -1;
                    } else if (nOldMinedCount != -1) {
                        nOldMinedCount++;
                    }
                }
            }
        );

        // Old consensus pledge
        if (pOldMinerPledge != nullptr && nBlockCount > 0) {
            if (nOldMinedCount == -1) {
                // Multi mining
                *pOldMinerPledge = MAX_MONEY;
            } else if (nOldMinedCount > 0) {
                int64_t nOldMinerCapacityTB = std::max((nNetCapacityTB * nOldMinedCount) / nBlockCount, (int64_t) 1);
                *pOldMinerPledge = GetCapacityPledgeAmount(nOldMinerCapacityTB, pledgeRatio);
            }
        }
    } else {
        // Binded plotter
        std::set<uint64_t> plotters = view.GetAccountBindPlotters(minerAccountID);
        nNetCapacityTB = GetCompatibleNetCapacity(nMiningHeight, params,
            [&nBlockCount, &nMinedCount, &plotters] (const CBlockIndex &block) {
                nBlockCount++;

                if (plotters.count(block.nPlotterId))
                    nMinedCount++;
            }
        );
        // Remove sugar
        if (nMinedCount < nBlockCount) nMinedCount++;
    }
    if (nMinedCount == 0 || nBlockCount == 0)
        return 0;

    int64_t nMinerCapacityTB = std::max((nNetCapacityTB * nMinedCount) / nBlockCount, (int64_t) 1);
    if (pMinerCapacity != nullptr) *pMinerCapacity = nMinerCapacityTB;
    return GetCapacityPledgeAmount(nMinerCapacityTB, pledgeRatio);
}

bool CheckProofOfCapacity(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params)
{
    uint64_t deadline = CalculateDeadline(prevBlockIndex, block, params);

    // Maybe overflow on arithmetic operation
    if (deadline > poc::MAX_TARGET_DEADLINE)
        return false;

    if (prevBlockIndex.nHeight + 1 < params.BHDIP007Height) {
        return deadline == 0 || block.GetBlockTime() > prevBlockIndex.GetBlockTime() + (int64_t)deadline;
    } else {
        // Strict check time interval
        return block.GetBlockTime() == prevBlockIndex.GetBlockTime() + (int64_t)deadline + 1;
    }
}

bool AddMiningSignaturePrivkey(const std::string& privkey, std::string* newAddress)
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
        interruptCheckDeadline();
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