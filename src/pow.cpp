// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <chainparams.h>
#include <chain.h>
#include <poc/poc.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util.h>
#include <validation.h>

uint64_t GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& consensusParams)
{
    assert(pindexLast != nullptr);
    AssertLockHeld(cs_main);

    return ::poc::CalculateBaseTarget(*pindexLast, *pblock, consensusParams);
}

bool CheckProofOfCapacity(const CBlockHeader* pblock, const Consensus::Params& consensusParams, bool fForceVerify)
{
    assert(pblock != nullptr);
    AssertLockHeld(cs_main);

    const CBlockIndex* pindexPrev = nullptr;
    if (!pblock->hashPrevBlock.IsNull()) {
        auto mi = mapBlockIndex.find(pblock->hashPrevBlock);
        pindexPrev = (mi != mapBlockIndex.end() ? mi->second : nullptr);
    }

    uint256 blockHash = pblock->GetHash();
    if (pindexPrev == nullptr) {
        // Genesis
        return blockHash == consensusParams.hashGenesisBlock;
    }

    bool fForceVerifyPoC = fForceVerify || gArgs.GetBoolArg("-forceverifypoc", false);
    if (!fForceVerifyPoC) {
        const MapCheckpoints &mapCheckpoints = Params().Checkpoints().mapCheckpoints;
        if (mapCheckpoints.empty()) {
            // Force check
            fForceVerifyPoC = true;
        } else if (mapCheckpoints.count(pindexPrev->nHeight + 1)) {
            // Verify checkpoint
            if (mapCheckpoints.find(pindexPrev->nHeight + 1)->second != blockHash)
                return false;
        } else if (pindexPrev->nHeight + 1 > mapCheckpoints.rbegin()->first) {
            // Force check new block
            fForceVerifyPoC = true;
        }
    }
    if (!fForceVerifyPoC)
        return true;

    // Check deadline
    uint64_t deadline = poc::CalculateDeadline(*pindexPrev, *pblock, consensusParams);
    return deadline <= poc::MAX_TARGET_DEADLINE && (deadline == 0 || pblock->nTime > pindexPrev->nTime + deadline);
}
