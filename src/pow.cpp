// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <poc/poc.h>
#include <primitives/block.h>

bool CheckProofOfCapacity(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& consensusParams)
{
    assert(pindexLast != nullptr);

    // Check deadline
    uint64_t deadline = poc::CalculateDeadline(*pindexLast, *pblock, consensusParams);
    return deadline <= poc::MAX_TARGET_DEADLINE && (deadline == 0 || pblock->nTime > pindexLast->nTime + deadline);
}
