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
#include <validation.h>

uint64_t GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);

    return ::poc::CalculateBaseTarget(*pindexLast, *pblock, params);
}

bool CheckProofOfCapacity(const CBlockHeader* pblock, const Consensus::Params& params, bool bCheckPoCDeadline)
{
    if (pblock->hashPrevBlock.IsNull()) {
        // Genesis
        return pblock->GetHash() == params.hashGenesisBlock;
    }

    auto iter = mapBlockIndex.find(pblock->hashPrevBlock);
    if (iter == mapBlockIndex.end()) {
        return false;
    }
    return ::poc::VerifyGenerationSignature(*(iter->second), *pblock, bCheckPoCDeadline, params);
}
