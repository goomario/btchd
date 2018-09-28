// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

uint64_t GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);

enum class PocVerifyLevel {
    Force,      //< Verify all block
    Checkpoint, //< Only verify checkpoint block
    Auto,       //< Verify checkpoint and  checkpoint after block
    Skip,       //< Dont verify any block. Reserved!
};

/** Check whether a block hash satisfies the proof-of-capacity requirement specified by nBaseTarget */
bool CheckProofOfCapacity(const CBlockHeader* pblock, const Consensus::Params&, PocVerifyLevel pocVerifyLevel = PocVerifyLevel::Force);

#endif // BITCOIN_POW_H
