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

/** Check whether a block hash satisfies the proof-of-capacity requirement specified by nBaseTarget */
bool CheckProofOfCapacity(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params&);

#endif // BITCOIN_POW_H
