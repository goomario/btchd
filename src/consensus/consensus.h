// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>

// BCO fork information
/** The starting height of the fork height. */
static const uint64_t BCO_FORK_BLOCK_HEIGHT = 501948 + 1; // 00000000000000000069c0ed50d118cef1e727cf5210fe1a7dddb835c752844e
static const int64_t BCO_BLOCK_UNIXTIME_MIN = 1522396264; // 2018-03-30 15:51:04

inline unsigned int MaxBlockSize(uint64_t nblock) {
    if (nblock < BCO_FORK_BLOCK_HEIGHT)
        return 4000*1000; // 4MB

    return (8*1000*1000); // 8MB
}

inline unsigned int MaxBlockSigops(uint64_t nblock) {
    return MaxBlockSize(nblock) / 50;
}

inline unsigned int MaxBlockSerializedSize(uint64_t nblock) {
    if (nblock < BCO_FORK_BLOCK_HEIGHT)
        return 4000*1000;

    return (8*1000*1000);
}

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
//static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
//static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);
/** Use GetMedianTimePast() instead of nTime for end point timestamp. */
static constexpr unsigned int LOCKTIME_MEDIAN_TIME_PAST = (1 << 1);

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
