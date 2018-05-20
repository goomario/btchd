// Copyright (c) 2017-2018 The BCO Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/consensus.h>

#include <limits>

// BCO fork information
/** The starting height of the fork height. */
static uint64_t BCO_FORK_BLOCK_HEIGHT = std::numeric_limits<uint64_t>::max();
static int64_t BCO_BLOCK_UNIXTIME_MIN = std::numeric_limits<int64_t>::max();

void BCOUpdateConsensus(uint64_t nForkHeight, int64_t nBlockMinTimestamp)
{
    BCO_FORK_BLOCK_HEIGHT = nForkHeight;
    BCO_BLOCK_UNIXTIME_MIN = nBlockMinTimestamp;
}

uint64_t BCOForkBlockHeight()
{
    return BCO_FORK_BLOCK_HEIGHT;
}

int64_t BCOBlockMinTimestamp()
{
    return BCO_BLOCK_UNIXTIME_MIN;
}