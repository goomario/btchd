// Copyright (c) 2017-2018 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POC_POC_H
#define BITCOIN_POC_POC_H

#include <script/script.h>

#include <amount.h>
#include <arith_uint256.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <stdlib.h>
#include <stdint.h>

#include <vector>

class CBlockHeader;
class CBlock;
class CBlockIndex;
class CCoinsViewCache;

namespace Consensus { struct Params; }

namespace poc {

/** 2^64, 0x10000000000000000*/
static const arith_uint256 TWO64 = arith_uint256(std::numeric_limits<uint64_t>::max()) + 1;

/**
 * Initial base target.
 * 
 * This correct value is 14660155037.
 * See https://www.reddit.com/r/burstcoin/comments/akbxcy/genesis_base_target_bhd_capacity_estimates/.
 */
static const uint64_t INITIAL_BASE_TARGET = 18325193796L; // 0x0000000444444444

/** Max target */
static const uint64_t MAX_BASE_TARGET = 18325193796L; // 0x0000000444444444

// Max target deadline
static const int64_t MAX_TARGET_DEADLINE = std::numeric_limits<uint32_t>::max();

// Invalid deadline
static const uint64_t INVALID_DEADLINE = std::numeric_limits<uint64_t>::max();

/** Calculate deadline */
uint64_t CalculateDeadline(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params, bool fEnableCache = true);

/** Calculate base target */
uint64_t CalculateBaseTarget(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params);

/** Add new nonce */
uint64_t AddNonce(uint64_t &bestDeadline, const CBlockIndex &prevBlockIndex, const uint64_t &nNonce, const uint64_t &nPlotterId,
    const std::string &generateTo, bool fCheckBind, const Consensus::Params& params);

/**
 * Get miner pledge forge block
 *
 * @param minerAccountID Miner address digit ID
 * @param nPlotterId Proof of capacity ID
 * @param nMiningHeight The height of pledge if forge block
 * @param view The coin view
 * @param params Consensus params
 * @param pMinerPledgeOldConsensus Only in BHDIP004. See https://btchd.org/wiki/BHDIP/004#getminerpledge
 * 
 * return MAX_MONEY if not bind. See https://btchd.org/wiki/BHDIP/006
 */
CAmount GetMinerForgePledge(const CAccountID &minerAccountID, const uint64_t &plotterId, int nMiningHeight, const CCoinsViewCache &view,
    const Consensus::Params &params, CAmount *pMinerPledgeOldConsensus = nullptr);

/**
 * Check block work
 */
bool CheckProofOfCapacity(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params);

/**
 * Add private key for mining signature
 */
bool AddMiningSignaturePrivkey(const std::string &privkey, std::string *newAddress = nullptr);

/**
 * Get mining signature addresses
 */
std::vector<std::string> GetMiningSignatureAddresses();

}

bool StartPOC();
void InterruptPOC();
void StopPOC();

#endif
