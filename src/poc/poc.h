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

#include <functional>
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
 * BHD base target for 240s.
 * 
 * This correct value is 14660155037. ((2^64-1)/300 - 1) / 300 / 4 / 1024 / 1024
 * See https://btchd.org/wiki/The_Proof_of_Capacity#Base_Target
 */
static const uint64_t BHD_BASE_TARGET_240 = 18325193796ull;

// BHD base target. ((2^64-1)/300 - 1) / 300 / 4 / 1024 / 1024
static const uint64_t BHD_BASE_TARGET = 14660155037ull;

// Max target deadline
static const int64_t MAX_TARGET_DEADLINE = std::numeric_limits<uint32_t>::max();

// Invalid deadline
static const uint64_t INVALID_DEADLINE = std::numeric_limits<uint64_t>::max();

/**
 * Calculate deadline
 *
 * @param prevBlockIndex    Previous block
 * @param block             Block header
 * @param params            Consensus params
 *
 * @return Return deadline
 */
uint64_t CalculateDeadline(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params);

/**
 * Calculate base target
 *
 * @param prevBlockIndex    Previous block
 * @param block             Block header
 * @param params            Consensus params
 *
 * @return Return new base target for current block
 */
uint64_t CalculateBaseTarget(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params);

/**
 * Add new nonce
 *
 * @param bestDeadline      Output current best deadline
 * @param prevBlockIndex    Previous block
 * @param nPlotterId        Plot Id
 * @param nNonce            Found nonce
 * @param generateTo        Destination address or private key for block signing
 * @param fCheckBind        Check address and plot bind relation
 * @param params            Consensus params
 *
 * @return Return deadline calc result
 */
uint64_t AddNonce(uint64_t& bestDeadline, const CBlockIndex& prevBlockIndex,
    const uint64_t& nPlotterId, const uint64_t& nNonce, const std::string& generateTo,
    bool fCheckBind, const Consensus::Params& params);

/**
 * Block collection
 */
typedef std::vector< std::reference_wrapper<const CBlockIndex> > CBlockList;

/**
 * Get blocks by eval window
 *
 * @param nHeight           The height of net capacity
 * @param fAscent           Ascent or Descent sort blocks
 * @param params            Consensus params
 */
CBlockList GetEvalBlocks(int nHeight, bool fAscent, const Consensus::Params& params);

/**
 * Eval pledge ratio by capacity
 *
 * @param nHeight           The height of net capacity
 * @param nNetCapacityTB    Network capacity of TB
 * @param params            Consensus params
 */
CAmount EvalPledgeRatio(int nHeight, int64_t nNetCapacityTB, const Consensus::Params& params);

/**
 * Get net capacity
 *
 * @param nHeight           The height of net capacity
 * @param params            Consensus params
 *
 * @return Return net capacity of TB
 */
int64_t GetNetCapacity(int nHeight, const Consensus::Params& params);

/**
 * Get net capacity
 *
 * @param nHeight           The height of net capacity
 * @param params            Consensus params
 * @param associateBlock    Associate block callback
 *
 * @return Return net capacity of TB
 */
int64_t GetNetCapacity(int nHeight, const Consensus::Params& params, std::function<void(const CBlockIndex &block)> associateBlock);

/**
 * Get pledge ratio
 *
 * @param nHeight           The height of pledge ratio
 * @param params            Consensus params
 *
 * @return Return pledge ratio
 */
CAmount GetPledgeRatio(int nHeight, const Consensus::Params& params);

/**
 * Get capacity pledge amount
 *
 * @param nCapacityTB       Miner capacity
 * @param pledgeRatio       The pledge ratio
 *
 * @return Return pledge amount
 */
CAmount GetCapacityPledgeAmount(int64_t nCapacityTB, CAmount pledgeRatio);

/**
 * Get mining pledge amount for miner
 *
 * @param minerAccountID            Miner address digit ID
 * @param nPlotterId                Proof of capacity ID
 * @param nMiningHeight             The height of mining
 * @param view                      The coin view
 * @param pMinerCapacityTB          Miner capacity by estimate
 * @param pOldMinerPledge           Only in BHDIP004. See https://btchd.org/wiki/BHDIP/004#getminerpledge
 * @param params                    Consensus params
 *
 * @return Mining pledge amount for miner
 */
CAmount GetMiningPledgeAmount(const CAccountID& minerAccountID, const uint64_t& nPlotterId, int nMiningHeight,
    const CCoinsViewCache& view, int64_t* pMinerCapacityTB, CAmount* pOldMinerPledge,
    const Consensus::Params& params);

/**
 * Check block work
 *
 * @param prevBlockIndex    Previous block
 * @param block             Block header
 * @param params            Consensus params
 *
 * @return Return true is poc valid
 */
bool CheckProofOfCapacity(const CBlockIndex& prevBlockIndex, const CBlockHeader& block, const Consensus::Params& params);

/**
 * Add private key for mining signature
 *
 * @param privkey       Private key for signing
 * @param newAddress    Private key related P2WSH address
 *
 * @return Return false on private key invalid
 */
bool AddMiningSignaturePrivkey(const std::string& privkey, std::string* newAddress = nullptr);

/**
 * Get mining signature addresses
 *
 * @return Imported signature key related P2WSH addresses
 */
std::vector<std::string> GetMiningSignatureAddresses();

}

bool StartPOC();
void InterruptPOC();
void StopPOC();

#endif
