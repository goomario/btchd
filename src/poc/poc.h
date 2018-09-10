// Copyright (c) 2017-2018 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POC_POC_H
#define BITCOIN_POC_POC_H

#include <script/script.h>

#include <arith_uint256.h>
#include <uint256.h>
#include <stdlib.h>
#include <stdint.h>

class CBlockHeader;
class CBlock;
class CBlockIndex;

namespace Consensus { struct Params; }

namespace poc {

/** 2^64, 0x10000000000000000*/
static const arith_uint256 TWO64 = arith_uint256(std::numeric_limits<uint64_t>::max()) + 1;

/** Initial base target */
static const uint64_t INITIAL_BASE_TARGET = 18325193796L; // 0x0000000444444444

/** Max target */
static const uint64_t MAX_BASE_TARGET = 18325193796L; // 0x0000000444444444

// Max target deadline
static const int64_t MAX_TARGET_DEADLINE = 365 * 24 * 60 * 60;

// Invalid deadline
static const uint64_t INVALID_DEADLINE = std::numeric_limits<uint64_t>::max();

uint64_t GetAccountIdByPassPhrase(const std::string &passPhrase);
uint64_t parseAccountId(const std::string& account);

/**
 * Get account Id
 */
uint64_t GetBlockGenerator(const CBlockHeader &block);
std::string GetBlockGeneratorRS(const CBlockHeader &block);

/**
 * Get generation signature
 * Next block generation signature
 */
uint256 GetBlockGenerationSignature(const CBlockHeader &prevBlock);

/**
 * Get block Id
 */
uint64_t GetBlockId(const CBlockHeader &block);
uint64_t GetBlockId(const CBlockIndex &blockIndex);

uint32_t GetBlockScoopNum(const uint256 &genSig, int nHeight);

/** Calculate deadline */
uint64_t CalculateDeadline(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params);

/** Calculate base target */
uint64_t CalculateBaseTarget(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params);

/** Verify generation singnature */
bool VerifyGenerationSignature(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, bool bForceCheckDeadline, const Consensus::Params& params);

/** Add new nonce */
uint64_t AddNonce(uint64_t &bestDeadline, const CBlockIndex &prevBlockIndex, const uint64_t &nNonce, const uint64_t &nPlotterId, const std::string &address, const Consensus::Params& params);

/** Get forge escape second time */
int64_t GetForgeEscape();

}

bool StartPOC();
void InterruptPOC();
void StopPOC();

#endif
