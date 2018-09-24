// Copyright (c) 2017-2018 The BitcoinHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <poc/poc.h>
#include <base58.h>
#include <chainparams.h>
#include <compat/endian.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <crypto/curve25519.h>
#include <crypto/shabal256.h>
#include <crypto/sha256.h>
#include <event2/thread.h>
#include <miner.h>
#include <ui_interface.h>
#include <util.h>
#include <utiltime.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <timedata.h>
#include <threadinterrupt.h>

#include <inttypes.h>

#include <limits>
#include <string>
#include <unordered_map>

namespace {

// shabal256
uint256 shabal256(const uint256 &genSig, int64_t nMix64)
{
    uint256 result;
    CShabal256()
        .Write((const unsigned char*)genSig.begin(), genSig.size())
        .Write((const unsigned char*)&nMix64, sizeof(nMix64))
        .Finalize((unsigned char*)result.begin());
    return result;
}

std::shared_ptr<CBlock> CreateBlock(CBlockIndex &prevBlockIndex, const uint64_t &nNonce, const uint64_t &nPlotterId, const uint64_t &nDeadline, const std::string &address)
{
    AssertLockHeld(cs_main);
    if (::vpwallets.empty()) {
        return nullptr;
    }

    CScript scriptPubKey;
    if (address.empty()) {
        // From wallet
        CWallet * const pwallet = ::vpwallets[0];

        std::shared_ptr<CReserveScript> coinbaseScript;
        pwallet->GetScriptForMining(coinbaseScript);
        if (!coinbaseScript) {
            LogPrintf("Cannot load script from wallet\n");
            return nullptr;
        }
        scriptPubKey = coinbaseScript->reserveScript;
    } else {
        // From address
        CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest)) {
            LogPrintf("Invalidate BitcoinHD address: %s\n", address);
            return nullptr;
        }
        scriptPubKey = GetScriptForDestination(dest);
    }
    if (scriptPubKey.empty()) {
        return nullptr;
    }

    std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(scriptPubKey, true, nNonce, nPlotterId, nDeadline));
    if (!pblocktemplate.get()) 
        return nullptr;

    CBlock *pblock = &pblocktemplate->block;

    unsigned int nHeight = prevBlockIndex.nHeight + 1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(static_cast<int64_t>(nNonce)) << CScriptNum(static_cast<int64_t>(nPlotterId))) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    return std::make_shared<CBlock>(*pblock);
}

// Generator
struct GeneratorState {
    uint64_t nonce;
    uint64_t plotterId;
    uint64_t deadline;
    uint64_t bestBlockDeadline; // Current best block deadline
    int64_t bestBlockTime; // Current best block time
    std::string address; // Generate to

    GeneratorState() : deadline(poc::INVALID_DEADLINE), bestBlockDeadline(poc::INVALID_DEADLINE), bestBlockTime(0) { }
};
typedef std::unordered_map<int, GeneratorState> Generators; // height -> GeneratorState
Generators mapGenerators;

CThreadInterrupt interruptCheckDeadline;
std::thread threadCheckDeadline;
void CheckDeadlineThread()
{
    RenameThread("bitcoin-checkdeadline");
    while (!interruptCheckDeadline) {
        if (!interruptCheckDeadline.sleep_for(std::chrono::milliseconds(500)))
            return;
        
        std::shared_ptr<CBlock> pblock;
        uint64_t deadline = 0;
        int height = 0;
        {
            LOCK(cs_main);
            if (!mapGenerators.empty()) {
                CBlockIndex *pindexTip = chainActive.Tip();
                int64_t nCurrentTime = std::max(pindexTip->GetMedianTimePast() + 1, GetAdjustedTime());
                auto it = mapGenerators.begin();
                while (it != mapGenerators.end() && !pblock) {
                    if (pindexTip->nHeight + 1 == it->first) {
                        // Current height
                        if (nCurrentTime > (int64_t)pindexTip->nTime + (int64_t)it->second.deadline || it->second.deadline == 50) {
                            // forge
                            LogPrint(BCLog::POC, "Generate block: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                it->first, it->second.nonce, it->second.plotterId, it->second.deadline);
                            pblock = CreateBlock(*pindexTip, it->second.nonce, it->second.plotterId, it->second.deadline, it->second.address);
                            if (!pblock) {
                                LogPrintf("Generate block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                    it->first, it->second.nonce, it->second.plotterId, it->second.deadline);
                            } else {
                                height = it->first;
                                deadline = it->second.deadline;
                            }
                        } else {
                            // Continue wait forge time
                            ++it;
                            continue;
                        }
                    } else if (pindexTip->nHeight == it->first) {
                        // Process future post block (MAX_FUTURE_BLOCK_TIME). My deadline is best(highest chainwork). Try snatch block
                        assert(pindexTip->pprev != nullptr);
                        if (it->second.bestBlockDeadline == poc::INVALID_DEADLINE || it->second.bestBlockTime != pindexTip->GetBlockTime()) {
                            it->second.bestBlockDeadline = poc::CalculateDeadline(*(pindexTip->pprev), pindexTip->GetBlockHeader(), Params().GetConsensus());
                            it->second.bestBlockTime = pindexTip->GetBlockTime();
                        }
                        if (it->second.deadline < it->second.bestBlockDeadline) {
                            // My deadline is best.
                            if (nCurrentTime > (int64_t)pindexTip->pprev->nTime + (int64_t)it->second.deadline) {
                                // Go forge
                                LogPrint(BCLog::POC, "Generate block(Snatch): height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 ", preDeadline=%" PRIu64 "\n",
                                    it->first, it->second.nonce, it->second.plotterId, it->second.deadline, it->second.bestBlockDeadline);
                                // Invalidate tip block
                                // TODO felix rewrite this logic
                                CValidationState state;
                                if (!InvalidateBlock(state, Params(), pindexTip)) {
                                    LogPrint(BCLog::POC, "Generate block(Snatch): invalidate current tip block error, %s\n", state.GetRejectReason());
                                    LogPrint(BCLog::POC, "Generate block(Snatch): current tip, %s\n", pindexTip->ToString());
                                } else {
                                    pblock = CreateBlock(*(pindexTip->pprev), it->second.nonce, it->second.plotterId, it->second.deadline, it->second.address);
                                    if (!pblock) {
                                        LogPrintf("Generate block fail(Snatch): height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 ", preDeadline=%" PRIu64 "\n",
                                            it->first, it->second.nonce, it->second.plotterId, it->second.deadline, it->second.bestBlockDeadline);
                                    } else {
                                        // Snatch block
                                        height = it->first;
                                        deadline = it->second.deadline;
                                    }
                                    ResetBlockFailureFlags(pindexTip);
                                }
                            } else {
                                // Continue wait forge time
                                ++it;
                                continue;
                            }
                        } else {
                            // Not better they, give up!
                            LogPrint(BCLog::POC, "Generate block(Snatch) give up: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline (mine=%" PRIu64 ") >= (tip=%" PRIu64 ")\n",
                                it->first, it->second.nonce, it->second.plotterId, it->second.deadline, it->second.bestBlockDeadline);
                        }
                    }

                    it = mapGenerators.erase(it);
                }
            }
        }

        // Broadcast
        if (pblock && !ProcessNewBlock(Params(), pblock, true, nullptr)) {
            LogPrintf("Process new block fail: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 ", deadline=%" PRIu64 "\n",
                height, pblock->nNonce, pblock->nPlotterId, deadline);
        }
    }
}

}

namespace poc {

uint64_t GetAccountIdByPassPhrase(const std::string &passPhrase)
{
    // rough high night desk familiar hop freely needle slowly threaten process flicker
    // 11529889285493050610ULL;
    // 
    // 1.k = sha256(passPhrase): 0xFE 0x71 0x11 0x6F
    // 2.publicKey = Curve25519(null,k): 0x1D 0x60 0x74 0xF4
    // 3.publicKeyHash = sha256(publicKey): 0xF2 0x4C 0x65 0x99
    // 4.id = int(publicKeyHash[0~7]): -6916854788216501006
    // 5.unsigned = 11529889285493050610
    uint8_t privateKey[CSHA256::OUTPUT_SIZE] = {0};
    uint8_t publicKey[CSHA256::OUTPUT_SIZE] = {0};
    uint8_t publicKeyHash[CSHA256::OUTPUT_SIZE] = {0};
    CSHA256().Write((const unsigned char*)passPhrase.data(), (size_t)passPhrase.length()).Finalize(privateKey);
    crypto::curve25519(publicKey, nullptr, (unsigned char*)privateKey);
    CSHA256().Write((const unsigned char*)publicKey, sizeof(publicKey)).Finalize(publicKeyHash);

    return ((uint64_t)publicKeyHash[0]) | \
        ((uint64_t)publicKeyHash[1]) << 8 | \
        ((uint64_t)publicKeyHash[2]) << 16 | \
        ((uint64_t)publicKeyHash[3]) << 24 | \
        ((uint64_t)publicKeyHash[4]) << 32 | \
        ((uint64_t)publicKeyHash[5]) << 40 | \
        ((uint64_t)publicKeyHash[6]) << 48 | \
        ((uint64_t)publicKeyHash[7]) << 56;
}

uint64_t parseAccountId(const std::string& account) 
{
    if (account.empty()) {
        return 0;
    }

    std::string accountUpper;
    std::transform(account.begin(), account.end(), back_inserter(accountUpper), ::toupper);

    if (accountUpper.substr(0, 6) == ("BURST-")) {
        return 0; //TODO Crypto.rsDecode(account.substring(6));
    }
    else {
        //parseUnsignedLong(account);
        return std::atoll(account.c_str());
    }
}

uint64_t GetBlockGenerator(const CBlockHeader &block)
{
    return block.nPlotterId;
}

std::string GetBlockGeneratorRS(const CBlockHeader &block)
{
    return std::to_string(GetBlockGenerator(block));
}

uint256 GetBlockGenerationSignature(const CBlockHeader &prevBlock)
{
    // 使用 hashMerkleRoot 和 nPlotterId 做签名
    uint256 result;
    CShabal256()
        .Write((const unsigned char*)prevBlock.hashMerkleRoot.begin(), prevBlock.hashMerkleRoot.size())
        .Write((const unsigned char*)&prevBlock.nPlotterId, sizeof(prevBlock.nPlotterId))
        .Finalize((unsigned char*)result.begin());
    return result;
}

uint64_t GetBlockId(const CBlockHeader &block)
{
    return block.GetHash().GetUint64(0);
}

uint64_t GetBlockId(const CBlockIndex &blockIndex)
{
    return GetBlockId(blockIndex.GetBlockHeader());
}

uint32_t GetBlockScoopNum(const uint256 &genSig, int nHeight)
{
    return UintToArith256(shabal256(genSig, htobe64(nHeight))) % 4096;
}

static constexpr int HASH_SIZE = 32;
static constexpr int HASHES_PER_SCOOP = 2;
static constexpr int SCOOP_SIZE = HASHES_PER_SCOOP * HASH_SIZE;
static constexpr int SCOOPS_PER_PLOT = 4096; // original 1MB/plot = 16384
static constexpr int PLOT_SIZE = SCOOPS_PER_PLOT * SCOOP_SIZE;

static const int HASH_CAP = 4096;

uint64_t CalculateDeadline(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params)
{
    if (prevBlockIndex.nHeight + 1 <= params.BtchdFundPreMingingHeight || params.fPocAllowMinDifficultyBlocks) {
        // Fund Or regtest
        return 0;
    }

    const uint256 genSig = poc::GetBlockGenerationSignature(prevBlockIndex.GetBlockHeader());
    const uint32_t scopeNum = poc::GetBlockScoopNum(genSig, prevBlockIndex.nHeight + 1);
    const uint64_t addr = htobe64(poc::GetBlockGenerator(block));
    const uint64_t nonce = htobe64(block.nNonce);

    std::unique_ptr<uint8_t> _gendata(new uint8_t[PLOT_SIZE + 16]);
    uint8_t *const gendata = _gendata.get();
    memcpy(gendata + PLOT_SIZE, (const unsigned char*)&addr, 8);
    memcpy(gendata + PLOT_SIZE + 8, (const unsigned char*)&nonce, 8);
    for (int i = PLOT_SIZE; i > 0; i -= HASH_SIZE) {
        int len = PLOT_SIZE + 16 - i;
        if (len > HASH_CAP) {
            len = HASH_CAP;
        }

        uint256 temp;
        CShabal256()
            .Write((const unsigned char*)gendata + i, len)
            .Finalize((unsigned char*)temp.begin());
        memcpy((uint8_t*)gendata + i - HASH_SIZE, (const uint8_t*)temp.begin(), HASH_SIZE);
    }
    uint256 base;
    CShabal256()
        .Write((const unsigned char*)gendata, PLOT_SIZE + 16)
        .Finalize((unsigned char*)base.begin());

    std::unique_ptr<uint8_t> _data(new uint8_t[PLOT_SIZE]);
    uint8_t *data = _data.get();
    for (int i = 0; i < PLOT_SIZE; i++) {
        data[i] = (uint8_t) (gendata[i] ^ (base.begin()[i % HASH_SIZE]));
    }
    _gendata.reset(nullptr);

    // PoC2 Rearrangement
    //
    // [0] [1] [2] [3] ... [N-1]
    // [1] <-> [N-1]
    // [3] <-> [N-3]
    // [5] <-> [N-5]
    uint8_t hashBuffer[HASH_SIZE];
    for (int pos = 32, revPos = PLOT_SIZE - HASH_SIZE; pos < (PLOT_SIZE / 2); pos += 64, revPos -= 64) {
        memcpy(hashBuffer, data + pos, HASH_SIZE); // Copy low scoop second hash to buffer
        memcpy(data + pos, data + revPos, HASH_SIZE); // Copy high scoop second hash to low scoop second hash
        memcpy(data + revPos, hashBuffer, HASH_SIZE); // Copy buffer to high scoop second hash
    }

    CShabal256()
        .Write((const unsigned char*)genSig.begin(), genSig.size())
        .Write((const unsigned char*)data + scopeNum * SCOOP_SIZE, SCOOP_SIZE)
        .Finalize((unsigned char*)base.begin());

    return base.GetUint64(0) / prevBlockIndex.nBaseTarget;
}

uint64_t CalculateBaseTarget(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params)
{
    int nHeight = prevBlockIndex.nHeight + 1;
    if (nHeight <= params.BtchdFundPreMingingHeight) {
        // genesis block & god mode block
        return INITIAL_BASE_TARGET;
    } else if (nHeight < params.BtchdFundPreMingingHeight + 4) {
        return INITIAL_BASE_TARGET;
    } else if (nHeight < params.BtchdFundPreMingingHeight + 2700) {
        // [N-1,N-2,N-3,N-4]
        uint64_t avgBaseTarget = prevBlockIndex.nBaseTarget;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        for (int i = nHeight - 2; i >= nHeight - 4; i--) {
            pLastindex = pLastindex->pprev;
            if (pLastindex == nullptr) {
                break;
            }
            avgBaseTarget += pLastindex->nBaseTarget;
        }
        avgBaseTarget /= 4;
        assert(pLastindex != nullptr);

        uint64_t curBaseTarget = avgBaseTarget;
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();

        uint64_t newBaseTarget = (curBaseTarget * diffTime) / (params.nPowTargetSpacing * 4); // 5m * 4blocks
        if (newBaseTarget > MAX_BASE_TARGET) {
            newBaseTarget = MAX_BASE_TARGET;
        }
        if (newBaseTarget < (curBaseTarget * 9 / 10)) {
            newBaseTarget = curBaseTarget * 9 / 10;
        }

        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }

        if (newBaseTarget > (curBaseTarget * 11 / 10)) {
            newBaseTarget = curBaseTarget * 11 / 10;
        }

        return newBaseTarget;
    } else {
        // [N-1,N-2,N-3,...,N-25]
        uint64_t avgBaseTarget = prevBlockIndex.nBaseTarget;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        for (int i = nHeight - 2, blockCounter = 1; i >= nHeight - 25; i--,blockCounter++) {
            pLastindex = pLastindex->pprev;
            if (pLastindex == nullptr) {
                break;
            }
            avgBaseTarget = (avgBaseTarget * blockCounter + pLastindex->nBaseTarget) / (blockCounter + 1);
        }
        assert(pLastindex != nullptr);
        
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        int64_t targetTimespan = params.nPowTargetSpacing * 24; // 5m * 24blocks

        if (diffTime < targetTimespan / 2) {
            diffTime = targetTimespan / 2;
        }

        if (diffTime > targetTimespan * 2) {
            diffTime = targetTimespan * 2;
        }

        uint64_t curBaseTarget = prevBlockIndex.nBaseTarget;
        uint64_t newBaseTarget = avgBaseTarget * diffTime / targetTimespan;

        if (newBaseTarget > MAX_BASE_TARGET) {
            newBaseTarget = MAX_BASE_TARGET;
        }

        if (newBaseTarget == 0) {
            newBaseTarget = 1;
        }

        if (newBaseTarget < curBaseTarget * 8 / 10) {
            newBaseTarget = curBaseTarget * 8 / 10;
        }

        if (newBaseTarget > curBaseTarget * 12 / 10) {
            newBaseTarget = curBaseTarget * 12 / 10;
        }

        return newBaseTarget;
    }
}

bool VerifyGenerationSignature(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, bool bForceCheckDeadline, const Consensus::Params& params)
{
    // Optional check deadline.
    // If block forge time interval more than 30 minute, then force check block deadline.
    if (!bForceCheckDeadline && block.nTime < prevBlockIndex.nTime + 30 * 60) {
        return true;
    }

    // TODO felix repeated verify, remove it.
    // Check base target
    if (block.nBaseTarget != CalculateBaseTarget(prevBlockIndex, block, params)) {
        return false;
    }

    // Dont verify last checkpoint before deadline
    if (!Params().Checkpoints().mapCheckpoints.empty() && Params().Checkpoints().mapCheckpoints.rbegin()->first > prevBlockIndex.nHeight) {
        return true;
    }

    // Check deadline
    uint64_t deadline = CalculateDeadline(prevBlockIndex, block, params);
    return deadline <= MAX_TARGET_DEADLINE && (deadline == 0 || block.nTime > prevBlockIndex.nTime + deadline);
}

uint64_t AddNonce(uint64_t &bestDeadline, const CBlockIndex &prevBlockIndex, const uint64_t &nNonce, const uint64_t &nPlotterId, const std::string &address, const Consensus::Params& params)
{
    LogPrint(BCLog::POC, "Add nonce: height=%d, nonce=%" PRIu64 ", plotterId=%" PRIu64 "\n",
        prevBlockIndex.nHeight + 1, nNonce, nPlotterId);

    CBlockHeader block;
    block.nVersion   = ComputeBlockVersion(&prevBlockIndex, params);
    block.nNonce     = nNonce;
    block.nPlotterId = nPlotterId;

    uint64_t calcDeadline = CalculateDeadline(prevBlockIndex, block, params);
    if (calcDeadline > MAX_TARGET_DEADLINE) {
        LogPrint(BCLog::POC, "Cann't accept deadline %5.1fday, more than %" PRIu64 "day.\n",
            calcDeadline / (24 * 60 * 60 * 1.0f), MAX_TARGET_DEADLINE / (24 * 60 * 60));

        auto it = mapGenerators.find(prevBlockIndex.nHeight + 1);
        if (it != mapGenerators.end()) {
            bestDeadline = it->second.deadline;
        } else {
            bestDeadline = 0;
        }
    } else {
        GeneratorState &generator = mapGenerators[prevBlockIndex.nHeight + 1];
        if (generator.deadline == INVALID_DEADLINE || calcDeadline < generator.deadline) {
            generator.nonce     = nNonce;
            generator.plotterId = nPlotterId;
            generator.deadline  = calcDeadline;
            generator.address   = address;

            uiInterface.NotifyBestDeadlineChanged(prevBlockIndex.nHeight + 1, nNonce, nPlotterId, calcDeadline);
        }

        bestDeadline = generator.deadline;
    }

    return calcDeadline;
}

int64_t GetForgeEscape()
{
    LOCK(cs_main);
    auto it = mapGenerators.cbegin();
    if (it == mapGenerators.cend()) {
        return -1;
    } else {
        const CBlockIndex *pindexTip = chainActive.Tip();
        int64_t nTime = std::max(pindexTip->GetMedianTimePast() + 1, GetAdjustedTime());
        int64_t nEscapeTime = (int64_t)pindexTip->nTime + (int64_t)it->second.deadline - nTime;
        if (nEscapeTime < 0) {
            nEscapeTime = 0;
        }
        return nEscapeTime;
    }
}

}

bool StartPOC()
{
    LogPrintf("Starting PoC module\n");
    interruptCheckDeadline.reset();
    threadCheckDeadline = std::thread(CheckDeadlineThread);
    return true;
}

void InterruptPOC()
{
    LogPrintf("Interrupting PoC module\n");
    interruptCheckDeadline();
}

void StopPOC()
{
    if (threadCheckDeadline.joinable())
        threadCheckDeadline.join();

    LogPrintf("Stopped PoC module\n");
}