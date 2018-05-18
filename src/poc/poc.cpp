// Copyright (c) 2018 bitconore.org

#include <poc/poc.h>
#include <chainparams.h>
#include <compat/endian.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
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

namespace {

// Millis: 2014-08-11 02:00:00.0
//const static int64_t EPOCH_BEGINNING = 1407722400000LL;

// Millis: 2018-01-25 00:00:00.0
const static int64_t EPOCH_BEGINNING = 1516809600000LL;

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

static const int HASH_SIZE = 32;
static const int HASHES_PER_SCOOP = 2;
static const int SCOOP_SIZE = HASHES_PER_SCOOP * HASH_SIZE;
static const int SCOOPS_PER_PLOT = 4096; // original 1MB/plot = 16384
static const int PLOT_SIZE = SCOOPS_PER_PLOT * SCOOP_SIZE;

static const int HASH_CAP = 4096;

uint64_t CalculateDeadline(const CBlockIndex &prevBlockIndex, const CBlockHeader &block)
{
    if (prevBlockIndex.nHeight + 1 <= Params().GetConsensus().BCOHeight + Params().GetConsensus().BCOInitBlockCount) {
        // genesis block & god mode block
        return 0;
    }

    if (Params().GetConsensus().fPowAllowMinDifficultyBlocks) {
        // test
        return 1;
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

    uint8_t data[PLOT_SIZE];
    for (int i = 0; i < PLOT_SIZE; i++) {
        data[i] = (uint8_t) (gendata[i] ^ (base.begin()[i % HASH_SIZE]));
    }
    _gendata.reset(nullptr);

    CShabal256()
        .Write((const unsigned char*)genSig.begin(), genSig.size())
        .Write((const unsigned char*)data + scopeNum * SCOOP_SIZE, SCOOP_SIZE)
        .Finalize((unsigned char*)base.begin());

    return base.GetUint64(0) / prevBlockIndex.nBits;
}

std::shared_ptr<CBlock> CreateBlock(const CBlockIndex &prevBlockIndex,
    const uint64_t &nNonce, const uint64_t &nAccountId)
{
    AssertLockHeld(cs_main);
    if (::vpwallets.empty()) {
        return nullptr;
    }

    CWallet * const pwallet = ::vpwallets[0];

    std::shared_ptr<CReserveScript> coinbaseScript;
    pwallet->GetScriptForMining(coinbaseScript);

    if (!coinbaseScript) {
        return nullptr;
    }

    if (coinbaseScript->reserveScript.empty()) {
        return nullptr;
    }

    std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript));
    if (!pblocktemplate.get()) 
        return nullptr;

    CBlock *pblock = &pblocktemplate->block;

    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << (prevBlockIndex.nHeight + 1) << CScriptNum(static_cast<int64_t>(nNonce))) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    pblock->nNonce = nNonce;
    pblock->nPlotSeed = nAccountId;

    return std::make_shared<CBlock>(*pblock);
}

// Check
static int32_t      gNextBlockHeight = 0;
static uint64_t     gNextBlockNonce = 0;
static uint64_t     gNextBlockSeed = 0;
static uint64_t     gNextBlockDeadline = 0;

CThreadInterrupt interruptCheckDeadline;
std::thread threadCheckDeadline;
void CheckDeadlineThread()
{
    RenameThread("bitcoin-checkdeadline");
    LogPrintf("Entering check deadline loop\n");
    while (!interruptCheckDeadline) {
        if (!interruptCheckDeadline.sleep_for(std::chrono::milliseconds(1000)))
            return;
        
        std::shared_ptr<CBlock> pblock;
        {
            LOCK(cs_main);
            if (gNextBlockHeight != 0) {
                const CBlockIndex *pindexTip = chainActive.Tip();
                if (pindexTip->nHeight + 1 == gNextBlockHeight) {
                    int64_t nTime = std::max(pindexTip->GetMedianTimePast()+1, GetAdjustedTime());
                    if (nTime > (int64_t)pindexTip->nTime + (int64_t)gNextBlockDeadline) {
                        // forge
                        LogPrint(BCLog::POC, "Generate block: height=%d, nonce=%" PRIu64 ", seed=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                gNextBlockHeight, gNextBlockNonce, gNextBlockSeed, gNextBlockDeadline);
                        pblock = CreateBlock(*pindexTip, gNextBlockNonce, gNextBlockSeed);
                        if (!pblock) {
                            LogPrintf("Generate block fail: height=%d, nonce=%" PRIu64 ", seed=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                gNextBlockHeight, gNextBlockNonce, gNextBlockSeed, gNextBlockDeadline);
                        }
                   } else {
                       // wait
                       LogPrint(BCLog::POC, "Wait deadline: dst=%" PRIu64 ", tip=%" PRIu64 ", deadline=%" PRIu64 "\n",
                                nTime, (int64_t)pindexTip->nTime, gNextBlockDeadline);
                       continue;
                   }
                }
            }
        }

        // ProcessNewBlock
        if (pblock && !ProcessNewBlock(Params(), pblock, true, nullptr)) {
            LogPrintf("Process new block fail: height=%d, nonce=%" PRIu64 ", seed=%" PRIu64 ", deadline=%" PRIu64 "\n",
                gNextBlockHeight, gNextBlockNonce, gNextBlockSeed, gNextBlockDeadline);
        }
        
        // clear
        {
            LOCK(cs_main);
            if (gNextBlockHeight != 0) {
                LogPrint(BCLog::POC, "Clear check deadline data");
                gNextBlockHeight = 0;
                gNextBlockNonce = 0;
                gNextBlockSeed = 0;
                gNextBlockDeadline = 0;
            }
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

uint64_t GetBlockGenerator(const CBlockHeader &block)
{
    return block.nPlotSeed;
}

std::string GetBlockGeneratorRS(const CBlockHeader &block)
{
    return std::to_string(GetBlockGenerator(block));
}

uint256 GetBlockGenerationSignature(const CBlockHeader &prevBlock)
{
    // 使用hashMerkleRoot和nPlotSeed做签名
    uint256 result;
    CShabal256()
        .Write((const unsigned char*)prevBlock.hashMerkleRoot.begin(), prevBlock.hashMerkleRoot.size())
        .Write((const unsigned char*)&prevBlock.nPlotSeed, sizeof(prevBlock.nPlotSeed))
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

uint64_t CalculateBaseTarget(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, const Consensus::Params& params)
{
    assert(prevBlockIndex.nHeight + 1 >= params.BCOHeight);
    int nPocGenesisBlockHeight = params.BCOHeight + params.BCOInitBlockCount;
    int nHeight = prevBlockIndex.nHeight + 1;
    if (nHeight <= nPocGenesisBlockHeight) {
        // genesis block & god mode block
        return INITIAL_BASE_TARGET;
    } else if (nHeight < nPocGenesisBlockHeight + 4) {
        // < 4
        return INITIAL_BASE_TARGET;
    } else if (nHeight < nPocGenesisBlockHeight + 2700) {
        // < 2700
        // [N-1,N-2,N-3,N-4]
        uint64_t avgBaseTarget = prevBlockIndex.nBits;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        for (int i = nHeight - 2; i >= nHeight - 4; i--) {
            pLastindex = pLastindex->pprev;
            if (pLastindex == nullptr) {
                break;
            }
            avgBaseTarget += pLastindex->nBits;
        }
        avgBaseTarget /= 4;
        assert(pLastindex != nullptr);

        uint64_t curBaseTarget = avgBaseTarget;
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();

        uint64_t newBaseTarget = (curBaseTarget * diffTime) / (params.nPowTargetSpacing / 2 * 4); // 5m * 4blocks
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
        uint64_t avgBaseTarget = prevBlockIndex.nBits;
        const CBlockIndex *pLastindex = &prevBlockIndex;
        for (int i = nHeight - 2, blockCounter = 1; i >= nHeight - 25; i--,blockCounter++) {
            pLastindex = pLastindex->pprev;
            if (pLastindex == nullptr) {
                break;
            }
            avgBaseTarget = (avgBaseTarget * blockCounter + pLastindex->nBits) / (blockCounter + 1);
        }
        assert(pLastindex != nullptr);
        
        int64_t diffTime = block.GetBlockTime() - pLastindex->GetBlockTime();
        int64_t targetTimespan = params.nPowTargetSpacing / 2 * 24; // 5m * 24blocks

        if (diffTime < targetTimespan / 2) {
            diffTime = targetTimespan / 2;
        }

        if (diffTime > targetTimespan * 2) {
            diffTime = targetTimespan * 2;
        }

        uint64_t curBaseTarget = prevBlockIndex.nBits;
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

bool VerifyGenerationSignature(const CBlockIndex &prevBlockIndex, const CBlockHeader &block, 
    bool bForceCheckDeadline, const Consensus::Params& params)
{
    if (block.GetBlockTime() < BCO_BLOCK_UNIXTIME_MIN ||
        block.nBits != CalculateBaseTarget(prevBlockIndex, block, params)) {
        return false;
    }

    if (prevBlockIndex.nHeight + 1 < Params().GetConsensus().BCOHeight + Params().GetConsensus().BCOInitBlockCount) {
        // God Mode
        return true;
    }

    // Optional check deadline. 
    // If block forge time interval more than 30 minute, then force check block deadline.
    if (!bForceCheckDeadline && block.nTime < prevBlockIndex.nTime + 30 * 60) {
        return true;
    }

    // Check deadline
    uint64_t deadline = CalculateDeadline(prevBlockIndex, block);
    return deadline <= 30 * 24 * 60 * 60 && block.nTime > prevBlockIndex.nTime + deadline;
}

bool TryGenerateBlock(const CBlockIndex &prevBlockIndex,
    const uint64_t &nNonce, const uint64_t &nAccountId, 
    uint64_t &deadline)
{
    LogPrint(BCLog::POC, "Try generate block: height=%d, nonce=%" PRIu64 ", account=%" PRIu64 "\n",
        prevBlockIndex.nHeight + 1, nNonce, nAccountId);

    CBlockHeader block;
    block.nVersion = ComputeBlockVersion(&prevBlockIndex, Params().GetConsensus());
    block.nNonce = nNonce;
    block.nPlotSeed = nAccountId;

    uint64_t calcDeadline = CalculateDeadline(prevBlockIndex, block);
    if (calcDeadline > 30 * 24 * 60 * 60) {
        LogPrint(BCLog::POC, "Try generate block: height=%d, nonce=%" PRIu64 ", account=%" PRIu64 ". Cann't accept deadline %5.1fday, more than 30day.\n",
            prevBlockIndex.nHeight + 1, nNonce, nAccountId, calcDeadline / (30 * 24 * 60 * 60 * 1.0f));
        return false;
    }

    deadline = calcDeadline;
    if (gNextBlockHeight != prevBlockIndex.nHeight + 1 
        || nAccountId != gNextBlockSeed 
        || deadline < gNextBlockDeadline) {
        gNextBlockHeight = prevBlockIndex.nHeight + 1;
        gNextBlockNonce = nNonce;
        gNextBlockSeed = nAccountId;
        gNextBlockDeadline = deadline;

        uiInterface.NotifyBcoDeadlineChanged(gNextBlockHeight, gNextBlockNonce, gNextBlockSeed, gNextBlockDeadline);
    }
    return true;
}

int64_t GetEpochTime()
{
    return GetAdjustedTime() - (EPOCH_BEGINNING + 500)/1000;
}

int64_t GetForgeEscape()
{
    if (gNextBlockDeadline == 0) {
        return -1;
    } else {
        LOCK(cs_main);
        const CBlockIndex *pindexTip = chainActive.Tip();
        int64_t nTime = std::max(pindexTip->GetMedianTimePast()+1, GetAdjustedTime());
        int64_t escape = (int64_t)pindexTip->nTime + (int64_t)gNextBlockDeadline - nTime;
        if (escape < 0) {
            escape = 0;
        }
        return escape;
    }
}

}

bool StartPOC()
{
    LogPrintf("Starting POC\n");
    threadCheckDeadline = std::thread(CheckDeadlineThread);
    interruptCheckDeadline.reset();
    return true;
}

void InterruptPOC()
{
    LogPrintf("Interrupting POC\n");
    // Interrupt e.g. running longpolls
    interruptCheckDeadline();
}

void StopPOC()
{
    LogPrintf("Stopping POC\n");
    if (threadCheckDeadline.joinable())
        threadCheckDeadline.join();
}