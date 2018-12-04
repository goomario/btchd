// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <chainparams.h>
#include <fs.h>
#include <hash.h>
#include <init.h>
#include <memusage.h>
#include <random.h>
#include <uint256.h>
#include <util.h>
#include <ui_interface.h>
#include <validation.h>

#include <exception>
#include <map>
#include <unordered_map>

#include <stdint.h>
#include <inttypes.h>

#include <boost/thread.hpp>

static const char DB_COIN = 'C';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_HEAD_BLOCKS = 'H';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

static const char DB_ACCOUNT_BALANCE = 'T';
static const char DB_COIN_RENTCREDIT = 'E';
static const char DB_COIN_RENTDEBIT = 'e';

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    char key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct AccountCoinRefEntry {
    CAccountID* accountID;
    COutPoint* outpoint;
    char key;
    AccountCoinRefEntry(const CAccountID* ptr1, const COutPoint* ptr2) : accountID(const_cast<CAccountID*>(ptr1)), outpoint(const_cast<COutPoint*>(ptr2)), key(DB_ACCOUNT_BALANCE) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(*accountID);
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(*accountID);
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct AccountCoinRWEntry {
    CAccountID accountID;
    COutPoint outpoint;
    char key;
    AccountCoinRWEntry(const CAccountID &accountIdIn, const COutPoint &outpointIn) : accountID(accountIdIn), outpoint(outpointIn), key(DB_ACCOUNT_BALANCE) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(accountID);
        s << outpoint.hash;
        s << VARINT(outpoint.n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(accountID);
        s >> outpoint.hash;
        s >> VARINT(outpoint.n);
    }
};

struct AccountCoinRentCreditRefEntry {
    CAccountID* accountID;
    COutPoint* outpoint;
    char key;
    AccountCoinRentCreditRefEntry(const CAccountID* ptr1, const COutPoint* ptr2) : accountID(const_cast<CAccountID*>(ptr1)), outpoint(const_cast<COutPoint*>(ptr2)), key(DB_COIN_RENTCREDIT) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(*accountID);
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(*accountID);
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct AccountCoinRentCreditRWEntry {
    CAccountID accountID;
    COutPoint outpoint;
    char key;
    AccountCoinRentCreditRWEntry(const CAccountID &accountIDIn, const COutPoint &outpointIn) : accountID(accountIDIn), outpoint(outpointIn), key(DB_COIN_RENTCREDIT) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(accountID);
        s << outpoint.hash;
        s << VARINT(outpoint.n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(accountID);
        s >> outpoint.hash;
        s >> VARINT(outpoint.n);
    }
};

struct AccountCoinRentDebitRefEntry {
    CAccountID* accountID;
    COutPoint* outpoint;
    char key;
    AccountCoinRentDebitRefEntry(const CAccountID* ptr1, const COutPoint* ptr2) : accountID(const_cast<CAccountID*>(ptr1)), outpoint(const_cast<COutPoint*>(ptr2)), key(DB_COIN_RENTDEBIT) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(*accountID);
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(*accountID);
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct AccountCoinRentDebitRWEntry {
    CAccountID accountID;
    COutPoint outpoint;
    char key;
    AccountCoinRentDebitRWEntry(const CAccountID &accountIDIn, const COutPoint &outpointIn) : accountID(accountIDIn), outpoint(outpointIn), key(DB_COIN_RENTDEBIT) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(accountID);
        s << outpoint.hash;
        s << VARINT(outpoint.n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(accountID);
        s >> outpoint.hash;
        s >> VARINT(outpoint.n);
    }
};

}


CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, true) { }

bool CCoinsViewDB::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    return db.Read(CoinEntry(&outpoint), coin);
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return db.Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!db.Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) {
    CDBBatch batch(db);
    size_t count = 0;
    size_t changed = 0;
    size_t batch_size = (size_t)gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
    int crash_simulate = gArgs.GetArg("-dbcrashratio", 0);
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, std::vector<uint256>{hashBlock, old_tip});

    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            if (it->second.coin.IsSpent()) {
                batch.Erase(CoinEntry(&it->first));
                if (it->second.coin.refOut.accountID != 0)
                    batch.Erase(AccountCoinRefEntry(&it->second.coin.refOut.accountID, &it->first));
                // Rent
                if (it->second.coin.extraData.protocolId == OPRETURN_PROTOCOLID_RENT) {
                    batch.Erase(AccountCoinRentCreditRefEntry(&it->second.coin.refOut.accountID, &it->first));
                    batch.Erase(AccountCoinRentDebitRefEntry(&it->second.coin.extraData.debitAccountID, &it->first));
                }
            } else {
                batch.Write(CoinEntry(&it->first), it->second.coin);
                if (it->second.coin.refOut.accountID != 0)
                    batch.Write(AccountCoinRefEntry(&it->second.coin.refOut.accountID, &it->first), VARINT(it->second.coin.out.nValue));
                // Rent
                if (it->second.coin.extraData.protocolId == OPRETURN_PROTOCOLID_RENT) {
                    batch.Write(AccountCoinRentCreditRefEntry(&it->second.coin.refOut.accountID, &it->first), VARINT(it->second.coin.out.nValue));
                    batch.Write(AccountCoinRentDebitRefEntry(&it->second.coin.extraData.debitAccountID, &it->first), VARINT(it->second.coin.out.nValue));
                }
            }
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
        if (batch.SizeEstimate() > batch_size) {
            LogPrint(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
            db.WriteBatch(batch);
            batch.Clear();
            if (crash_simulate) {
                static FastRandomContext rng;
                if (rng.randrange(crash_simulate) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    LogPrint(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.SizeEstimate() * (1.0 / 1048576.0));
    bool ret = db.WriteBatch(batch);
    LogPrint(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;

}

size_t CCoinsViewDB::EstimateSize() const
{
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}

CAmount CCoinsViewDB::GetBalance(const CAccountID &accountID, const CCoinsMap &mapModifiedCoins,
        CAmount *pLockInBindIdBalance, CAmount *pLockInRentCreditBalance, CAmount *pRentDebitBalance) const {
    CAmount availableBalance = 0;
    if (pLockInBindIdBalance != nullptr) *pLockInBindIdBalance = 0;

    // Read from database
    {
        std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
        CAmount value;
        AccountCoinRWEntry entry(accountID, COutPoint(uint256(), 0));
        pcursor->Seek(entry);
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_ACCOUNT_BALANCE && entry.accountID == accountID) {
                if (pcursor->GetValue(VARINT(value)))
                    availableBalance += value;
            } else {
                break;
            }
            pcursor->Next();
        }
    }

    // Apply modified coin
    for (CCoinsMap::const_iterator it = mapModifiedCoins.cbegin(); it != mapModifiedCoins.cend(); it++) {
        if ((it->second.flags & CCoinsCacheEntry::DIRTY) && it->second.coin.refOut.accountID == accountID) {
            if (it->second.coin.IsSpent()) {
                if (db.Exists(CoinEntry(&it->first)))
                    availableBalance -= it->second.coin.refOut.value;
            } else {
                assert(it->second.coin.refOut.value == it->second.coin.out.nValue);
                if (!db.Exists(CoinEntry(&it->first)))
                    availableBalance += it->second.coin.refOut.value;
            }
        }
    }
    assert(availableBalance >= 0);

    // Rent credit
    if (pLockInRentCreditBalance != nullptr) {
        *pLockInRentCreditBalance = 0;

        // Read from database
        {
            std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
            CAmount value;
            AccountCoinRentCreditRWEntry entry(accountID, COutPoint(uint256(), 0));
            pcursor->Seek(entry);
            while (pcursor->Valid()) {
                if (pcursor->GetKey(entry) && entry.key == DB_COIN_RENTCREDIT && entry.accountID == accountID) {
                    if (pcursor->GetValue(VARINT(value)))
                        *pLockInRentCreditBalance += value;
                } else {
                    break;
                }
                pcursor->Next();
            }
        }

        // Apply modified coin
        for (CCoinsMap::const_iterator it = mapModifiedCoins.cbegin(); it != mapModifiedCoins.cend(); it++) {
            if ((it->second.flags & CCoinsCacheEntry::DIRTY) && it->second.coin.refOut.accountID == accountID && it->second.coin.extraData.protocolId == OPRETURN_PROTOCOLID_RENT) {
                if (it->second.coin.IsSpent()) {
                    if (db.Exists(CoinEntry(&it->first)))
                        *pLockInRentCreditBalance -= it->second.coin.refOut.value;
                } else {
                    assert(it->second.coin.refOut.value == it->second.coin.out.nValue);
                    if (!db.Exists(CoinEntry(&it->first)))
                        *pLockInRentCreditBalance += it->second.coin.refOut.value;
                }
            }
        }
        assert(*pLockInRentCreditBalance >= 0);
    }

    // Rent debit
    if (pRentDebitBalance != nullptr) {
        *pRentDebitBalance = 0;

        // Read from database
        {
            std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
            CAmount value;
            AccountCoinRentDebitRWEntry entry(accountID, COutPoint(uint256(), 0));
            pcursor->Seek(entry);
            while (pcursor->Valid()) {
                if (pcursor->GetKey(entry) && entry.key == DB_COIN_RENTDEBIT && entry.accountID == accountID) {
                    if (pcursor->GetValue(VARINT(value)))
                        *pRentDebitBalance += value;
                } else {
                    break;
                }
                pcursor->Next();
            }
        }

        // Apply modified coin
        for (CCoinsMap::const_iterator it = mapModifiedCoins.cbegin(); it != mapModifiedCoins.cend(); it++) {
            if ((it->second.flags & CCoinsCacheEntry::DIRTY) && it->second.coin.extraData.protocolId == OPRETURN_PROTOCOLID_RENT && it->second.coin.extraData.debitAccountID == accountID) {
                if (it->second.coin.IsSpent()) {
                    if (db.Exists(CoinEntry(&it->first)))
                        *pRentDebitBalance -= it->second.coin.refOut.value;
                } else {
                    assert(it->second.coin.refOut.value == it->second.coin.out.nValue);
                    if (!db.Exists(CoinEntry(&it->first)))
                        *pRentDebitBalance += it->second.coin.refOut.value;
                }
            }
        }
        assert(*pRentDebitBalance >= 0);
    }

    return availableBalance;
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe) {
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo &info) {
    return Read(std::make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing) {
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadReindexing(bool &fReindexing) {
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int &nFile) {
    return Read(DB_LAST_BLOCK, nFile);
}

CCoinsViewCursor *CCoinsViewDB::Cursor() const
{
    CCoinsViewDBCursor *i = new CCoinsViewDBCursor(const_cast<CDBWrapper&>(db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

unsigned int CCoinsViewDBCursor::GetValueSize() const
{
    return pcursor->GetValueSize();
}

bool CCoinsViewDBCursor::Valid() const
{
    return keyTmp.first == DB_COIN;
}

void CCoinsViewDBCursor::Next()
{
    pcursor->Next();
    CoinEntry entry(&keyTmp.second);
    if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
        keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
    } else {
        keyTmp.first = entry.key;
    }
}

bool CBlockTreeDB::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<int, const CBlockFileInfo*> >::const_iterator it=fileInfo.begin(); it != fileInfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_FILES, it->first), *it->second);
    }
    batch.Write(DB_LAST_BLOCK, nLastFile);
    for (std::vector<const CBlockIndex*>::const_iterator it=blockinfo.begin(); it != blockinfo.end(); it++) {
        batch.Write(std::make_pair(DB_BLOCK_INDEX, (*it)->GetBlockHash()), CDiskBlockIndex(*it));
    }
    return WriteBatch(batch, true);
}

bool CBlockTreeDB::ReadTxIndex(const uint256 &txid, CDiskTxPos &pos) {
    return Read(std::make_pair(DB_TXINDEX, txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >&vect) {
    CDBBatch batch(*this);
    for (std::vector<std::pair<uint256,CDiskTxPos> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(std::make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteFlag(const std::string &name, bool fValue) {
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string &name, bool &fValue) {
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&)> insertBlockIndex)
{
    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_BLOCK_INDEX, uint256()));

    // Load mapBlockIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_BLOCK_INDEX) {
            CDiskBlockIndex diskindex;
            if (pcursor->GetValue(diskindex)) {
                // Construct block index object
                CBlockIndex* pindexNew = insertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev           = insertBlockIndex(diskindex.hashPrev);
                pindexNew->nHeight         = diskindex.nHeight;
                pindexNew->nFile           = diskindex.nFile;
                pindexNew->nDataPos        = diskindex.nDataPos;
                pindexNew->nUndoPos        = diskindex.nUndoPos;
                pindexNew->nVersion        = diskindex.nVersion;
                pindexNew->hashMerkleRoot  = diskindex.hashMerkleRoot;
                pindexNew->nTime           = diskindex.nTime;
                pindexNew->nBaseTarget     = diskindex.nBaseTarget;
                pindexNew->nNonce          = diskindex.nNonce;
                pindexNew->nPlotterId      = diskindex.nPlotterId;
                pindexNew->nStatus         = diskindex.nStatus;
                pindexNew->nTx             = diskindex.nTx;
                pindexNew->minerAccountID  = diskindex.minerAccountID;

                pcursor->Next();
            } else {
                return error("%s: failed to read value", __func__);
            }
        } else {
            break;
        }
    }

    return true;
}

/** Upgrade the database from older formats */
bool CCoinsViewDB::Upgrade() {
    const CAmount flagBalance = 0;
    const AccountCoinRWEntry flagAccountEntry(std::numeric_limits<CAccountID>::max(), COutPoint(uint256(), 0));

    CAmount currentTagBalance;
    if (db.Read(flagAccountEntry, VARINT(currentTagBalance)) && currentTagBalance == flagBalance)
        return true; // Exist balance entry

    // Reindex UTXO for address
    uiInterface.ShowProgress(_("Upgrading UTXO database"), 0, true);
    LogPrintf("Upgrading UTXO database: [0%%]...");

    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    int remove = 0, add = 0;

    // Clear old account balance index data
    {
        AccountCoinRWEntry entry(0, COutPoint(uint256(), 0));
        pcursor->Seek(entry);
        if (pcursor->Valid()) {
            CDBBatch batch(db);
            while (pcursor->Valid()) {
                if (pcursor->GetKey(entry) && entry.key == DB_ACCOUNT_BALANCE) {
                    batch.Erase(entry);
                    remove++;
                } else {
                    break;
                }
                pcursor->Next();
            }
            db.WriteBatch(batch);
        }
    }

    // Create account balance index data
    pcursor->Seek(DB_COIN);
    if (pcursor->Valid()) {
        size_t batch_size = (size_t)gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
        int utxo_bucket = 130000 / 100; // Current UTXO about 130000
        int indexProgress = -1;
        CDBBatch batch(db);
        COutPoint outpoint;
        Coin coin;
        CoinEntry entry(&outpoint);
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_COIN) {
                if (!pcursor->GetValue(coin))
                    return error("%s: cannot parse coin record", __func__);

                if (coin.refOut.accountID != 0) {
                    batch.Write(AccountCoinRefEntry(&coin.refOut.accountID, &outpoint), VARINT(coin.refOut.value));
                    add++;
                    if (batch.SizeEstimate() > batch_size) {
                        db.WriteBatch(batch);
                        batch.Clear();
                    }

                    if (add % (utxo_bucket/10) == 0) {
                        int newProgress = std::min(90, add / utxo_bucket);
                        if (newProgress/10 != indexProgress/10) {
                            indexProgress = newProgress;
                            uiInterface.ShowProgress(_("Upgrading UTXO database"), indexProgress, true);
                            LogPrintf("[%d%%]...", indexProgress);
                        }
                    }
                }
            } else {
                break;
            }
            pcursor->Next();
        }
        db.WriteBatch(batch);
    }
    if (!db.Write(flagAccountEntry, VARINT(flagBalance)))
        return error("%s: cannot write UTXO upgrade flag", __func__);
    add++;
    uiInterface.ShowProgress("", 100, false);
    LogPrintf("[%s]. remove %d, add %d\n", ShutdownRequested() ? "CANCELLED" : "DONE", remove, add);

    // Remove older database file
    #ifdef WIN32
        ::DeleteFileW((GetDataDir() / "chainstate/account.db3").c_str());
    #else
        unlink((GetDataDir() / "chainstate/account.db3").c_str());
    #endif

    return !ShutdownRequested();
}
