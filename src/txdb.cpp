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

/** UTXO version flag */
static const char DB_COIN_VERSION = 'V';

static const char DB_COIN = 'C';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_HEAD_BLOCKS = 'H';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

/** Index flag for <Account,UTXO> to UTXO amount */
static const char DB_ACCOUNT_COIN = 'T';
/** Index flag for <Loan account,UTXO> to pledge loan UTXO amount */
static const char DB_COIN_PLEDGELOAN = 'E';
/** Index flag for <Debit account,UTXO> to pledge debit UTXO amount */
static const char DB_COIN_PLEDGEDEBIT = 'e';
/** Index flag for <Account,PlotterId> to bind plotter UTXO */
static const char DB_COIN_BINDPLOTTER = 'P';

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

struct AccountCoinEntry {
    CAccountID accountID;
    COutPoint outpoint;
    char key;
    AccountCoinEntry(const CAccountID &accountIdIn, const COutPoint &outpointIn) :
        accountID(accountIdIn), outpoint(outpointIn),
        key(DB_ACCOUNT_COIN) {}

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

struct AccountCoinRefEntry {
    CAccountID* accountID;
    COutPoint* outpoint;
    char key;
    AccountCoinRefEntry(const CAccountID* ptr1, const COutPoint* ptr2) :
        accountID(const_cast<CAccountID*>(ptr1)), outpoint(const_cast<COutPoint*>(ptr2)),
        key(DB_ACCOUNT_COIN) {}

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

struct BindPlotterEntry {
    CAccountID accountID;
    uint64_t plotterId;
    COutPoint outpoint;
    char key;
    BindPlotterEntry(const CAccountID &accountIDIn, const uint64_t &plotterIdIn, const COutPoint &outpointIn) :
        accountID(accountIDIn), plotterId(plotterIdIn), outpoint(outpointIn),
        key(DB_COIN_BINDPLOTTER) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(accountID);
        s << VARINT(plotterId);
        s << outpoint.hash;
        s << VARINT(outpoint.n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(accountID);
        s >> VARINT(plotterId);
        s >> outpoint.hash;
        s >> VARINT(outpoint.n);
    }
};

struct BindPlotterRefEntry {
    CAccountID* accountID;
    uint64_t* plotterId;
    COutPoint* outpoint;
    char key;
    BindPlotterRefEntry(const CAccountID* accountIDIn, const uint64_t* plotterIdIn, const COutPoint *outpointIn) :
        accountID(const_cast<CAccountID*>(accountIDIn)), plotterId(const_cast<uint64_t*>(plotterIdIn)), outpoint(const_cast<COutPoint*>(outpointIn)),
        key(DB_COIN_BINDPLOTTER) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(*accountID);
        s << VARINT(*plotterId);
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(*accountID);
        s >> VARINT(*plotterId);
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct PledgeLoanEntry {
    CAccountID creditAccountID;
    COutPoint outpoint;
    char key;
    PledgeLoanEntry(const CAccountID &accountIDIn, const COutPoint &outpointIn) :
        creditAccountID(accountIDIn), outpoint(outpointIn),
        key(DB_COIN_PLEDGELOAN) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(creditAccountID);
        s << outpoint.hash;
        s << VARINT(outpoint.n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(creditAccountID);
        s >> outpoint.hash;
        s >> VARINT(outpoint.n);
    }
};

struct PledgeLoanRefEntry {
    CAccountID* creditAccountID;
    COutPoint* outpoint;
    char key;
    PledgeLoanRefEntry(const CAccountID* ptr1, const COutPoint* ptr2) :
        creditAccountID(const_cast<CAccountID*>(ptr1)), outpoint(const_cast<COutPoint*>(ptr2)),
        key(DB_COIN_PLEDGELOAN) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(*creditAccountID);
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(*creditAccountID);
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
    }
};

struct PledgeDebitEntry {
    CAccountID debitAccountID;
    COutPoint outpoint;
    char key;
    PledgeDebitEntry(const CAccountID &accountIDIn, const COutPoint &outpointIn) :
        debitAccountID(accountIDIn), outpoint(outpointIn),
        key(DB_COIN_PLEDGEDEBIT) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(debitAccountID);
        s << outpoint.hash;
        s << VARINT(outpoint.n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(debitAccountID);
        s >> outpoint.hash;
        s >> VARINT(outpoint.n);
    }
};

struct PledgeDebitRefEntry {
    CAccountID* debitAccountID;
    COutPoint* outpoint;
    char key;
    PledgeDebitRefEntry(const CAccountID* ptr1, const COutPoint* ptr2) :
        debitAccountID(const_cast<CAccountID*>(ptr1)), outpoint(const_cast<COutPoint*>(ptr2)),
        key(DB_COIN_PLEDGEDEBIT) {}

    template<typename Stream>
    void Serialize(Stream &s) const {
        s << key;
        s << VARINT(*debitAccountID);
        s << outpoint->hash;
        s << VARINT(outpoint->n);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        s >> key;
        s >> VARINT(*debitAccountID);
        s >> outpoint->hash;
        s >> VARINT(outpoint->n);
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

                if (it->second.coin.refOutAccountID != 0)
                    batch.Erase(AccountCoinRefEntry(&it->second.coin.refOutAccountID, &it->first));

                if (it->second.coin.extraData) {
                    if (it->second.coin.extraData->type == DATACARRIER_TYPE_BINDPLOTTER) {
                        batch.Erase(BindPlotterRefEntry(&it->second.coin.refOutAccountID, &BindPlotterPayload::As(it->second.coin.extraData)->id, &it->first));
                    }
                    else if (it->second.coin.extraData->type == DATACARRIER_TYPE_PLEDGELOAN) {
                        batch.Erase(PledgeLoanRefEntry(&it->second.coin.refOutAccountID, &it->first));
                        batch.Erase(PledgeDebitRefEntry(&PledgeLoanPayload::As(it->second.coin.extraData)->GetDebitAccountID(), &it->first));
                    }
                }
            } else {
                batch.Write(CoinEntry(&it->first), it->second.coin);

                if (it->second.coin.refOutAccountID != 0)
                    batch.Write(AccountCoinRefEntry(&it->second.coin.refOutAccountID, &it->first), VARINT(it->second.coin.out.nValue));

                if (it->second.coin.extraData) {
                    if (it->second.coin.extraData->type == DATACARRIER_TYPE_BINDPLOTTER) {
                        batch.Write(BindPlotterRefEntry(&it->second.coin.refOutAccountID, &BindPlotterPayload::As(it->second.coin.extraData)->id, &it->first), 0);
                    }
                    else if (it->second.coin.extraData->type == DATACARRIER_TYPE_PLEDGELOAN) {
                        batch.Write(PledgeLoanRefEntry(&it->second.coin.refOutAccountID, &it->first), VARINT(it->second.coin.out.nValue));
                        batch.Write(PledgeDebitRefEntry(&PledgeLoanPayload::As(it->second.coin.extraData)->GetDebitAccountID(), &it->first), VARINT(it->second.coin.out.nValue));
                    }
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

CCoinsViewCursorRef CCoinsViewDB::Cursor() const {
    /** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
    class CCoinsViewDBCursor : public CCoinsViewCursor
    {
    public:
        CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256 &hashBlockIn) : CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {
            /* It seems that there are no "const iterators" for LevelDB.  Since we
               only need read operations on it, use a const-cast to get around
               that restriction.  */
            pcursor->Seek(DB_COIN);
            // Cache key of first record
            if (pcursor->Valid()) {
                CoinEntry entry(&keyTmp.second);
                pcursor->GetKey(entry);
                keyTmp.first = entry.key;
            }
            else {
                keyTmp.first = 0; // Make sure Valid() and GetKey() return false
            }
        }

        bool GetKey(COutPoint &key) const override {
            // Return cached key
            if (keyTmp.first == DB_COIN) {
                key = keyTmp.second;
                return true;
            }
            return false;
        }

        bool GetValue(Coin &coin) const override { return pcursor->GetValue(coin); }
        unsigned int GetValueSize() const override { return pcursor->GetValueSize(); }

        bool Valid() const override { return keyTmp.first == DB_COIN; }
        void Next() override {
            pcursor->Next();
            CoinEntry entry(&keyTmp.second);
            if (!pcursor->Valid() || !pcursor->GetKey(entry)) {
                keyTmp.first = 0; // Invalidate cached key after last record so that Valid() and GetKey() return false
            }
            else {
                keyTmp.first = entry.key;
            }
        }

    private:
        std::unique_ptr<CDBIterator> pcursor;
        std::pair<char, COutPoint> keyTmp;
    };

    return std::make_shared<CCoinsViewDBCursor>(db.NewIterator(), GetBestBlock());
}

CCoinsViewCursorRef CCoinsViewDB::PledgeLoanCursor(const CAccountID &accountID) const {
    class CCoinsViewDBPledgeCreditCursor : public CCoinsViewCursor
    {
    public:
        CCoinsViewDBPledgeCreditCursor(const CCoinsViewDB* pcoinviewdbIn, CDBIterator* pcursorIn, const uint256& hashBlockIn, const CAccountID& accountIDIn)
            : CCoinsViewCursor(hashBlockIn), pcoinviewdb(pcoinviewdbIn), pcursor(pcursorIn), accountID(accountIDIn), outpoint(uint256(), 0) {
            if (accountID != 0) {
                pcursor->Seek(PledgeLoanRefEntry(&accountID, &outpoint));
                // Test key of first record
                TestKey();
            }
        }

        bool GetKey(COutPoint &key) const override {
            // Return cached key
            if (accountID != 0) {
                key = outpoint;
                return true;
            }
            return false;
        }

        bool GetValue(Coin &coin) const override { return pcoinviewdb->GetCoin(outpoint, coin); }
        unsigned int GetValueSize() const override { return pcursor->GetValueSize(); }

        bool Valid() const override { return accountID != 0; }
        void Next() override {
            pcursor->Next();
            TestKey();
        }

    private:
        void TestKey() {
            CAccountID tempAccountID;
            PledgeLoanRefEntry entry(&tempAccountID, &outpoint);
            if (!pcursor->Valid() || !pcursor->GetKey(entry) || entry.key != DB_COIN_PLEDGELOAN || tempAccountID != accountID) {
                accountID = 0;
            }
        }

        const CCoinsViewDB* pcoinviewdb;
        std::unique_ptr<CDBIterator> pcursor;
        CAccountID accountID;
        COutPoint outpoint;
    };

    return std::make_shared<CCoinsViewDBPledgeCreditCursor>(this, db.NewIterator(), GetBestBlock(), accountID);
}

CCoinsViewCursorRef CCoinsViewDB::PledgeDebitCursor(const CAccountID &accountID) const {
    class CCoinsViewDBPledgeDebitCursor : public CCoinsViewCursor
    {
    public:
        CCoinsViewDBPledgeDebitCursor(const CCoinsViewDB* pcoinviewdbIn, CDBIterator* pcursorIn, const uint256& hashBlockIn, const CAccountID& accountIDIn)
            : CCoinsViewCursor(hashBlockIn), pcoinviewdb(pcoinviewdbIn), pcursor(pcursorIn), accountID(accountIDIn), outpoint(uint256(), 0) {
            if (accountID != 0) {
                pcursor->Seek(PledgeDebitRefEntry(&accountID, &outpoint));
                // Test key of first record
                TestKey();
            }
        }

        bool GetKey(COutPoint &key) const override {
            // Return cached key
            if (accountID != 0) {
                key = outpoint;
                return true;
            }
            return false;
        }

        bool GetValue(Coin &coin) const override { return pcoinviewdb->GetCoin(outpoint, coin); }
        unsigned int GetValueSize() const override { return pcursor->GetValueSize(); }

        bool Valid() const override { return accountID != 0; }
        void Next() override {
            pcursor->Next();
            TestKey();
        }

    private:
        void TestKey() {
            CAccountID tempAccountID;
            PledgeDebitRefEntry entry(&tempAccountID, &outpoint);
            if (!pcursor->Valid() || !pcursor->GetKey(entry) || entry.key != DB_COIN_PLEDGEDEBIT || tempAccountID != accountID) {
                accountID = 0;
            }
        }

        const CCoinsViewDB* pcoinviewdb;
        std::unique_ptr<CDBIterator> pcursor;
        CAccountID accountID;
        COutPoint outpoint;
    };

    return std::make_shared<CCoinsViewDBPledgeDebitCursor>(this, db.NewIterator(), GetBestBlock(), accountID);
}

size_t CCoinsViewDB::EstimateSize() const {
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}

CAmount CCoinsViewDB::GetBalance(const CAccountID &accountID, const CCoinsMap &mapParentModifiedCoins,
    CAmount *pBindPlotterBalance, CAmount *pPledgeLoanBalance, CAmount *pPledgeDebitBalance) const
{
    std::unique_ptr<CDBIterator> pcursor;
    CAmount availableBalance = 0;

    // Read from database
    {
        if (!pcursor) pcursor.reset(db.NewIterator());

        CAmount value;
        AccountCoinEntry entry(accountID, COutPoint(uint256(), 0));
        pcursor->Seek(entry);
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_ACCOUNT_COIN && entry.accountID == accountID) {
                if (pcursor->GetValue(VARINT(value)))
                    availableBalance += value;
            } else {
                break;
            }
            pcursor->Next();
        }
    }

    // Apply modified coin
    for (CCoinsMap::const_iterator it = mapParentModifiedCoins.cbegin(); it != mapParentModifiedCoins.cend(); it++) {
        if ((it->second.flags & CCoinsCacheEntry::DIRTY) && it->second.coin.refOutAccountID == accountID) {
            if (it->second.coin.IsSpent()) {
                if (db.Exists(CoinEntry(&it->first)))
                    availableBalance -= it->second.coin.out.nValue;
            } else {
                if (!db.Exists(CoinEntry(&it->first)))
                    availableBalance += it->second.coin.out.nValue;
            }
        }
    }
    assert(availableBalance >= 0);

    // The bind plotter coin
    if (pBindPlotterBalance != nullptr) {
        *pBindPlotterBalance = 0;

        // Read from database
        {
            if (!pcursor) pcursor.reset(db.NewIterator());

            BindPlotterEntry entry(accountID, 0, COutPoint(uint256(), 0));
            pcursor->Seek(entry);
            while (pcursor->Valid()) {
                if (pcursor->GetKey(entry) && entry.key == DB_COIN_BINDPLOTTER && entry.accountID == accountID) {
                    *pBindPlotterBalance += PROTOCOL_BINDPLOTTER_AMOUNT;
                } else {
                    break;
                }
                pcursor->Next();
            }
        }

        // Apply modified coin
        for (CCoinsMap::const_iterator it = mapParentModifiedCoins.cbegin(); it != mapParentModifiedCoins.cend(); it++) {
            if ((it->second.flags & CCoinsCacheEntry::DIRTY) && it->second.coin.refOutAccountID == accountID &&
                    it->second.coin.extraData && it->second.coin.extraData->type == DATACARRIER_TYPE_BINDPLOTTER) {
                if (it->second.coin.IsSpent()) {
                    if (db.Exists(CoinEntry(&it->first)))
                        *pBindPlotterBalance -= PROTOCOL_BINDPLOTTER_AMOUNT;
                } else {
                    if (!db.Exists(CoinEntry(&it->first)))
                        *pBindPlotterBalance += PROTOCOL_BINDPLOTTER_AMOUNT;
                }
            }
        }
        assert(*pBindPlotterBalance >= 0);
    }

    // The pledge loan
    if (pPledgeLoanBalance != nullptr) {
        *pPledgeLoanBalance = 0;

        // Read from database
        {
            if (!pcursor) pcursor.reset(db.NewIterator());

            CAmount value;
            PledgeLoanEntry entry(accountID, COutPoint(uint256(), 0));
            pcursor->Seek(entry);
            while (pcursor->Valid()) {
                if (pcursor->GetKey(entry) && entry.key == DB_COIN_PLEDGELOAN && entry.creditAccountID == accountID) {
                    if (pcursor->GetValue(VARINT(value)))
                        *pPledgeLoanBalance += value;
                } else {
                    break;
                }
                pcursor->Next();
            }
        }

        // Apply modified coin
        for (CCoinsMap::const_iterator it = mapParentModifiedCoins.cbegin(); it != mapParentModifiedCoins.cend(); it++) {
            if ((it->second.flags & CCoinsCacheEntry::DIRTY) && it->second.coin.refOutAccountID == accountID &&
                    it->second.coin.extraData && it->second.coin.extraData->type == DATACARRIER_TYPE_PLEDGELOAN) {
                if (it->second.coin.IsSpent()) {
                    if (db.Exists(CoinEntry(&it->first)))
                        *pPledgeLoanBalance -= it->second.coin.out.nValue;
                } else {
                    if (!db.Exists(CoinEntry(&it->first)))
                        *pPledgeLoanBalance += it->second.coin.out.nValue;
                }
            }
        }
        assert(*pPledgeLoanBalance >= 0);
    }

    // The pledge debit
    if (pPledgeDebitBalance != nullptr) {
        *pPledgeDebitBalance = 0;

        // Read from database
        {
            if (!pcursor) pcursor.reset(db.NewIterator());

            CAmount value;
            PledgeDebitEntry entry(accountID, COutPoint(uint256(), 0));
            pcursor->Seek(entry);
            while (pcursor->Valid()) {
                if (pcursor->GetKey(entry) && entry.key == DB_COIN_PLEDGEDEBIT && entry.debitAccountID == accountID) {
                    if (pcursor->GetValue(VARINT(value)))
                        *pPledgeDebitBalance += value;
                } else {
                    break;
                }
                pcursor->Next();
            }
        }

        // Apply modified coin
        for (CCoinsMap::const_iterator it = mapParentModifiedCoins.cbegin(); it != mapParentModifiedCoins.cend(); it++) {
            if ((it->second.flags & CCoinsCacheEntry::DIRTY) && it->second.coin.extraData &&
                    it->second.coin.extraData->type == DATACARRIER_TYPE_PLEDGELOAN &&
                    PledgeLoanPayload::As(it->second.coin.extraData)->GetDebitAccountID() == accountID) {
                if (it->second.coin.IsSpent()) {
                    if (db.Exists(CoinEntry(&it->first)))
                        *pPledgeDebitBalance -= it->second.coin.out.nValue;
                } else {
                    if (!db.Exists(CoinEntry(&it->first)))
                        *pPledgeDebitBalance += it->second.coin.out.nValue;
                }
            }
        }
        assert(*pPledgeDebitBalance >= 0);
    }

    return availableBalance;
}

void CCoinsViewDB::GetAccountBindPlotterEntries(const CAccountID &accountID, const uint64_t &plotterId, std::set<COutPoint> &outpoints) const {
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    BindPlotterEntry entry(accountID, plotterId, COutPoint(uint256(), 0));
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && entry.key == DB_COIN_BINDPLOTTER && entry.accountID == accountID && (plotterId == 0 || entry.plotterId == plotterId)) {
            outpoints.insert(entry.outpoint);
        } else {
            break;
        }
        pcursor->Next();
    }
}

void CCoinsViewDB::GetBindPlotterAccountEntries(const uint64_t &plotterId, std::set<COutPoint> &outpoints) const {
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    BindPlotterEntry entry(0, 0, COutPoint(uint256(), 0));
    pcursor->Seek(entry);
    while (pcursor->Valid()) {
        if (pcursor->GetKey(entry) && entry.key == DB_COIN_BINDPLOTTER && entry.plotterId == plotterId) {
            outpoints.insert(entry.outpoint);
        } else {
            break;
        }
        pcursor->Next();
    }
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe) { }

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
    const uint32_t currentCoinDbVersion = 0x20181225;

    // Check coin database version
    {
        uint32_t coinDbVersion;
        if (db.Read(DB_COIN_VERSION, VARINT(coinDbVersion)) && coinDbVersion == currentCoinDbVersion)
            return true; // Newest version
        db.Erase(DB_COIN_VERSION);
    }

    // Reindex UTXO for address
    uiInterface.ShowProgress(_("Upgrading UTXO database"), 0, true);
    LogPrintf("Upgrading UTXO database to %08x: [0%%]...", currentCoinDbVersion);

    int remove = 0, add = 0;
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());

    // Clear old account balance index data
    pcursor->Seek(DB_ACCOUNT_COIN);
    if (pcursor->Valid()) {
        CDBBatch batch(db);
        AccountCoinEntry entry(0, COutPoint());
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_ACCOUNT_COIN) {
                batch.Erase(entry);
                remove++;
            } else {
                break;
            }
            pcursor->Next();
        }
        db.WriteBatch(batch);
    }
    // Clear old bind plotter index data
    pcursor->Seek(DB_COIN_BINDPLOTTER);
    if (pcursor->Valid()) {
        CDBBatch batch(db);
        BindPlotterEntry entry(0, 0, COutPoint());
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_COIN_BINDPLOTTER) {
                batch.Erase(entry);
                remove++;
            } else {
                break;
            }
            pcursor->Next();
        }
        db.WriteBatch(batch);
    }
    // Clear old pledge loan index data
    pcursor->Seek(DB_COIN_PLEDGELOAN);
    if (pcursor->Valid()) {
        CDBBatch batch(db);
        PledgeLoanEntry entry(0, COutPoint());
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_COIN_PLEDGELOAN) {
                batch.Erase(entry);
                remove++;
            } else {
                break;
            }
            pcursor->Next();
        }
        db.WriteBatch(batch);
    }
    // Clear old pledge debit index data
    pcursor->Seek(DB_COIN_PLEDGEDEBIT);
    if (pcursor->Valid()) {
        CDBBatch batch(db);
        PledgeDebitEntry entry(0, COutPoint());
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_COIN_PLEDGEDEBIT) {
                batch.Erase(entry);
                remove++;
            } else {
                break;
            }
            pcursor->Next();
        }
        db.WriteBatch(batch);
    }

    // Create account balance index data
    pcursor->Seek(DB_COIN);
    if (pcursor->Valid()) {
        size_t batch_size = (size_t)gArgs.GetArg("-dbbatchsize", nDefaultDbBatchSize);
        int utxo_bucket = 130000 / 100; // Current UTXO about 130000
        int indexProgress = -1;
        CDBBatch batch(db);
        COutPoint outpoint;
        CoinEntry entry(&outpoint);
        while (pcursor->Valid()) {
            if (pcursor->GetKey(entry) && entry.key == DB_COIN) {
                Coin coin;
                if (!pcursor->GetValue(coin))
                    return error("%s: cannot parse coin record", __func__);

                if (coin.refOutAccountID != 0) {
                    // Balance of address index
                    batch.Write(AccountCoinRefEntry(&coin.refOutAccountID, &outpoint), VARINT(coin.out.nValue));
                    add++;

                    // Extra data
                    if (coin.extraData) {
                        if (coin.extraData->type == DATACARRIER_TYPE_BINDPLOTTER) {
                            batch.Write(BindPlotterRefEntry(&coin.refOutAccountID, &BindPlotterPayload::As(coin.extraData)->id, &outpoint), 0);
                            add++;
                        }
                        else if (coin.extraData->type == DATACARRIER_TYPE_PLEDGELOAN) {
                            batch.Write(PledgeLoanRefEntry(&coin.refOutAccountID, &outpoint), VARINT(coin.out.nValue));
                            batch.Write(PledgeDebitRefEntry(&PledgeLoanPayload::As(coin.extraData)->GetDebitAccountID(), &outpoint), VARINT(coin.out.nValue));
                            add += 2;
                        }
                    }

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

    // Update coin version
    if (!db.Write(DB_COIN_VERSION, VARINT(currentCoinDbVersion)))
        return error("%s: cannot write UTXO upgrade flag", __func__);

    uiInterface.ShowProgress("", 100, false);
    LogPrintf("[%s]. remove utxo %d, add utxo %d\n", ShutdownRequested() ? "CANCELLED" : "DONE", remove, add);


    // Remove older database file
    #ifdef WIN32
        ::DeleteFileW((GetDataDir() / "chainstate/account.db3").c_str());
    #else
        unlink((GetDataDir() / "chainstate/account.db3").c_str());
    #endif

    return !ShutdownRequested();
}
