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
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

static const char DB_BEST_BLOCK = 'B';
static const char DB_HEAD_BLOCKS = 'H';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    char key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

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

// Account version exception
class CUpgradeAccountException : public std::exception { };

// SQL exception
class CSqlException : public std::exception
{
public:
    CSqlException(SqlAutoReleaseDB &db, const std::string &err) : std::exception()
    {
        detail += err;
        detail += " (";
        detail += sqlite3_errmsg(db.get());
        detail += ")";
    }

    const char* what() const noexcept
    {
        return detail.c_str();
    }

private:
    std::string detail;
};

void TryExecuteSql(SqlAutoReleaseDB &db, const std::string &sql) {
    char *errmsg;
    sqlite3_exec(db.get(), sql.c_str(), NULL, NULL, &errmsg);
    if (errmsg != NULL) {
        std::string err = errmsg;
        sqlite3_free(errmsg);
        throw CSqlException(db, err);
    }
}

SqlAutoReleaseDB CreateDatabase(const fs::path& path, const std::string &initSql) {
    sqlite3 *db = NULL;
#ifdef WIN32
    int rc = sqlite3_open16(path.c_str(), &db);
#else
    int rc = sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
#endif
    auto autoDB = SqlAutoReleaseDB(db, sqlite3_close);
    if (rc != SQLITE_OK) {
        throw CSqlException(autoDB, std::string("ERROR opening SQLite DB(") + path.string() + ")");
    }

    TryExecuteSql(autoDB, initSql);
    return autoDB;
}

SqlAutoReleaseStmt CreateStatement(SqlAutoReleaseDB &db, const std::string &sql) {
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db.get(), sql.c_str(), -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        throw CSqlException(db, "ERROR create SQLite statement");
    }

    return SqlAutoReleaseStmt(stmt, sqlite3_finalize);
}

void CheckRC(int requireRc, int rc, SqlAutoReleaseDB &db, const char *func) {
    if (rc != requireRc)
        throw CSqlException(db, func);
}

//! Auto commit wrapper
class SqlAutoTransaction
{
public:
    SqlAutoTransaction(SqlAutoReleaseDB &dbIn) : db(dbIn), commited(false) {
        TryExecuteSql(db, "BEGIN TRANSACTION");
    }

    ~SqlAutoTransaction() {
        if (!commited) {
            TryExecuteSql(db, "ROLLBACK");
        }
    }

    bool Commit() {
        assert(!commited);
        try {
            TryExecuteSql(db, "COMMIT");
            commited = true;
            return true;
        } catch (CSqlException &e) {
            LogPrintf("CCoinsViewDB: Commit account transaction error: \"%s\"", e.what());
        }

        return false;
    }

private:
    SqlAutoReleaseDB &db;
    bool commited;
};

class SqlAutoResetStmt
{
public:
    SqlAutoResetStmt(SqlAutoReleaseStmt &stmtIn) : stmt(stmtIn) {}
    ~SqlAutoResetStmt() {
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

private:
    SqlAutoReleaseStmt &stmt;
};

const std::string ACCOUNT_DDL_SQL =
    "CREATE TABLE IF NOT EXISTS `account` ("
    "  `db_id` INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  `accountId` BIGINT(20) NOT NULL,"
    "  `balance` BIGINT(20) NOT NULL,"
    "  `height` INTEGER(11) NOT NULL"
    ");"
    "CREATE UNIQUE INDEX IF NOT EXISTS `account_accountId_height_idx` ON `account` (`accountId`,`height`);"
    "CREATE INDEX IF NOT EXISTS `account_accountId_height_idx` ON `account` (`accountId`,`height`);"
    "CREATE TABLE IF NOT EXISTS `account_meta` (`name` VARCHAR(32) PRIMARY KEY, `value` VARCHAR(64));";
const std::string ACCOUNT_GET_NEAREST_BALANCE_SQL =
    "SELECT `balance`,`height` FROM `account`"
    " WHERE `accountId` = ? AND `height` <= ?"
    " ORDER BY `height` DESC"
    " LIMIT 1;";
const std::string ACCOUNT_INSERT_SQL =
    "INSERT INTO `account`(`accountId`,`balance`,`height`)"
    " VALUES(?,?,?);";
const std::string ACCOUNT_UPDATE_BALANCE_SQL =
    "UPDATE `account` SET `balance` = `balance` + ?"
    " WHERE `accountId` = ? AND `height` >= ?";

const int ACCOUNT_VERSION = 20180920;
int nCurrentAccountDbVersion = 0;

}

#define CRC_DONE(rc)    CheckRC(SQLITE_DONE, rc, accountDB, __func__)


CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) :
    db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe, true),
    accountDB(CreateDatabase(GetDataDir() / "chainstate/account.db3", ACCOUNT_DDL_SQL)),
    getAccountNearestStmt(CreateStatement(accountDB, ACCOUNT_GET_NEAREST_BALANCE_SQL))
{
    if (fWipe) {
        // Clear
        if (!ClearAccount()) {
            throw CUpgradeAccountException();
        }
        nCurrentAccountDbVersion = 0;
    }
}

bool CCoinsViewDB::ClearAccount() {
    SqlAutoTransaction autoTx(accountDB);
    SqlAutoReleaseStmt clearAccountStmt(CreateStatement(accountDB, "DELETE FROM `account`"));
    SqlAutoReleaseStmt clearAccountMetaStmt(CreateStatement(accountDB, "DELETE FROM `account_meta`"));
    SqlAutoReleaseStmt dropAccountVersionStmt(CreateStatement(accountDB, "DROP TABLE IF EXISTS `account_ver`"));
    SqlAutoReleaseStmt resetSequenceStmt(CreateStatement(accountDB, "DELETE FROM `sqlite_sequence` WHERE `name` = 'account'"));
    CRC_DONE(sqlite3_step(clearAccountStmt.get()));
    CRC_DONE(sqlite3_step(clearAccountMetaStmt.get()));
    CRC_DONE(sqlite3_step(dropAccountVersionStmt.get()));
    CRC_DONE(sqlite3_step(resetSequenceStmt.get()));
    return autoTx.Commit();
}

bool CCoinsViewDB::CheckDB(const CChainParams &chainparams) {
    std::map<std::string, std::string> mapAccountMeta;
    // Load meta data
    {
        SqlAutoReleaseStmt accountMetaStmt(CreateStatement(accountDB, "SELECT `name`,`value` FROM `account_meta`"));
        while (sqlite3_step(accountMetaStmt.get()) == SQLITE_ROW) {
            char * name = (char *) sqlite3_column_text(accountMetaStmt.get(), 0);
            char * value = (char *) sqlite3_column_text(accountMetaStmt.get(), 1);
            mapAccountMeta[std::string(name)] = std::move(std::string(value?value : ""));
        }
    }

    // Check best block
    uint256 bestBlock = GetBestBlock();
    if (bestBlock.IsNull()) {
        // Empty
        return ClearAccount();
    }

    if (mapAccountMeta.count("bestHash") == 0 || mapAccountMeta["bestHash"] != bestBlock.ToString()) {
        // Bad block
        return false;
    }

    // Check account version
    nCurrentAccountDbVersion = mapAccountMeta.count("ver") ? std::stoi(mapAccountMeta["ver"]) : 0;
    if (nCurrentAccountDbVersion != ACCOUNT_VERSION) {
        // Require upgrade
        return false;
    }

    return true;
}

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

bool CCoinsViewDB::BatchWrite(CCoinsMap &mapCoins, CAccountDiffCoinsMap &mapAccountDiffCoins, const uint256 &hashBlock) {
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
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent())
                batch.Erase(entry);
            else
                batch.Write(entry, it->second.coin);
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

    // Update account table
    size_t accountChanged = mapAccountDiffCoins.size();
    size_t accountDiffCoinsMemorySize = memusage::DynamicUsage(mapAccountDiffCoins);
    SqlAutoTransaction autoTx(accountDB);
    // Check account best block
    {
        uint256 currentBestBlock;
        SqlAutoReleaseStmt accountBestStmt(CreateStatement(accountDB, "SELECT `value` FROM `account_meta` WHERE `name` = 'bestHash'"));
        if (sqlite3_step(accountBestStmt.get()) == SQLITE_ROW) {
            char * bestBlockHash = (char *) sqlite3_column_text(accountBestStmt.get(), 0);
            if (bestBlockHash) {
                currentBestBlock = uint256S(bestBlockHash);
            }
        }
        if (currentBestBlock != old_tip) {
            // levelDB and sqlite not synced
            return false;
        }

        SqlAutoReleaseStmt deleteBestStmt(CreateStatement(accountDB, "DELETE FROM `account_meta` WHERE `name` = 'bestHash' OR `name` = 'bestHeight'"));
        CRC_DONE(sqlite3_step(deleteBestStmt.get()));
    }
    if (!mapAccountDiffCoins.empty()) {
        // Insert items
        SqlAutoReleaseStmt addAccountStmt(CreateStatement(accountDB, ACCOUNT_INSERT_SQL));
        SqlAutoReleaseStmt updateAccountBalanceStmt(CreateStatement(accountDB, ACCOUNT_UPDATE_BALANCE_SQL));
        for (auto itHeight = mapAccountDiffCoins.begin(); itHeight != mapAccountDiffCoins.end(); itHeight = mapAccountDiffCoins.erase(itHeight)) {
            int nDataHeight = itHeight->first;
            auto &mapAccountDiff = itHeight->second;
            for (auto itAccount = mapAccountDiff.begin(); itAccount != mapAccountDiff.end(); itAccount = mapAccountDiff.erase(itAccount)) {
                auto &nAccountId = itAccount->first;
                auto &accountDiff = itAccount->second;
                if (nAccountId == 0 || accountDiff.nDiffCoins == 0)
                    continue;

                LogPrint(BCLog::COINDB, "CoinDiff: %19" PRIu64 "\t %6d\t %+8d.%08d\n", nAccountId, nDataHeight,
                    (int)(accountDiff.nDiffCoins / COIN), abs((int)(accountDiff.nDiffCoins % COIN)));

                // Query near balance
                CAmount nAccountBalance;
                int nBalanceHeight;
                {
                    SqlAutoResetStmt autoResetStmt(getAccountNearestStmt);
                    sqlite3_bind_int64(getAccountNearestStmt.get(), 1, static_cast<sqlite_int64>(nAccountId));
                    sqlite3_bind_int(getAccountNearestStmt.get(), 2, nDataHeight);
                    if (sqlite3_step(getAccountNearestStmt.get()) == SQLITE_ROW) {
                        nAccountBalance = static_cast<CAmount>(sqlite3_column_int64(getAccountNearestStmt.get(), 0));
                        nBalanceHeight = sqlite3_column_int(getAccountNearestStmt.get(), 1);
                    } else {
                        nAccountBalance = 0;
                        nBalanceHeight = -1;
                    }
                }
                nAccountBalance += accountDiff.nDiffCoins;
                assert(nAccountBalance >= 0);
                if (nBalanceHeight == nDataHeight) {
                    // Update current and all new height balance
                    SqlAutoResetStmt autoResetStmt(updateAccountBalanceStmt);
                    sqlite3_bind_int64(updateAccountBalanceStmt.get(), 1, static_cast<sqlite_int64>(accountDiff.nDiffCoins));
                    sqlite3_bind_int64(updateAccountBalanceStmt.get(), 2, static_cast<sqlite_int64>(nAccountId));
                    sqlite3_bind_int(updateAccountBalanceStmt.get(), 3, nDataHeight);
                    CRC_DONE(sqlite3_step(updateAccountBalanceStmt.get()));
                } else {
                    // Add new item
                    SqlAutoResetStmt autoResetStmt(addAccountStmt);
                    sqlite3_bind_int64(addAccountStmt.get(), 1, static_cast<sqlite_int64>(nAccountId));
                    sqlite3_bind_int64(addAccountStmt.get(), 2, static_cast<sqlite_int64>(nAccountBalance));
                    sqlite3_bind_int(addAccountStmt.get(), 3, nDataHeight);
                    CRC_DONE(sqlite3_step(addAccountStmt.get()));

                    // Update all new height balance
                    SqlAutoResetStmt autoResetStmt2(updateAccountBalanceStmt);
                    sqlite3_bind_int64(updateAccountBalanceStmt.get(), 1, static_cast<sqlite_int64>(accountDiff.nDiffCoins));
                    sqlite3_bind_int64(updateAccountBalanceStmt.get(), 2, static_cast<sqlite_int64>(nAccountId));
                    sqlite3_bind_int(updateAccountBalanceStmt.get(), 3, nDataHeight + 1);
                    CRC_DONE(sqlite3_step(updateAccountBalanceStmt.get()));
                }
            }
        }
    }
    // Write version
    if (nCurrentAccountDbVersion != ACCOUNT_VERSION) {
        SqlAutoReleaseStmt insertAccountVersionStmt(CreateStatement(accountDB, "INSERT INTO `account_meta`(`name`,`value`) VALUES('ver',?)"));
        sqlite3_bind_int(insertAccountVersionStmt.get(), 1, ACCOUNT_VERSION);
        CRC_DONE(sqlite3_step(insertAccountVersionStmt.get()));
    }
    // Write best block
    {
        int nHeight = mapBlockIndex[hashBlock]->nHeight;
        std::string bestBlockHash = hashBlock.ToString();
        // Hash
        SqlAutoReleaseStmt insertAccountBestHashStmt(CreateStatement(accountDB, "INSERT INTO `account_meta`(`name`,`value`) VALUES('bestHash',?)"));
        sqlite3_bind_text(insertAccountBestHashStmt.get(), 1, bestBlockHash.c_str(), -1, NULL);
        CRC_DONE(sqlite3_step(insertAccountBestHashStmt.get()));
        // Height
        SqlAutoReleaseStmt insertAccountBestHeightStmt(CreateStatement(accountDB, "INSERT INTO `account_meta`(`name`,`value`) VALUES('bestHeight',?)"));
        sqlite3_bind_int(insertAccountBestHeightStmt.get(), 1, nHeight);
        CRC_DONE(sqlite3_step(insertAccountBestHeightStmt.get()));
    }

    // Commit changes
    LogPrint(BCLog::COINDB, "Writing final batch of %.2f MiB\n", (batch.SizeEstimate() + accountDiffCoinsMemorySize) * (1.0 / 1048576.0));
    bool ret = db.WriteBatch(batch) && autoTx.Commit();
    LogPrint(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    LogPrint(BCLog::COINDB, "Committed %u changed account balance outputs to account database...\n", (unsigned int)accountChanged);
    if (ret) {
        nCurrentAccountDbVersion = ACCOUNT_VERSION;
    }
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return db.EstimateSize(DB_COIN, (char)(DB_COIN+1));
}

CAmount CCoinsViewDB::GetAccountBalance(const CAccountId &nAccountId, int nHeight) const
{
    CAmount nAccountBalance = 0;

    SqlAutoResetStmt autoResetStmt(getAccountNearestStmt);
    sqlite3_bind_int64(getAccountNearestStmt.get(), 1, static_cast<sqlite_int64>(nAccountId));
    sqlite3_bind_int(getAccountNearestStmt.get(), 2, nHeight);
    if (sqlite3_step(getAccountNearestStmt.get()) == SQLITE_ROW) {
        nAccountBalance = static_cast<CAmount>(sqlite3_column_int64(getAccountNearestStmt.get(), 0));
    }

    return nAccountBalance;
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
                pindexNew->nMinerAccountId = diskindex.nMinerAccountId;

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

namespace {

//! Legacy class to deserialize pre-pertxout database entries without reindex.
class CCoins
{
public:
    //! whether transaction is a coinbase
    bool fCoinBase;

    //! unspent transaction outputs; spent outputs are .IsNull(); spent outputs at the end of the array are dropped
    std::vector<CTxOut> vout;

    //! at which height this transaction was included in the active block chain
    int nHeight;

    //! empty constructor
    CCoins() : fCoinBase(false), vout(0), nHeight(0) { }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        // version
        int nVersionDummy;
        ::Unserialize(s, VARINT(nVersionDummy));
        // header code
        ::Unserialize(s, VARINT(nCode));
        fCoinBase = nCode & 1;
        std::vector<bool> vAvail(2, false);
        vAvail[0] = (nCode & 2) != 0;
        vAvail[1] = (nCode & 4) != 0;
        unsigned int nMaskCode = (nCode / 8) + ((nCode & 6) != 0 ? 0 : 1);
        // spentness bitmask
        while (nMaskCode > 0) {
            unsigned char chAvail = 0;
            ::Unserialize(s, chAvail);
            for (unsigned int p = 0; p < 8; p++) {
                bool f = (chAvail & (1 << p)) != 0;
                vAvail.push_back(f);
            }
            if (chAvail != 0)
                nMaskCode--;
        }
        // txouts themself
        vout.assign(vAvail.size(), CTxOut());
        for (unsigned int i = 0; i < vAvail.size(); i++) {
            if (vAvail[i])
                ::Unserialize(s, REF(CTxOutCompressor(vout[i])));
        }
        // coinbase height
        ::Unserialize(s, VARINT(nHeight));
    }
};

}

/** Upgrade the database from older formats.
 *
 * Currently implemented: from the per-tx utxo model (0.8..0.14.x) to per-txout.
 */
bool CCoinsViewDB::Upgrade() {
    std::unique_ptr<CDBIterator> pcursor(db.NewIterator());
    pcursor->Seek(std::make_pair(DB_COINS, uint256()));
    if (!pcursor->Valid()) {
        return true;
    }
    LogPrintf("Deprecated upgrade UTXO!\n");
    assert(false);

    int64_t count = 0;
    LogPrintf("Upgrading utxo-set database...\n");
    LogPrintf("[0%%]...");
    uiInterface.ShowProgress(_("Upgrading UTXO database"), 0, true);
    size_t batch_size = 1 << 24;
    CDBBatch batch(db);
    int reportDone = 0;
    std::pair<unsigned char, uint256> key;
    std::pair<unsigned char, uint256> prev_key = {DB_COINS, uint256()};
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        if (ShutdownRequested()) {
            break;
        }
        if (pcursor->GetKey(key) && key.first == DB_COINS) {
            if (count++ % 256 == 0) {
                uint32_t high = 0x100 * *key.second.begin() + *(key.second.begin() + 1);
                int percentageDone = (int)(high * 100.0 / 65536.0 + 0.5);
                uiInterface.ShowProgress(_("Upgrading UTXO database"), percentageDone, true);
                if (reportDone < percentageDone/10) {
                    // report max. every 10% step
                    LogPrintf("[%d%%]...", percentageDone);
                    reportDone = percentageDone/10;
                }
            }
            CCoins old_coins;
            if (!pcursor->GetValue(old_coins)) {
                return error("%s: cannot parse CCoins record", __func__);
            }
            COutPoint outpoint(key.second, 0);
            for (size_t i = 0; i < old_coins.vout.size(); ++i) {
                if (!old_coins.vout[i].IsNull() && !old_coins.vout[i].scriptPubKey.IsUnspendable()) {
                    Coin newcoin(std::move(old_coins.vout[i]), old_coins.nHeight, old_coins.fCoinBase);
                    outpoint.n = i;
                    CoinEntry entry(&outpoint);
                    batch.Write(entry, newcoin);
                }
            }
            batch.Erase(key);
            if (batch.SizeEstimate() > batch_size) {
                db.WriteBatch(batch);
                batch.Clear();
                db.CompactRange(prev_key, key);
                prev_key = key;
            }
            pcursor->Next();
        } else {
            break;
        }
    }
    db.WriteBatch(batch);
    db.CompactRange({DB_COINS, uint256()}, key);
    uiInterface.ShowProgress("", 100, false);
    LogPrintf("[%s].\n", ShutdownRequested() ? "CANCELLED" : "DONE");
    return !ShutdownRequested();
}
