// Copyright (c) 2017-2018 The BTCHD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DBWRAPPER_SQL_H
#define BITCOIN_DBWRAPPER_SQL_H

#include <fs.h>

#include <cassert>
#include <exception>
#include <string>

#include <sqlite3.h>

// Throw SQL exception
class CSqlException : public std::exception
{
public:
    CSqlException(sqlite3 *db, const std::string &err) : std::exception()
    {
        detail += err;
        detail += " (";
        detail += sqlite3_errmsg(db);
        detail += ")";
    }

    const char* what() const noexcept
    {
        return detail.c_str();
    }

    static void ExecuteAndThrow(sqlite3 *db, const std::string &sql)
    {
        char *errmsg;
        sqlite3_exec(db, sql.c_str(), NULL, NULL, &errmsg);
        if (errmsg != NULL) {
            std::string err = errmsg;
            sqlite3_free(errmsg);
            throw CSqlException(db, err);
        }
    }

private:
    std::string detail;
};

class CSqlDBWrapper;

/** Batch of changes queued to be written to a CSqlDBWrapper */
class CSqlDBBatch
{
    friend class CSqlDBWrapper;

public:
    /**
     * @param[in] parent    CSqlDBWrapper that this batch is to be submitted to
     * @param[in] sql       Prepare SQL
     */
    CSqlDBBatch(const CSqlDBWrapper &parent, const std::string &sql);

    ~CSqlDBBatch()
    {
        if (!commited) {
            CSqlException::ExecuteAndThrow(db, "ROLLBACK");
            commited = true;
        }

        if (!stmt) {
            sqlite3_finalize(stmt);
            stmt = NULL;
        }
    }

    void Clear()
    {
        sqlite3_clear_bindings(stmt);
        sqlite3_reset(stmt);

        if (!commited) {
            CSqlException::ExecuteAndThrow(db, "ROLLBACK");
            commited = true;
        }
        CSqlException::ExecuteAndThrow(db, "BEGIN TRANSACTION");
        commited = false;
    }

    template <typename T, typename K, typename V>
    void Write(const K& key, const V& value)
    {
        if (T::sqldb_stmt_write(stmt, key, value)) {
            if (SQLITE_DONE != sqlite3_step(stmt)) {
                throw CSqlException(db, "Commit stmt error");
            }
            sqlite3_clear_bindings(stmt);
            sqlite3_reset(stmt);
        }
    }

    template <typename T, typename K>
    void Erase(const K& key)
    {
        if (T::sqldb_stmt_erase(stmt, key)) {
            if (SQLITE_DONE != sqlite3_step(stmt)) {
                throw CSqlException(db, "Commit error");
            }
            sqlite3_clear_bindings(stmt);
            sqlite3_reset(stmt);
        }
    }

protected:
    virtual void Commit()
    {
        assert(!commited);

        CSqlException::ExecuteAndThrow(db, "COMMIT");
        commited = true;
    }

    bool commited;
    mutable sqlite3 *db;
    mutable sqlite3_stmt *stmt;
};

class CSqlDBWrapper final
{
    friend class CSqlDBBatch;

public:
    CSqlDBWrapper(const fs::path& path, bool fMemory = false) : db(NULL)
    {
        int rc = sqlite3_open(fMemory ? ":memory:" : path.c_str(), &db);
        if (rc != SQLITE_OK) {
            throw CSqlException(db, "ERROR opening SQLite DB");
        }
    }

    ~CSqlDBWrapper()
    {
        if (db) {
            sqlite3_close(db);
            db = NULL;
        }
    }

    bool WriteBatch(CSqlDBBatch& batch)
    {
        batch.Commit();
        return true;
    }

    void Execute(const std::string &sql)
    {
        CSqlException::ExecuteAndThrow(db, sql);
    }

private:
    mutable sqlite3* db;
};

#endif // BITCOIN_DBWRAPPER_SQL_H