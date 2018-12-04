// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <chainparams.h>
#include <consensus/consensus.h>
#include <pubkey.h>
#include <random.h>
#include <script/script.h>

bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return false; }
CCoinsViewCursor *CCoinsView::Cursor() const { return nullptr; }
CAmount CCoinsView::GetBalance(const CAccountID &accountID, const CCoinsMap &mapModifiedCoins,
        CAmount *pLockInBindIdBalance, CAmount *pLockInRentCreditBalance, CAmount *pRentDebitBalance) const {
    if (pLockInBindIdBalance != nullptr) *pLockInBindIdBalance = 0;
    if (pLockInRentCreditBalance != nullptr) *pLockInRentCreditBalance = 0;
    if (pRentDebitBalance != nullptr) *pRentDebitBalance = 0;
    return 0;
}

bool CCoinsView::HaveCoin(const COutPoint &outpoint) const
{
    Coin coin;
    return GetCoin(outpoint, coin);
}

CCoinsViewBacked::CCoinsViewBacked(CCoinsView *viewIn) : base(viewIn) { }
bool CCoinsViewBacked::GetCoin(const COutPoint &outpoint, Coin &coin) const { return base->GetCoin(outpoint, coin); }
bool CCoinsViewBacked::HaveCoin(const COutPoint &outpoint) const { return base->HaveCoin(outpoint); }
uint256 CCoinsViewBacked::GetBestBlock() const { return base->GetBestBlock(); }
std::vector<uint256> CCoinsViewBacked::GetHeadBlocks() const { return base->GetHeadBlocks(); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) { return base->BatchWrite(mapCoins, hashBlock); }
CCoinsViewCursor *CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }
CAmount CCoinsViewBacked::GetBalance(const CAccountID &accountID, const CCoinsMap &mapModifiedCoins,
        CAmount *pLockInBindIdBalance, CAmount *pLockInRentCreditBalance, CAmount *pRentDebitBalance) const {
    return base->GetBalance(accountID, mapModifiedCoins, pLockInBindIdBalance, pLockInRentCreditBalance, pRentDebitBalance);
}

SaltedOutpointHasher::SaltedOutpointHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn) : CCoinsViewBacked(baseIn), cachedCoinsUsage(0) {}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage;
}

CCoinsMap::iterator CCoinsViewCache::FetchCoin(const COutPoint &outpoint) const {
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end())
        return it;
    Coin tmp;
    if (!base->GetCoin(outpoint, tmp))
        return cacheCoins.end();
    CCoinsMap::iterator ret = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::forward_as_tuple(std::move(tmp))).first;
    if (ret->second.coin.IsSpent()) {
        // The parent only has an empty entry for this outpoint; we can consider our
        // version as fresh.
        ret->second.flags = CCoinsCacheEntry::FRESH;
    }
    cachedCoinsUsage += ret->second.coin.DynamicMemoryUsage();
    return ret;
}

bool CCoinsViewCache::GetCoin(const COutPoint &outpoint, Coin &coin) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it != cacheCoins.end()) {
        coin = it->second.coin;
        return !coin.IsSpent();
    }
    return false;
}

void CCoinsViewCache::AddCoin(const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
    assert(!coin.IsSpent());
    if (coin.out.scriptPubKey.IsUnspendable()) return;
    CCoinsMap::iterator it;
    bool inserted;
    std::tie(it, inserted) = cacheCoins.emplace(std::piecewise_construct, std::forward_as_tuple(outpoint), std::tuple<>());
    bool fresh = false;
    if (!inserted) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    }
    if (!possible_overwrite) {
        if (!it->second.coin.IsSpent()) {
            throw std::logic_error("Adding new coin that replaces non-pruned entry");
        }
        fresh = !(it->second.flags & CCoinsCacheEntry::DIRTY);
    }
    it->second.coin = std::move(coin);
    it->second.coin.refOut.accountID = GetAccountIDByScriptPubKey(it->second.coin.out.scriptPubKey);
    it->second.coin.refOut.value = it->second.coin.out.nValue;
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check) {
    CoinExtraData extraData;
    bool fHaveExtraData = GetTransactionExtraData(tx, nHeight, extraData);

    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Always set the possible_overwrite flag to AddCoin for coinbase txn, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        if (i == 0 && fHaveExtraData) {
            assert(extraData.protocolId != 0);
            Coin coin(tx.vout[i], nHeight, fCoinbase);
            coin.extraData = extraData;
            cache.AddCoin(COutPoint(txid, i), std::move(coin), overwrite);
        } else {
            cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
        }
    }
}

bool CCoinsViewCache::SpendCoin(const COutPoint &outpoint, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;
    cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
    if (moveout) {
        *moveout = std::move(it->second.coin);
    }
    if (it->second.flags & CCoinsCacheEntry::FRESH) {
        cacheCoins.erase(it);
    } else {
        it->second.flags |= CCoinsCacheEntry::DIRTY;
        it->second.coin.Clear();
    }
    return true;
}

static const Coin coinEmpty;

const Coin& CCoinsViewCache::AccessCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) {
        return coinEmpty;
    } else {
        return it->second.coin;
    }
}

bool CCoinsViewCache::HaveCoin(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = FetchCoin(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

bool CCoinsViewCache::HaveCoinInCache(const COutPoint &outpoint) const {
    CCoinsMap::const_iterator it = cacheCoins.find(outpoint);
    return (it != cacheCoins.end() && !it->second.coin.IsSpent());
}

uint256 CCoinsViewCache::GetBestBlock() const {
    if (hashBlock.IsNull())
        hashBlock = base->GetBestBlock();
    return hashBlock;
}

void CCoinsViewCache::SetBestBlock(const uint256 &hashBlockIn) {
    hashBlock = hashBlockIn;
}

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlockIn) {
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end(); it = mapCoins.erase(it)) {
        // Ignore non-dirty entries (optimization).
        if (!(it->second.flags & CCoinsCacheEntry::DIRTY)) {
            continue;
        }
        CCoinsMap::iterator itUs = cacheCoins.find(it->first);
        if (itUs == cacheCoins.end()) {
            // The parent cache does not have an entry, while the child does
            // We can ignore it if it's both FRESH and pruned in the child
            if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent())) {
                // Otherwise we will need to create it in the parent
                // and move the data up and mark it as dirty
                CCoinsCacheEntry& entry = cacheCoins[it->first];
                entry.coin = std::move(it->second.coin);
                cachedCoinsUsage += entry.coin.DynamicMemoryUsage();
                entry.flags = CCoinsCacheEntry::DIRTY;
                // We can mark it FRESH in the parent if it was FRESH in the child
                // Otherwise it might have just been flushed from the parent's cache
                // and already exist in the grandparent
                if (it->second.flags & CCoinsCacheEntry::FRESH) {
                    entry.flags |= CCoinsCacheEntry::FRESH;
                }
            }
        } else {
            // Assert that the child cache entry was not marked FRESH if the
            // parent cache entry has unspent outputs. If this ever happens,
            // it means the FRESH flag was misapplied and there is a logic
            // error in the calling code.
            if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent()) {
                throw std::logic_error("FRESH flag misapplied to cache entry for base transaction with spendable outputs");
            }

            // Found the entry in the parent cache
            if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent()) {
                // The grandparent does not have an entry, and the child is
                // modified and being pruned. This means we can just delete
                // it from the parent.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                cacheCoins.erase(itUs);
            } else {
                // A normal modification.
                cachedCoinsUsage -= itUs->second.coin.DynamicMemoryUsage();
                itUs->second.coin = std::move(it->second.coin);
                cachedCoinsUsage += itUs->second.coin.DynamicMemoryUsage();
                itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                // NOTE: It is possible the child has a FRESH flag here in
                // the event the entry we found in the parent is pruned. But
                // we must not copy that FRESH flag to the parent as that
                // pruned state likely still needs to be communicated to the
                // grandparent.
            }
        }
    }

    hashBlock = hashBlockIn;
    return true;
}

CAmount CCoinsViewCache::GetBalance(const CAccountID &accountID, const CCoinsMap &mapModifiedCoins,
        CAmount *pLockInBindIdBalance, CAmount *pLockInRentCreditBalance, CAmount *pRentDebitBalance) const {
    // Invalid account ID
    if (accountID == 0) {
        if (pLockInBindIdBalance != nullptr) *pLockInBindIdBalance = 0;
        if (pLockInRentCreditBalance != nullptr) *pLockInRentCreditBalance = 0;
        if (pRentDebitBalance != nullptr) *pRentDebitBalance = 0;
        return 0;
    }

    if (cacheCoins.empty()) {
        return base->GetBalance(accountID, mapModifiedCoins, pLockInBindIdBalance, pLockInRentCreditBalance, pRentDebitBalance);
    } else if (mapModifiedCoins.empty()) {
        return base->GetBalance(accountID, cacheCoins, pLockInBindIdBalance, pLockInRentCreditBalance, pRentDebitBalance);
    } else {
        assert(&mapModifiedCoins != &cacheCoins);

        CCoinsMap tempUsCoinsMap;
        // Copy current CCoinsMap
        for (CCoinsMap::const_iterator it = cacheCoins.cbegin(); it != cacheCoins.cend(); it++) {
            if (it->second.coin.refOut.accountID == accountID)
                tempUsCoinsMap[it->first] = it->second;
        }
        if (tempUsCoinsMap.empty()) {
            return base->GetBalance(accountID, mapModifiedCoins, pLockInBindIdBalance, pLockInRentCreditBalance, pRentDebitBalance);
        } else {
            // Merge CCoinsMap. See CCoinsViewCache::BatchWrite()
            for (CCoinsMap::const_iterator it = mapModifiedCoins.cbegin(); it != mapModifiedCoins.cend(); it++) {
                if (!(it->second.flags & CCoinsCacheEntry::DIRTY) || it->second.coin.refOut.accountID != accountID) {
                    continue;
                }
                CCoinsMap::iterator itUs = tempUsCoinsMap.find(it->first);
                if (itUs == tempUsCoinsMap.end()) {
                    if (!(it->second.flags & CCoinsCacheEntry::FRESH && it->second.coin.IsSpent())) {
                        CCoinsCacheEntry& entry = tempUsCoinsMap[it->first];
                        entry.coin = it->second.coin;
                        entry.flags = CCoinsCacheEntry::DIRTY;
                        if (it->second.flags & CCoinsCacheEntry::FRESH) {
                            entry.flags |= CCoinsCacheEntry::FRESH;
                        }
                    }
                } else {
                    if ((it->second.flags & CCoinsCacheEntry::FRESH) && !itUs->second.coin.IsSpent()) {
                        throw std::logic_error("FRESH flag misapplied to cache entry for base transaction with spendable outputs");
                    }
                    if ((itUs->second.flags & CCoinsCacheEntry::FRESH) && it->second.coin.IsSpent()) {
                        tempUsCoinsMap.erase(itUs);
                    } else {
                        itUs->second.coin = it->second.coin;
                        itUs->second.flags |= CCoinsCacheEntry::DIRTY;
                    }
                }
            }
            return base->GetBalance(accountID, tempUsCoinsMap, pLockInBindIdBalance, pLockInRentCreditBalance, pRentDebitBalance);
        }
    }
}

CAmount CCoinsViewCache::GetAccountBalance(const CAccountID &accountID, CAmount *pLockInBindIdBalance, CAmount *pLockInRentCreditBalance, CAmount *pRentDebitBalance) const {
    // Merge with base cache coins and calculate balance
    return base->GetBalance(accountID, cacheCoins, pLockInBindIdBalance, pLockInRentCreditBalance, pRentDebitBalance);
}

bool CCoinsViewCache::Flush() {
    bool fOk = base->BatchWrite(cacheCoins, hashBlock);
    cacheCoins.clear();
    cachedCoinsUsage = 0;
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& outpoint)
{
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end() && it->second.flags == 0) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        cacheCoins.erase(it);
    }
}

unsigned int CCoinsViewCache::GetCacheSize() const {
    return cacheCoins.size();
}

CAmount CCoinsViewCache::GetValueIn(const CTransaction& tx) const
{
    if (tx.IsCoinBase())
        return 0;

    CAmount nResult = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        nResult += AccessCoin(tx.vin[i].prevout).out.nValue;

    return nResult;
}

bool CCoinsViewCache::HaveInputs(const CTransaction& tx) const
{
    if (!tx.IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!HaveCoin(tx.vin[i].prevout)) {
                return false;
            }
        }
    }
    return true;
}

static const size_t MIN_TRANSACTION_OUTPUT_WEIGHT = WITNESS_SCALE_FACTOR * ::GetSerializeSize(CTxOut(), SER_NETWORK, PROTOCOL_VERSION);
static const size_t MAX_OUTPUTS_PER_BLOCK = MAX_BLOCK_WEIGHT / MIN_TRANSACTION_OUTPUT_WEIGHT;

const Coin& AccessByTxid(const CCoinsViewCache& view, const uint256& txid)
{
    COutPoint iter(txid, 0);
    while (iter.n < MAX_OUTPUTS_PER_BLOCK) {
        const Coin& alternate = view.AccessCoin(iter);
        if (!alternate.IsSpent()) return alternate;
        ++iter.n;
    }
    return coinEmpty;
}

bool GetTransactionExtraData(const CTransaction& tx, int nHeight, CoinExtraData &extraData, CScriptID *pAssocScriptID)
{
    if (tx.IsCoinBase() || tx.vout.size() < 2 || tx.vout.size() > 3 || tx.vout[0].scriptPubKey.IsUnspendable() || nHeight < Params().GetConsensus().BHDIP1010Height)
        return false;

    // OP_RETURN 0x04 <ProtocolID> <CustomData>
    const CScript &script = tx.vout[tx.vout.size()-1].scriptPubKey;
    if (script.size() < 6 || script[0] != OP_RETURN || script[1] != 0x04)
        return false;
    CScript::const_iterator pc = script.begin() + 1;
    opcodetype opcode;

    // Get data protocol ID
    unsigned int protocolId;
    {
        std::vector<unsigned char> protocolIdBytes;
        if (!script.GetOp(pc, opcode, protocolIdBytes) || opcode != 0x04 || opcode != protocolIdBytes.size())
            return false;
        protocolId = (protocolIdBytes[0] << 0) | (protocolIdBytes[1] << 8) | (protocolIdBytes[2] << 16) | (protocolIdBytes[3] << 24);
    }

    if (protocolId == OPRETURN_PROTOCOLID_BINDID) {

    } else if (protocolId == OPRETURN_PROTOCOLID_RENT) {
        if (script.size() != 27)
            return false;
        std::vector<unsigned char> destBytes;
        if (!script.GetOp(pc, opcode, destBytes) || opcode != 0x14 || opcode != destBytes.size())
            return false;
        CTxDestination dest = CScriptID(uint160(destBytes));
        extraData.debitAccountID = GetAccountIDByTxDestination(dest);
        if (extraData.debitAccountID == 0) {
            return false;
        }
        extraData.protocolId = protocolId;

        if (pAssocScriptID != nullptr) *pAssocScriptID = *(boost::get<CScriptID>(&dest));
        return true;
    }

    return false;
}