// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>

#include <base58.h>
#include <consensus/consensus.h>
#include <pubkey.h>
#include <random.h>
#include <script/standard.h>

bool CCoinsView::GetCoin(const COutPoint &outpoint, Coin &coin) const { return false; }
uint256 CCoinsView::GetBestBlock() const { return uint256(); }
std::vector<uint256> CCoinsView::GetHeadBlocks() const { return std::vector<uint256>(); }
bool CCoinsView::BatchWrite(CCoinsMap &mapCoins, CAccountDiffCoinsMap &mapAccountDiffCoins, const uint256 &hashBlock) { return false; }
CCoinsViewCursor *CCoinsView::Cursor() const { return nullptr; }
CAmount CCoinsView::GetAccountBalance(const CAccountId &nAccountId, int nHeight) const { return 0; }

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
bool CCoinsViewBacked::BatchWrite(CCoinsMap &mapCoins, CAccountDiffCoinsMap &mapAccountDiffCoins, const uint256 &hashBlock) { return base->BatchWrite(mapCoins, mapAccountDiffCoins, hashBlock); }
CCoinsViewCursor *CCoinsViewBacked::Cursor() const { return base->Cursor(); }
size_t CCoinsViewBacked::EstimateSize() const { return base->EstimateSize(); }
CAmount CCoinsViewBacked::GetAccountBalance(const CAccountId &nAccountId, int nHeight) const { return base->GetAccountBalance(nAccountId, nHeight); }

SaltedOutpointHasher::SaltedOutpointHasher() : k0(GetRand(std::numeric_limits<uint64_t>::max())), k1(GetRand(std::numeric_limits<uint64_t>::max())) {}

CCoinsViewCache::CCoinsViewCache(CCoinsView *baseIn) : CCoinsViewBacked(baseIn), cachedCoinsUsage(0) {}

size_t CCoinsViewCache::DynamicMemoryUsage() const {
    return memusage::DynamicUsage(cacheCoins) + cachedCoinsUsage + memusage::DynamicUsage(cacheAccountDiffCoins);
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

void CCoinsViewCache::AddCoin(int nHeight, const COutPoint &outpoint, Coin&& coin, bool possible_overwrite) {
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
    it->second.flags |= CCoinsCacheEntry::DIRTY | (fresh ? CCoinsCacheEntry::FRESH : 0);
    cachedCoinsUsage += it->second.coin.DynamicMemoryUsage();

    // Add coin
    CAccountDiffCoinsValue &diffCoinsValue = cacheAccountDiffCoins[nHeight][GetAccountIdByScriptPubKey(it->second.coin.out.scriptPubKey)];
    diffCoinsValue.nDiffCoins += it->second.coin.out.nValue;
    CAmount &coinAudit = diffCoinsValue.vAudit[outpoint];
    if (coinAudit > 0) {
        // Replace coin
        diffCoinsValue.nDiffCoins -= coinAudit;
        coinAudit = 0;
    }
    coinAudit += it->second.coin.out.nValue;
}

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, bool check) {
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();
    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Always set the possible_overwrite flag to AddCoin for coinbase txn, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        cache.AddCoin(nHeight, COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);
    }
}

bool CCoinsViewCache::SpendCoin(int nHeight, const COutPoint &outpoint, Coin* moveout) {
    CCoinsMap::iterator it = FetchCoin(outpoint);
    if (it == cacheCoins.end()) return false;

    // Spent coin
    CAccountDiffCoinsValue &diffCoinsValue = cacheAccountDiffCoins[nHeight][GetAccountIdByScriptPubKey(it->second.coin.out.scriptPubKey)];
    diffCoinsValue.nDiffCoins -= it->second.coin.out.nValue;
    CAmount &coinAudit = diffCoinsValue.vAudit[outpoint];
    if (coinAudit < 0) {
        // Has spend
        diffCoinsValue.nDiffCoins -= coinAudit;
        coinAudit = 0;
    }
    coinAudit -= it->second.coin.out.nValue;

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

bool CCoinsViewCache::BatchWrite(CCoinsMap &mapCoins, CAccountDiffCoinsMap &mapAccountDiffCoins, const uint256 &hashBlockIn) {
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

    // Merge account coin changes
    for (auto itHeight = mapAccountDiffCoins.begin(); itHeight != mapAccountDiffCoins.end(); itHeight = mapAccountDiffCoins.erase(itHeight)) {
        for (auto itAccount = itHeight->second.begin(); itAccount != itHeight->second.end(); itAccount++) {
            CAccountDiffCoinsValue &diffIn = itAccount->second;
            CAccountDiffCoinsValue &diffOut = cacheAccountDiffCoins[itHeight->first][itAccount->first];
            for (auto itAudit = diffIn.vAudit.begin(); itAudit != diffIn.vAudit.end(); itAudit = diffIn.vAudit.erase(itAudit)) {
                diffOut.vAudit[itAudit->first] += itAudit->second;
            }
            diffOut.nDiffCoins += diffIn.nDiffCoins;
        }
    }

    hashBlock = hashBlockIn;
    return true;
}

CAmount CCoinsViewCache::GetAccountBalance(const CAccountId &nAccountId, int nHeight) const {
    CAmount nCacheAmountDiff = 0;
    for (auto itHeight = cacheAccountDiffCoins.begin(); itHeight != cacheAccountDiffCoins.end(); itHeight++) {
        if (itHeight->first <= nHeight) {
            auto itAccount = itHeight->second.find(nAccountId);
            if (itAccount != itHeight->second.end()) {
                nCacheAmountDiff += itAccount->second.nDiffCoins;
            }
        }
    }

    return std::max(nCacheAmountDiff + base->GetAccountBalance(nAccountId, nHeight), (CAmount) 0);
}

bool CCoinsViewCache::Flush() {
    bool fOk = base->BatchWrite(cacheCoins, cacheAccountDiffCoins, hashBlock);
    cacheCoins.clear();
    cacheAccountDiffCoins.clear();
    cachedCoinsUsage = 0;
    return fOk;
}

void CCoinsViewCache::Uncache(const COutPoint& outpoint)
{
    CCoinsMap::iterator it = cacheCoins.find(outpoint);
    if (it != cacheCoins.end() && it->second.flags == 0) {
        cachedCoinsUsage -= it->second.coin.DynamicMemoryUsage();
        cacheCoins.erase(it);

        // Erase coin
        for (auto itHeight = cacheAccountDiffCoins.begin(); itHeight != cacheAccountDiffCoins.end();) {
            auto &mapAccountDiff = itHeight->second;
            for (auto itAccount = mapAccountDiff.begin(); itAccount != mapAccountDiff.end();) {
                auto &accountDiff = itAccount->second;
                auto itAudit = accountDiff.vAudit.find(outpoint);
                if (itAudit != accountDiff.vAudit.end()) {
                    accountDiff.nDiffCoins -= itAudit->second;
                    accountDiff.vAudit.erase(itAudit);
                    if (accountDiff.vAudit.empty()) {
                        // Remove empty coin
                        assert(accountDiff.nDiffCoins == 0);
                        itAccount = mapAccountDiff.erase(itAccount);
                        continue;
                    }
                }

                itAccount++;
            }

            if (mapAccountDiff.empty()) {
                // Remove empty item
                itHeight = cacheAccountDiffCoins.erase(itHeight);
            } else {
                itHeight++;
            }
        }
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

namespace {

class CAccountIdVisitor : public boost::static_visitor<bool> {
private:
    CAccountId *nAccountId;

public:
    explicit CAccountIdVisitor(CAccountId *nAccountIdIn) { nAccountId = nAccountIdIn; }

    bool operator()(const CNoDestination&) const {
        *nAccountId = 0;
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        *nAccountId = 0;
        return false;
    }

    bool operator()(const CScriptID &scriptID) const {
        return ToId(scriptID.begin(), scriptID.end());
    }

    bool operator()(const WitnessV0KeyHash &id) const {
        *nAccountId = 0;
        return false;
    }

    bool operator()(const WitnessV0ScriptHash &id) const {
        *nAccountId = 0;
        return false;
    }

    bool operator()(const WitnessUnknown &id) const {
       *nAccountId = 0;
        return false;
    }

private:
    template <typename T>
    bool ToId(const T begin, const T end) const
    {
        if (end - begin >= 8) {
            *nAccountId = ((uint64_t)begin[0]) |
                          ((uint64_t)begin[1]) << 8 |
                          ((uint64_t)begin[2]) << 16 |
                          ((uint64_t)begin[3]) << 24 |
                          ((uint64_t)begin[4]) << 32 |
                          ((uint64_t)begin[5]) << 40 |
                          ((uint64_t)begin[6]) << 48 |
                          ((uint64_t)begin[7]) << 56;
            return true;
        } else {
            *nAccountId = 0;
            return false;
        }
    }
};

}

CAccountId GetAccountIdByScriptPubKey(const CScript &scriptPubKey) {
    CTxDestination dest;
    if (ExtractDestination(scriptPubKey, dest)) {
        return GetAccountIdByTxDestination(dest);
    } else {
        return 0;
    }
}

CAccountId GetAccountIdByTxDestination(const CTxDestination &dest) {
    CAccountId nAccountId;
    boost::apply_visitor(CAccountIdVisitor(&nAccountId), dest);
    return nAccountId;
}

CAccountId GetAccountIdByAddress(const std::string &address) {
    CTxDestination dest = DecodeDestination(address);
    if (IsValidDestination(dest)) {
        return GetAccountIdByTxDestination(dest);
    } else {
        return 0;
    }
}