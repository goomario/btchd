// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <chainparamsseeds.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <poc/poc.h>
#include <script/interpreter.h>
#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <cassert>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint64_t nNonce, uint64_t nBaseTarget, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(2);
    txNew.vin[0].scriptSig = CScript() << static_cast<unsigned int>(0)
        << CScriptNum(static_cast<int64_t>(nNonce)) << CScriptNum(static_cast<int64_t>(0))
        << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;
    txNew.vout[1].nValue = 0;
    txNew.vout[1].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime       = nTime;
    genesis.nBaseTarget = nBaseTarget;
    genesis.nNonce      = nNonce;
    genesis.nVersion    = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=8cec494f7f02ad, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=6b80acabaf0fef, nTime=1531292789, nBaseTarget=18325193796, nNonce=0, vtx=1)
 *   CTransaction(hash=6b80acabaf0fef, ver=1, vin.size=1, vout.size=2, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=25.00000000, scriptPubKey=0x2102CD2103A86877937A05)
 *     CTxOut(nValue=00.00000000, scriptPubKey=0x2102CD2103A86877937A05)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint64_t nNonce, uint64_t nBaseTarget, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("02cd2103a86877937a05eff85cf487424b52796542149f2888f9a17fbe6d66ce9d") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBaseTarget, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";

        consensus.BHDFundAddress = "32B86ghqRTJkh2jvyhRWFugX7YWoqHPqVE";
        // See https://btchd.org/wiki/fund-address-pool
        consensus.BHDFundAddressPool = {
            "3F26JRhiGjc8z8pRKJvLXBEkdE6nLDAA3y", //!< 0x20000000, Deprecated!. Last use on v1.1.0.1-30849da
            "32B86ghqRTJkh2jvyhRWFugX7YWoqHPqVE", //!< 0x20000004, 0x20000000
            "39Vb1GNSurGoHcQ4aTKrTYC1oNmPppGea3",
            "3Maw3PdwSvtXgBKJ9QPGwRSQW8AgQrGK3W",
            "3Hy3V3sPVpuQaG6ttihfQNh4vcDXumLQq9",
            "3MxgS9jRcGLihAtb9goAyD1QC8AfRNFE1F",
            "3A4uNFxQf6Jo8b6QpBVnNcjDRqDchgpGbR",
        };
        assert(consensus.BHDFundAddressPool.find(consensus.BHDFundAddress) != consensus.BHDFundAddressPool.end());

        consensus.BHDIP001StartMingingHeight = 84000 + 1; // 21M * 10% = 2.1M, 2.1M/25=84000, + 1 to deprecated test data
        consensus.BHDIP001FundRoyaltyPercent = 5; // 5%
        consensus.BHDIP001FundRoyaltyPercentOnLowPledge = 70; // 70%
        consensus.BHDIP001NoPledgeHeight = consensus.BHDIP001StartMingingHeight + 8640; // End 1 month after 30 * 24 * 60 / 5 = 8640
        consensus.BHDIP001PledgeAmountPerTB = 3 * COIN;

        consensus.nSubsidyHalvingInterval = 420000;
        consensus.nCapacityEvalWindow = 2016;
        consensus.fPocAllowMinDifficultyBlocks = false;
        consensus.nPowTargetSpacing = 5 * 60;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016;

        consensus.BIP16Height = 0; // Always enforce BIP16
        consensus.BIP34Height = 0; // Always enforce BIP34
        consensus.BIP65Height = 0; // Always enforce BIP65
        consensus.BIP66Height = 0; // Always enforce BIP66

        consensus.BHDIP004ActiveHeight = 96264; // BHDIP004. BitcoinHD new consensus upgrade bug. 96264 is first invalid block
        consensus.BHDIP004InActiveHeight = 99000;

        consensus.BHDIP006Height = 129100; // BHDIP006. Actived on Wed, 02 Jan 2019 02:17:19 GMT
        consensus.BHDIP006BindPlotterActiveHeight = consensus.BHDIP006Height + consensus.nCapacityEvalWindow; // BHDIP006. Bind plotter actived at 131116 and Tue, 08 Jan 2019 23:14:57 GMT
        consensus.BHDIP006CheckRelayHeight = 133000; // BHDIP006. Bind/unbind plotter limit. Active at 133000 about when Tue, 15 Jan 2019 11:00:00 GMT
        consensus.BHDIP006LimitBindPlotterHeight = 134650; // BHDIP006. Bind plotter limit. Active at 134100 about when Tue, 21 Jan 2019 9:00:00 GMT

        // Require signing block by miner
        consensus.BHDIP007Height = 1600000; // BHDIP007. NOT SURE ACTIVATE TIME

        // TestDummy
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000007dc6bb82d969e06301");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x65994104a989a60a1d55f27528878b7d02642ec5a4e84c9497a79ce47eafda7c"); // 157000

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xe5;
        pchMessageStart[1] = 0xba;
        pchMessageStart[2] = 0xb0;
        pchMessageStart[3] = 0xd5;
        nDefaultPort = 8733;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1531292789, 0, poc::INITIAL_BASE_TARGET, 2, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x8cec494f7f02ad25b3abf418f7d5647885000e010c34e16c039711e4061497b0"));
        assert(genesis.hashMerkleRoot == uint256S("0x6b80acabaf0fef45e2cad0b8b63d07cff1b35640e81f3ab3d83120dd8bc48164"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they dont support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.push_back("seed0-chain.btchd.net");
        vSeeds.push_back("seed1-chain.btchd.net");
        vSeeds.push_back("seed2-chain.btchd.net");
        vSeeds.push_back("seed3-chain.btchd.net");
        vSeeds.push_back("seed4-chain.btchd.net");
        vSeeds.push_back("seed0-chain.btchd.org");
        vSeeds.push_back("seed1-chain.btchd.org");
        vSeeds.push_back("seed2-chain.btchd.org");
        vSeeds.push_back("seed3-chain.btchd.org");
        vSeeds.push_back("seed0-chain.btchd.info");
        vSeeds.push_back("seed0-chain.btchd.top");
        vSeeds.push_back("seed0-chain.btchd.pro");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {      0, uint256S("0x8cec494f7f02ad25b3abf418f7d5647885000e010c34e16c039711e4061497b0") },
                {   2000, uint256S("0x3e0ea5fc8f09808fc4ea0c7f2bd90bedd2de2ce6852882c82593c7aedc4ff5a4") },
                {   4000, uint256S("0xa9406ac6837fcb59d1549c8a9e9623530c82c9a69b426a8ce5e8b61bb1ae349e") },
                {   8000, uint256S("0xec2455cb8fede24bb2de7993de20d79a25a4e5936d773b72efff711890538b6c") },
                {  10000, uint256S("0x5345016cec4d0d9458990ca12384371e0ae61e140aa85e1e995db7d51b57c42a") },
                {  16000, uint256S("0x378156abc134017c11ae94f5758854b629c05050030f42834813d6d7530ade2f") },
                {  22000, uint256S("0x2f6e0be78a4f6d13917c6d3811faff36dab7578e4c38c5d56ef0054e54c05316") },
                {  30000, uint256S("0x484b7cb499004f1ca0ef8e2fccb4c4fcd3535196a7ac45b2e82adbfebd3dda78") },
                {  40000, uint256S("0x00fb659ebbf0e396d3c28cdcea2dc86c0464c8240b4527cd71d64b975bf09995") },
                {  50000, uint256S("0xcc3008bac1014bd11bf0e5ee15c5e3221af9ab396bf546b873dac13de5f2184e") },
                {  60000, uint256S("0xb01923d8ea4c6c8d1830bdd922841246dc994b64867c8b0113ff8f17e46918e4") },
                {  70000, uint256S("0x464a90f3e349e9066847dfb377e11b994b412407ba8ca00c34e330278db8383e") },
                {  80000, uint256S("0x4a6f5a5c944105a70aaba7e64c5a7c8f4fc4f3759ac8af423c824db8c89f7482") },
                {  84001, uint256S("0xa474cb4eeca85ada0f4600b1d6fe656bb09c88328e00c3fcccc0136f2c360e94") },
                // Offset +1000. Sync batch by 1000
                {  85000, uint256S("0xaaeb335da849331f43e7808611f38e630ffbb2726ba131181ba72ac8d58a2da3") },
                {  86000, uint256S("0xe4fabbdcef187186ae1f1cc32ef8ec2fa22025c0f38a8a4cb0a89118ba34f75b") },
                {  87000, uint256S("0xf045373bf308043b5e3aff3fffa76e72290c2e433574b1a27a4ad34cab3f12bd") },
                {  88000, uint256S("0x24928cd2154d1546930e5a6ac4f7828dc40fca3dadfc31ce8fa8caea6cfb5401") },
                {  89000, uint256S("0x4cc9894182dc2ea2bc5d7c94ac9a653ebbf0914898cadda126085d046d9e90bb") },
                {  90000, uint256S("0x7acd0596d0a5b97c036fa705e08ea636b07e5dc004d8171d2a02955fae12ddde") },
                {  91000, uint256S("0xd9eb11eb97e95b84a416f65feda01cdc134b4bba7c206e22ba03bd623e29dd16") },
                {  92000, uint256S("0xfe0f3540c630cde2afc5e5081a4aec25ea43a57e1bf603e403054e218a3dc9cf") },
                {  93000, uint256S("0x821d1ca35a7b8812f36f387216f0eea83cafcaa7191b4c0308e27cf8356abc1f") },
                {  94000, uint256S("0x7dd832ac7da06f01cf8db0e6e9917dab12e37d009f7369cff00c0484cdd42a22") },
                {  95000, uint256S("0x728178b9cea6f448c31c27edec58bcb082c1bee798f6367e4e246c361c106464") },
                {  96000, uint256S("0x18ada0a6fbd634489a4b05318731035fa048bdbb381084b10071107b3790dd3b") },
                {  97000, uint256S("0x049777c7f4ad62da817a4076b11ad9c3fe15c4310a43cfeb246cc3982c7cf2ca") },
                {  98000, uint256S("0x3f1068eb2eb9a6b1a2e3a93ef74a34c59fefe0d0e48b6d1f458bc562a8c83a05") },
                {  99000, uint256S("0x85f44668b874c3d54c3db34b5779648c7a110a402245c218b5b913f414442a67") },
                { 100000, uint256S("0x5ef9b2dae9a7aceac25c5229225a64e49a493435ed0ecbe6baf92a6496515931") },
                { 101000, uint256S("0xec5c821be5b16d509f4c29bc9620461768808e5ae40a7b3eb6a7ca260801f939") },
                { 102000, uint256S("0x90a77896d7c1ac9c52504c5779f4b070530cd4de8047babe443de4c71feef0e4") },
                { 103000, uint256S("0xfcc8b4afb2c6bf51132b1bf7c45e19015b4e54d2aed6d0f9afe61a314edf1a1a") },
                { 104000, uint256S("0xf89deb06a14ebde24cfaf1ff4fb0f545f59a7940e660d498f6c306c6c9b66cde") },
                { 105000, uint256S("0x27fdb3d2bce66669327e0d6522c2c9cde431491223b9b3e750e87c96279c8175") },
                { 106000, uint256S("0xf7dfa89a61703f561fbd30782328c03ea2721c2c2cda04046b872303468512ed") },
                { 107000, uint256S("0xe981b196881cc881a799489c5debb101beabc141b7f3b71c22cd64cd01277cca") },
                { 108000, uint256S("0xd7c1c6d6d019ebe460d4bef7f3dc2fd2a4375462eff574560343d47bf314161d") },
                { 109000, uint256S("0xb186f772f58dabb20be41c0d533944ff739125241648babdc8ad427f04e5a594") },
                { 110000, uint256S("0xc3fa82d07a4ed51b347f3694ff144d654dbccc950092988df9f58aeb2b907dc8") },
                { 111000, uint256S("0xe9946732846962845b25d217aab72b87fbe8502fc4e83d2d45e30ef09daa3ff8") },
                { 112000, uint256S("0xfd78fbf7e6e6274919f12c384e46ea7f5e3ffc2c7a3828a35664622d06885667") },
                { 113000, uint256S("0xfa577eb0c02a6f81642a166791dace0d035515c1afaa2f071447d8c462ac88c8") },
                { 114000, uint256S("0xfe881b2ea8b7481e5233c80fc2d8394d7a5c29484275dd93bce8d0d375f458cf") },
                { 115000, uint256S("0x5f002fde0487f97652407b5976f309b7de0f95ddfc336a20e5896cdd7fe4906b") },
                { 116000, uint256S("0x5ea5ea3fe879a01ec7f2625cf68b1b703d2d7fcc7dbc9206b34b651ad6533f16") },
                { 117000, uint256S("0x83d9faee9a07dfaefcf28c36f6c5532598dc48bdda52617696c4a5455904bcab") },
                { 118000, uint256S("0xf640f20483939c0ca4bfea2c42bd11fb6c071e40dd415ed9895ea220c2a19e1c") },
                { 119000, uint256S("0x05c1edc9af0474d10c04457c7bb54f75a4d5e9e7432dabdef4ddd5581e9478db") },
                { 120000, uint256S("0x0b1ae104b516bbc4f19f4850c6bb499154387b391334ed7f0e93671e11530bbc") },
                { 121000, uint256S("0xde15e2e48e4c906d4de2f5d6ed40add4a3c023912fdf5b66be6cc5c5017e92fa") },
                { 122000, uint256S("0x5f60e469b8742068e56147d4e463723952e0395e196e255ad8941835459ad37e") },
                { 123000, uint256S("0xb503ab001307533401f96f28f53c4747479243a2314b363ca06477234ed29281") },
                { 124000, uint256S("0x3387babe46e9d70cb6fec1d8104b741070b86c7d96362b512026ccefe7546774") },
                { 125000, uint256S("0xebf85c414e8a830b1723ad9f7a86206e2254089b273ecaac7a0fc8dbb35dc0e1") },
                { 126000, uint256S("0xb4a81eb95d4ea3028b489bd77b045c4278058a6889558967949b4694967302c6") },
                { 127000, uint256S("0x323e69f9713a0d5c0a83427e70e4fa5c5e2693cc8ee0e5d4c4e91adb6f982633") },
                { 128000, uint256S("0x94ebf25c1db0e170e5d3c6529f2e453ce2edac11984ac9b94c1c61eda76d7d42") },
                { 129000, uint256S("0xc58f6d8bc07ca5e899440bf487474b09f4e139de83defb6b6f36b8e1c49954ec") },
                { 129100, uint256S("0xebbc8573080109747838beec06c2014f11327b7b7dc35eab8332a53efecf7f25") }, // BHDIP006 fork height
                { 130000, uint256S("0xfea47141ac2ab697b33ceb3ee71cbca42c8aa93115f301ca69fd21d7ab2f65f5") },
                { 131000, uint256S("0x9452748d6899f2bb16126c1377e91309aabf0b0645106c26b0959bc0912f7315") },
                { 132000, uint256S("0x35feb21020d8dc2674a811c5c23e8d85bd2d13339022c273c202986746c18636") },
                { 133000, uint256S("0xcdea9a2bfc267e7cc9d7e6d8c5606a5b7685c39eec4afba6e8a07bbafd776bac") }, // BHDIP006 unbind limit
                { 134000, uint256S("0x68dedaf2c309f2008ec63d19328547b598ec51989ab3be4106b3c1df4e2c1b77") },
                { 134650, uint256S("0x2c1d20602c660e0fc5bfae6d1bd6bf4a6fa9e2970e625b88275a3ef30b09b418") }, // BHDIP006 bind limit
                { 135000, uint256S("0x14698c428f50e6183cfc1af3f434c83c65681af6f8f83e9e6ef2e7ed5461ae67") },
                { 136000, uint256S("0xda9cdfbb86b88444abe8f4273f476c51c63b1eed61d819bbd98af3aa23241325") },
                { 137000, uint256S("0xc335e19ccd57f3b494ff474ff179ad0e782e825cea18ab46ad82f9a45ad94b24") },
                { 138000, uint256S("0x256edfe36cf331eafa31e6396038d15b5f2596b36bd62c7d58a5264479b6a634") },
                { 139000, uint256S("0xcc05217ab08a5dea6aa49808c46c401fc208e244f8590db9e0db72d18d902061") },
                { 140000, uint256S("0x4dcf1556b92576914bcbd6b79345892a46be3cac4014da8877dbedf0e868bcf5") },
                { 141000, uint256S("0x6efcb0df741c38788680fa738cc57775fa81c2aa2f6a3b05354fcbbcc896145d") },
                { 142000, uint256S("0x5b28060a28c9b374711d03298178c8a72ae2219bb7448ff6744a871afd913bc5") },
                { 143000, uint256S("0x9df7ff3439d4b164249a04ddf738d1f18a04f360648914585a78f7876dd017d3") },
                { 144000, uint256S("0x410a176bd881b5b10c138e5a1cc19323cba95354a56ed3bca13b9c7617b59525") },
                { 145000, uint256S("0x75c2a8338a6a4bdbbc3ca98b7395aeddb296e9dd41e94f822c577e9510c0af3f") },
                { 146000, uint256S("0x3175a4b96764360c7a833a42b0109e35effd467f0570fe6652b6bf7037ba6688") },
                { 147000, uint256S("0xd7ac27f028619bc9f0d55da5e618b6248a58bf5485f793775c67a1af73fba134") },
                { 148000, uint256S("0x3ea544f4c427f30826a3461c1289629fbb5acffda8bb780b52cc97548392b8f3") },
                { 149000, uint256S("0x8f0cc1e2f8712fad78585535447c7af71cf1f7d5cd254151fdfadb495d0c7ccb") },
                { 150000, uint256S("0xb1a59ed57b8d63b8f22c0778639ed83675e927338d9248023c9e18d512dfbdc8") },
                { 151000, uint256S("0x7e7eb55fae28b36fe72ba6b3af36998136d585f491f6eec4c92b8d8bf424c2d2") },
                { 152000, uint256S("0x09f2593a4b69c9e8c96961989caf7056ff7ecfb68bd6bc7b094ece2afb0e21c6") },
                { 153000, uint256S("0x3ae7b88e3c9fd78b1023aa7394820d476ceaf229f2b50b12a8a0f6287697246b") },
                { 154000, uint256S("0x28810c52d94b874222992567e0941c47a3463d01e0d1435e2f5b15699bc891ee") },
                { 155000, uint256S("0x0a2ab0a13df17f6fe30f32ee3dd846449eeaaf5fce40db70157683a23db50fee") },
                { 156000, uint256S("0x73ef83a58d52c335282d0e1211758d11b312e21ca17c96b5d4e54039846f3223") },
                { 157000, uint256S("0x65994104a989a60a1d55f27528878b7d02642ec5a4e84c9497a79ce47eafda7c") },
                { 157700, uint256S("0x8f7714d52edfa401f2cff73a3cd81e8a279a93c5fefe71283695127b12e968d4") },
            }
        };

        chainTxData = ChainTxData{
            // Call by getchaintxstats
            // Data as of block 13e58274799e45c18f61a3e2c561b79ab42c8a99fabe0aef6093c3a4173478bf (height 157747)
            1554960146, // * UNIX timestamp of last known number of transactions
            204217,     // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.00614     // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.BHDFundAddress = "2N3DHXpYQFZ6pNCUxNpHuTtaFQZJCmCKNBw";
        consensus.BHDFundAddressPool = { "2N3DHXpYQFZ6pNCUxNpHuTtaFQZJCmCKNBw" };
        assert(consensus.BHDFundAddressPool.find(consensus.BHDFundAddress) != consensus.BHDFundAddressPool.end());

        consensus.BHDIP001StartMingingHeight = 8400; // 21M * 1% = 0.21M, 0.21M/25=8400
        consensus.BHDIP001FundRoyaltyPercent = 5; // 5%
        consensus.BHDIP001FundRoyaltyPercentOnLowPledge = 70; // 70%
        consensus.BHDIP001NoPledgeHeight = consensus.BHDIP001StartMingingHeight + 4000;
        consensus.BHDIP001PledgeAmountPerTB = 3 * COIN;

        consensus.nSubsidyHalvingInterval = 420000;
        consensus.nCapacityEvalWindow = 2016;
        consensus.fPocAllowMinDifficultyBlocks = false;
        consensus.nPowTargetSpacing = 5 * 60;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016;

        consensus.BIP16Height = 0; // Always enforce BIP16
        consensus.BIP34Height = 0; // Always enforce BIP34
        consensus.BIP65Height = 0; // Always enforce BIP65
        consensus.BIP66Height = 0; // Always enforce BIP66

        consensus.BHDIP004ActiveHeight = 12400; // BHDIP004. BitcoinHD new consensus upgrade bug.
        consensus.BHDIP004InActiveHeight = 21000;

        consensus.BHDIP006Height = 41290; // BHDIP006
        consensus.BHDIP006BindPlotterActiveHeight = consensus.BHDIP006Height + 6; // BHDIP006. Bind plotter active at 41296
        consensus.BHDIP006CheckRelayHeight = consensus.BHDIP006BindPlotterActiveHeight + consensus.nCapacityEvalWindow * 2; // 45328
        consensus.BHDIP006LimitBindPlotterHeight = 48790;

        consensus.BHDIP007Height = 72550; // BHDIP007.

        // TestDummy
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000f7db2ebcfbdcbf");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x93065a3b4e43baf4b6dbba22c5cd560ce9c9c04310ed81b9519ef75d2d37cc4e"); // 72000

        pchMessageStart[0] = 0x1e;
        pchMessageStart[1] = 0x12;
        pchMessageStart[2] = 0xa0;
        pchMessageStart[3] = 0x08;
        nDefaultPort = 18733;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1531292789, 1, poc::INITIAL_BASE_TARGET, 2, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xb67faee747224b7646d66cd08763f33d72b594da8e884535c2f95904fe3cf8c1"));
        assert(genesis.hashMerkleRoot == uint256S("0xb8f17dd05a0d3fe40963d189ee0397ff909ce33bd1c9821898d2400b89ea75e6"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back("testnet-seed0-chain.btchd.net");
        vSeeds.push_back("testnet-seed1-chain.btchd.net");
        vSeeds.push_back("testnet-seed2-chain.btchd.net");
        vSeeds.push_back("testnet-seed3-chain.btchd.net");
        vSeeds.push_back("testnet-seed0-chain.btchd.org");
        vSeeds.push_back("testnet-seed1-chain.btchd.org");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {      0, uint256S("0xb67faee747224b7646d66cd08763f33d72b594da8e884535c2f95904fe3cf8c1") },
                {   2000, uint256S("0x13c8cd68809c554d883015b263bbe0b5ab19f3589ea659505e5e59c2aad7d32c") },
                {   4000, uint256S("0x1feebf8cd1458170c531fca3cc46baff57765ad2b61695b0a6ba28b9fd467fab") },
                {   6000, uint256S("0x13303b079c3c651c682096b419abbf610c06a87cb0bd5b2ddd638b1da5ccb29d") },
                {   8000, uint256S("0x070ef2c57440d016b0a97b005a18811d2396ca2aa9a5f2458e844ac4f86923a8") },
                {   8400, uint256S("0x9ceb8e7eaceba6d78d66b6561e60f0196e0580d2e708f0076578d99035def0e4") },
                // Offset +1000. Sync batch by 1000
                {   8600, uint256S("0x85328fd04bf8ece91dbb0e5d494059517a579c09e1c00cb1699aa832de42f825") },
                {   9000, uint256S("0xf6d498706e76904cf7404f0d701d542755713d8e238af3f2aeea5c228b0c4d79") },
                {  10000, uint256S("0x8912d6c4b3666e16db738c5b9253760da60140c6f6da4677c3c65a922c562981") },
                {  11000, uint256S("0x0437ad4d012411f2c2866aa6f7a57d87cdafe88b24eae2c4035b49e9621abbbb") },
                {  12000, uint256S("0xf274f4f16024e66139babad61b953f6e670dcc7ce729519013169491324afa42") },
                {  13000, uint256S("0x3d24ad7d4fb9e8aea19f53a8438c7ab8fb11057b95b0da667d61d826d567b22a") },
                {  14000, uint256S("0x225060edd20c722111a96eb7f1947a9cca58755f524fc8c23a6d64fe7fc5be92") },
                {  15000, uint256S("0x280971724545fa94d13d3d638cac4f7652e55ae83abf43f2b91d87a692cade35") },
                {  16000, uint256S("0x32e35edd797596ce166609b58f6ee6b920f8e60bfc7f4131f98ae21faa8398b7") },
                {  17000, uint256S("0x37df13069ca3e02d06cfd5f20a4895f2300a4bec851c5a28bcba3176fb6bcc5c") },
                {  18000, uint256S("0xd0b4e5638db1d664dffc561a6c4c9f6bf691c376a36ccbfc412418c4aee03df1") },
                {  19000, uint256S("0x0f8132de13286db54e4a8e4ea173af29c9b959dbbdcc206e674c56e6532406cf") },
                {  20000, uint256S("0xd886caeac8c821716d0cab7a1ffc58836eca7e24193c0fb7cdb0ccf0f08f8eea") },
                {  21000, uint256S("0x276c4ebfbecfd90b9cad397f78907604569f772c91c223247b6f3354e71b0dcd") },
                {  22000, uint256S("0x54ebf72c827700d162290d8369321266d78443d43387ed4dacc6bcc8e8dee61c") },
                {  23000, uint256S("0x0b0885eb92f712cf502c6adeef8e13e7b96c50cecc0e6f9972844be2cd66a578") },
                {  24000, uint256S("0xb0f1ce1964d04acc6e0ce02db2c1874b83811d973d025b95b8f927c94ba622d6") },
                {  25000, uint256S("0xb754a47f674d6489a9c0c2723912f98fb25fccc09c344eba7d7b9e175abd5284") },
                {  26000, uint256S("0xbacd9dcc2147915a3e84b0b24addad37c3f57c1cea01ea0483220effeac2ed0f") },
                {  27000, uint256S("0xbf6521f94f267e1a81dc479324340e5065c569f38449556be418e5b0909b9c44") },
                {  28000, uint256S("0xd119dc0c48a3071ea2e1522fa758e85717c9a19fbab7542b3890b3076a13851a") },
                {  29000, uint256S("0x0af437183e3c1d4d1b4d7f47237ac7f504aa1194d6cf58c872841e9d31603302") },
                {  30000, uint256S("0xc8c0367622ced32dd3c4793d974e04d672d8f88115149445f37c6c5950bfe9b2") },
                {  31000, uint256S("0xc5d44ac59d740717fa04e1709666c9e98766c638b7d20fcb9d30bc8c59033a17") },
                {  32000, uint256S("0xb7f29370d35409bfaf79715785ec44d73cb653c34d80190dced08e19af0d800b") },
                {  33000, uint256S("0x21b8ac3f7d40232e4ffd913e91f9bda6f1834812df5806df9af58ad1b17b235b") },
                {  34000, uint256S("0x941e0ef9fe8f8c1e1a05fcb4644b655b659f5d5dc64a1d9f946e450bcdd64fd6") },
                {  35000, uint256S("0xafab1f8f1368a9787b42f41ebc442a99dde6649c36a8f38f17641f310562fd3a") },
                {  36000, uint256S("0x91f802d19f2d24e3ae85a1fc3e30dd2896bb2469410ed5532d9bb7811427e2b0") },
                {  37000, uint256S("0xf5c65d46e2b95bad3ca951cddd03cd77650870d39aa5f756a9ea9490d9040047") },
                {  38000, uint256S("0x4496f906d81728a522dc5e5e8c4784df4663da9b7063f1e5e6ffd1474ef61fec") },
                {  39000, uint256S("0x1a16d2bb21d44e0399badc33d5215b32ccaeccd77721af3bd61be66e1db2bfcd") },
                {  40000, uint256S("0x5e968add124371c1d5fe4cd2171d45d2c8a11dea1339eb1ade25cb9725a0a56b") },
                {  41000, uint256S("0xf5aba9e950da5e44d1a8c1d2bdd616fba62a6e6c226492436782ad7fda3bcd72") },
                {  42000, uint256S("0x181454802688c0899771b697a2b2cb8e3d291ac098b0f41899319dc9f0c39112") },
                {  43000, uint256S("0x6a47b08bf3c4e58b7a8bec4451092cd5ab79891a63390dda2bcd810735819aa3") },
                {  44000, uint256S("0x9d25ffd74c63f7c1d56d33f279aeb3be91c7d64be85b6f87d3a4defef8d72456") },
                {  45000, uint256S("0x2ff01e7481e7829da065aac48f420b57513ce46aa4e429391064c42dde66df15") },
                {  46000, uint256S("0x1052f78825e55d3eec69684d7d5fd09fde27f7d07a21978229a2b14cee13bb73") },
                {  47000, uint256S("0xd799b0e60cca52bc2c1dff4f4af5eabf8b66f1a290b8e89323fbcc2506d582b6") },
                {  48000, uint256S("0x22784d9a08f451f51b00c23b99396e131840b7d9f51fe7be50a74c2025c6bd36") },
                {  49000, uint256S("0x7439cd47ad9e4158deaf123ba81bc11aaf67467c7824884ac2f9b564dd55e709") },
                {  50000, uint256S("0x762e0c3c9baedf5b113f7253ca9091bf646e009cb322f4aaf720d5a3f889dc45") },
                {  51000, uint256S("0xad667d924328cece33c1a7982a0f2662b69c4c99804c629967e3251b31adb3b1") },
                {  52000, uint256S("0x7a11b8feafa4921bf32a43fb5fa2938f658fc57916cb2972237ed928e3073ee9") },
                {  53000, uint256S("0xb00e50860354f3b2d2e5c19f2ade4978163262ab6eddaa5618cb21bb44e33380") },
                {  54000, uint256S("0x121773f98a69b2be0b99a33e63b4246311da1939c23bc3d726e94d6fa6d88a13") },
                {  55000, uint256S("0xb501478578ad612e2b1763b76a08a8b5760617c138af2f9379618d8b2b342f6a") },
                {  56000, uint256S("0x9d55d5b3c1df040dc7504a1b36f60d6f11f89036d8ac5869b82df67cb223edb3") },
                {  57000, uint256S("0xa7b978bd0aadf9743cb02e6e94c23d2bfca59c4d0836264ea892efbb65b6d9f8") },
                {  58000, uint256S("0x97235c555f8d072236da56807bfe0f8ca32edfca5fc864b4b233045338bcf0bc") },
                {  59000, uint256S("0x64305c04fe6883c3eeefe85a03c9b7b7f223d7310480b69f54908e417dc3c20f") },
                {  60000, uint256S("0x1128e28907b17c292aaa32f3c3d9e06650fb0436683797cd98731a688e408866") },
                {  61000, uint256S("0x765a58f5ec90d4c53b01781b1bcaffeac5aa7492047521a250c1d87c5f8fb858") },
                {  62000, uint256S("0xcb32e25b1586aefc293044ea9d9fdd08d8ce36608cec29bc7a4022a5e73e2cb8") },
                {  63000, uint256S("0x05f6fa5db2beeed859e768a50d020a16611380fcfe3735dc3373e008a181c283") },
                {  64000, uint256S("0xf39de31b4f07eab4202f922e65d0722f2f6c5f12d89fe638fa64297d2c29a63f") },
                {  65000, uint256S("0x34b9817113b21963a78861dcdbaa03e34eee21b61ace49d8092c52c2f5b06a51") },
                {  66000, uint256S("0xe2f7a9bf0b5ad6630c8623448bd1e6669a52107c74edfc1e33c7cf22030b5cdc") },
                {  67000, uint256S("0x382e79f0ca05e6515eb7afdd7500adef354b2774910eea657a583f445fdbeac4") },
                {  68000, uint256S("0xd4f8fb21c8079683d76efaaa79405f11eb9948e9ea6578dabcbe70a3ed4e0673") },
                {  69000, uint256S("0x5560a6c2ff84094a9f0fe242b27750212254235557525a76872958f39eb81161") },
                {  70000, uint256S("0x7c0d0abf50bdab5960a6f80d966ad76b6c5fd9098ae66fc09c683deba8ac6ccd") },
                {  71000, uint256S("0x1e4025e4fba50e3aeaa020ddc409398c2bb1a4ea03cd738bfc79a8674132bdb0") },
                {  72000, uint256S("0x93065a3b4e43baf4b6dbba22c5cd560ce9c9c04310ed81b9519ef75d2d37cc4e") },
                {  72500, uint256S("0x4f1ad437620ba48bb527a5279a11ed59d57b2d45d7c919d74aadcbaf66766ccc") },
            }
        };

        chainTxData = ChainTxData{
            1554960497,
            72820,
            0.003337
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";

        consensus.BHDFundAddress = "2NDHUkujmJ3SBL5JmFZrycxGbAumhr2ycgy"; // pubkey 03eab29d59f6d14053c6e98f6d3d7e7db9cc17c619a513b9c00aa416fbdada73f1
        consensus.BHDFundAddressPool = { "2NDHUkujmJ3SBL5JmFZrycxGbAumhr2ycgy" };
        assert(consensus.BHDFundAddressPool.find(consensus.BHDFundAddress) != consensus.BHDFundAddressPool.end());

        consensus.BHDIP001StartMingingHeight = 84; // 21M * 0.01% = 0.0021M, 0.0021M/25=84
        consensus.BHDIP001FundRoyaltyPercent = 5; // 5%
        consensus.BHDIP001FundRoyaltyPercentOnLowPledge = 70; // 70%
        consensus.BHDIP001NoPledgeHeight = consensus.BHDIP001StartMingingHeight + 10; // 94
        consensus.BHDIP001PledgeAmountPerTB = 3 * COIN;

        consensus.nSubsidyHalvingInterval = 300;
        consensus.nCapacityEvalWindow = 144;
        consensus.fPocAllowMinDifficultyBlocks = true;
        consensus.nPowTargetSpacing = 5 * 60;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144;

        consensus.BIP16Height = 0; // Always enforce BIP16
        consensus.BIP34Height = 0; // Always enforce BIP34
        consensus.BIP65Height = 0; // Always enforce BIP65
        consensus.BIP66Height = 0; // Always enforce BIP66

        consensus.BHDIP004ActiveHeight = 0;
        consensus.BHDIP004InActiveHeight = 0;

        consensus.BHDIP006Height = consensus.BHDIP001NoPledgeHeight + 200; // 294
        consensus.BHDIP006BindPlotterActiveHeight = consensus.BHDIP006Height + 50; // 344
        consensus.BHDIP006CheckRelayHeight = consensus.BHDIP006BindPlotterActiveHeight + consensus.nCapacityEvalWindow; // 488
        consensus.BHDIP006LimitBindPlotterHeight = consensus.BHDIP006CheckRelayHeight + 5; // 493

        consensus.BHDIP007Height = 550; // BHDIP007.

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xe6;
        pchMessageStart[1] = 0xbb;
        pchMessageStart[2] = 0xb1;
        pchMessageStart[3] = 0xd6;
        nDefaultPort = 18744;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1531292789, 2, poc::INITIAL_BASE_TARGET, 2, 25 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x8414542ce030252cd4958545e6043b8c4e48182756fe39325851af58922b7df6"));
        assert(genesis.hashMerkleRoot == uint256S("0xb17eff00d4b76e03a07e98f256850a13cd42c3246dc6927be56db838b171d79b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0x8414542ce030252cd4958545e6043b8c4e48182756fe39325851af58922b7df6")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
