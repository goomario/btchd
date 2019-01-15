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

#include <assert.h>

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
        consensus.BHDIP006BindPlotterActiveHeight = consensus.BHDIP006Height + consensus.nMinerConfirmationWindow; // BHDIP006. Bind plotter actived at 131116 and Tue, 08 Jan 2019 23:14:57 GMT
        consensus.BHDIP006CheckRelayHeight = 133000; // BHDIP006. 2 weeks after bind/unbind plotter limit. Active at 133000 about when Tue, 15 Jan 2019 11:00:00 GMT
        consensus.BHDIP006FirstForkBlockHash = uint256S("0xebbc8573080109747838beec06c2014f11327b7b7dc35eab8332a53efecf7f25");

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
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000003a061e117380c2a8");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x7af7b16776f8e91f5dcafae8405ea3ccdb0b8db06d85b64549ca61eca4990f35"); // 113900

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
                // Offset +200. Generate by `createcheckpoint`
                {  84200, uint256S("0x2f33e669d67cae589d63385229a145b303957eaaf58b1b520a533071d4a96bb9") },
                {  84400, uint256S("0x259db7622b22d26f7eceb1d7c503d0ea3e10fa79ff1999119c74b0f696e2b59f") },
                {  84600, uint256S("0x107d9ed8bfdd68c3e8885ccfcbca229d6c293a2b9cebe150260c3ad0b9a716e2") },
                {  84800, uint256S("0x119e74019c25587bdf895903f96ef17ce81bb179daa3ddbc469ce66690c5f5a4") },
                {  85000, uint256S("0xaaeb335da849331f43e7808611f38e630ffbb2726ba131181ba72ac8d58a2da3") },
                {  85200, uint256S("0xd262ec3fda7fd4738879f03480a90abcd420d64f25d85ce9726255df15197f0f") },
                {  85400, uint256S("0x03380530ece1d91ba6ed364bc821a6c1474cbf7502ede40d14070334429fe430") },
                {  85600, uint256S("0x0196ac98c66f33f2e450d40198e1ecbef0f2880e6e644c77c9a4b8a84fb65ba0") },
                {  85800, uint256S("0x681094d306bb54e29122142610f052897859301b0a4fca367d6177d07f4c9827") },
                {  86000, uint256S("0xe4fabbdcef187186ae1f1cc32ef8ec2fa22025c0f38a8a4cb0a89118ba34f75b") },
                {  86200, uint256S("0x6034b482e0df3c74a20431620cdbcf4efa0f19a791fcf2f19053d68c1e7695e3") },
                {  86400, uint256S("0x2b015628fe649ac753f5ec7bb62bb4717a1d38ac067c3b88dfe4db95c4a97fa6") },
                {  86600, uint256S("0x97f6db7e888b2bb6673465b0f55ae6068a6eb6106386660d1c62a915a015c6cd") },
                {  86800, uint256S("0x2eb5739189132e1ead14a7d6e20f9d372d3f6e6440639126eaa92b5f206217aa") },
                {  87000, uint256S("0xf045373bf308043b5e3aff3fffa76e72290c2e433574b1a27a4ad34cab3f12bd") },
                {  87200, uint256S("0x1f271296524127c8ffe499fa3fb7c06977412f91ab0b2dbb2b6fbd520ebce79b") },
                {  87400, uint256S("0x90fab627f32bfaecbd917a4fd5ae3082223c7fe1d812373574df4ba490f697b4") },
                {  87600, uint256S("0xffa79adef1cc53f8c0c6c81ba1beea70ae0819ed9d62a35ff09a8557da6ce00f") },
                {  87800, uint256S("0xb7cb9da53b3fd8c1b6437b6498b3c84e674ca126ea07f6c55f613504400a06d3") },
                {  88000, uint256S("0x24928cd2154d1546930e5a6ac4f7828dc40fca3dadfc31ce8fa8caea6cfb5401") },
                {  88200, uint256S("0xc8418e02ff9153e74340dd5faed15887c5803fb0c2692e988389288cd248e515") },
                {  88400, uint256S("0x1c4ea03540d12ba517d6dafa95ede92691a9f62f0cd215fe0a0b485bdb3ea6be") },
                {  88600, uint256S("0xb91f12464896db515a250a2ffcba9e72d6a075e2c3fc4dd08eb3d1dbc58b83ff") },
                {  88800, uint256S("0x0bccca6a0d8ac55773195d3f7dbcf958775727ed1ca04c7c7e18d6ebb88a8d14") },
                {  89000, uint256S("0x4cc9894182dc2ea2bc5d7c94ac9a653ebbf0914898cadda126085d046d9e90bb") },
                {  89200, uint256S("0xca121617f8e2b227f58f8109627ecc8050ae31d516f803b17599a0e7ae624c0e") },
                {  89400, uint256S("0x80d1d1663cb9f6a293d3ff74e4f7f40e5681b2b7131ba81ddf653f9b0a0683f5") },
                {  89600, uint256S("0xe113902ec5924fb2678f062b46a79f3390e350dd858406631eaed4372e79c26e") },
                {  89800, uint256S("0x50c324e6bff9922d0985f89dac72153de0bc7f45bad8c5e4c519d0b064274b29") },
                {  90000, uint256S("0x7acd0596d0a5b97c036fa705e08ea636b07e5dc004d8171d2a02955fae12ddde") },
                {  90200, uint256S("0x8caffaf9e5f57a84d0c1069964869d5e57ba40f656993267ba4d5b998e7fe58c") },
                {  90400, uint256S("0x33a57fb4592a056ee6dd564108b7ae11bc3b0c9b25cf0d067c255032f31d3ca9") },
                {  90600, uint256S("0x79856e499f4faf63b71be3d3df734332fa25328da4ce9d4ef5d68467091e4e3e") },
                {  90800, uint256S("0xad0c33534d6c1d118c3b2869123977350aa8fdd34fb5e6ec0a03f0b9bfd81b19") },
                {  91000, uint256S("0xd9eb11eb97e95b84a416f65feda01cdc134b4bba7c206e22ba03bd623e29dd16") },
                {  91200, uint256S("0x49c50e4cd84fc9c45dff3b724947d6582f6222cf01ce50b6108e75ea136e07af") },
                {  91400, uint256S("0x8d38a5fb1b00cb788e1069237b6229a6da6d10978be150c4c042741c22551cf0") },
                {  91600, uint256S("0x89d021a94b47acdd2667969cfc60c6352a2910f53e8a6fd9a205a37b48a948f4") },
                {  91800, uint256S("0xd55bb1049a644c9a9ae98b06c59ef2c89f87ffe91db5870910898d7b7ffaea13") },
                {  92000, uint256S("0xfe0f3540c630cde2afc5e5081a4aec25ea43a57e1bf603e403054e218a3dc9cf") },
                {  92200, uint256S("0xac064cbe76b34b36f965c451c942d7e0a480b7af2a54ac88cf70f3c8491743b2") },
                {  92400, uint256S("0xdc557c78c5899ebf752993a92e7e83a0f45748f1e78437531226989f808faad8") },
                {  92600, uint256S("0x63796d61ff9223a9bb8917600b5203a2ffc632369cc7e31c4562e6e6a1075479") },
                {  92800, uint256S("0x24defd2b2545dfdfe8a26a901221a90c5b38cf2a9ba5dbb9266288b852b824d7") },
                {  93000, uint256S("0x821d1ca35a7b8812f36f387216f0eea83cafcaa7191b4c0308e27cf8356abc1f") },
                {  93200, uint256S("0xb428a5a21f8c4a8ad22f60fa78ec575733fa640c538076b9b911d97c8e76fe73") },
                {  93400, uint256S("0x1708abfe91a498b1fe3c04c539689b5aa1c9f92352c93ce73b40a3fee38a4755") },
                {  93600, uint256S("0x2a5b9b0d18db080a59748bb346dd8a9244ba7a7ba2fab8004d689947167eec2d") },
                {  93800, uint256S("0xa6b2604f860c532f05048cf95f9fb25294ffa7c3580772cefe2ad9038bc6683c") },
                {  94000, uint256S("0x7dd832ac7da06f01cf8db0e6e9917dab12e37d009f7369cff00c0484cdd42a22") },
                {  94200, uint256S("0xc0c3478cd451a36e3597a5080154bfdd7e0d0f3646c526b979cbda79b460e5a3") },
                {  94400, uint256S("0x175d8f7fcf214834aebdfd7a50991270295389cb7713451050da3be48dda74f6") },
                {  94600, uint256S("0x12777bcd92846b42b051ec74342284b7ed8e785f294d8e88e6e4858cd533ae96") },
                {  94800, uint256S("0x2655ccb83a5e2ffabc6033284e62a24bc9d74bc224497c6e699cae6920f61390") },
                {  95000, uint256S("0x728178b9cea6f448c31c27edec58bcb082c1bee798f6367e4e246c361c106464") },
                {  95200, uint256S("0x5441930fcd3427c501546fcac3091f1ee3852069487e219fb1479fd1350566e8") },
                {  95400, uint256S("0x0e4463f1b218c575a8ec8633c02498c38c7b14dd94f7c6867279f2a9ff41fe0f") },
                {  95600, uint256S("0x0974455871ebb4b83f69f957b1d6d70b463735aff756105bfc6660064d9a755c") },
                {  95800, uint256S("0x44e484979aab91281df9a13966e6fbeac93c4795d9e50d817ca1fe4df6cc992a") },
                {  96000, uint256S("0x18ada0a6fbd634489a4b05318731035fa048bdbb381084b10071107b3790dd3b") },
                {  96200, uint256S("0x7081ffd8664b3c4fc9af895d76cd5a4deb867a1ba55638dd0d7812b5f9592831") },
                {  96400, uint256S("0xe55cc40435569806b32bc76ec8ca3861446180d1d1a7d863af993493bcacafea") },
                {  96600, uint256S("0xcca7988b7651ab1a84857549fc413bcd5c654023bad93ffe79d025360b1d6b84") },
                {  96800, uint256S("0xe64abdd6ba26a53f90144a145f816e710ad2ff6e39ecc6d323ee0e7f29cda926") },
                {  97000, uint256S("0x049777c7f4ad62da817a4076b11ad9c3fe15c4310a43cfeb246cc3982c7cf2ca") },
                {  97200, uint256S("0xc7031aadf9850074e23c9b22a7eb1468ce25d68e9d370927deade9528c6ee22f") },
                {  97400, uint256S("0xe16e087fd9b422030bddadef95eaa1eae2633bd2d22ef38e5a86db9f54f2e252") },
                {  97600, uint256S("0x34eb48fe5c386a5acf423a7f3968a4238bd76be295d3405c58c5c64c6559c910") },
                {  97800, uint256S("0x3d0a31185943e371c97de42f0c4c6e9f9195c04f32501d074bb15d67cbbf8474") },
                {  98000, uint256S("0x3f1068eb2eb9a6b1a2e3a93ef74a34c59fefe0d0e48b6d1f458bc562a8c83a05") },
                {  98200, uint256S("0x5c749fa4e458455d0e7c0edf09557e82bd09a513347053169cf5d36fe2f328fa") },
                {  98400, uint256S("0xf894c7b0203511f5f57a8f82b992461728a1ba54117f558b871adba878f1c07d") },
                {  98600, uint256S("0x591819bd122e0e3dcc209a8870eb2f2d1930ca6558d32e4ec0a507affda28b6b") },
                {  98800, uint256S("0x7189eb3effbc085496331dbf7a6cf5f35127fa191f2f132fd4d678d48adbffd0") },
                {  99000, uint256S("0x85f44668b874c3d54c3db34b5779648c7a110a402245c218b5b913f414442a67") },
                {  99200, uint256S("0x78f35626e38514969c4bea2b787f0631962994e3530f6079b5f13c32084ca66b") },
                {  99400, uint256S("0x778c7f310e957dc8a028a40672ba3e1f659bfda31d8f85421ca329099139a9d5") },
                {  99600, uint256S("0x0ed09d56f210669a620b6f3824745810f1e5d781e67a9fb9ba2f1c97cf9293d3") },
                {  99800, uint256S("0xdb831f51bdf6435e89e0ddc39369dee5f9a04f549e35d8434dbc43802808ce86") },
                { 100000, uint256S("0x5ef9b2dae9a7aceac25c5229225a64e49a493435ed0ecbe6baf92a6496515931") },
                { 100200, uint256S("0x8d3b0d2014ffb75c3c59dc38c5e6255d0229d96d32541f9ddc7dd89a9743a477") },
                { 100400, uint256S("0xc0b6c0d821c532ade8818b5da1dd42ee6ed8872c1abebae6ae3f1950ca4a76fd") },
                { 100600, uint256S("0x6b72dc593f1f5f8a3c06e2787b02ab9ba803f0303e673130afa34c72821747d6") },
                { 100800, uint256S("0x12c1184cd2884c41360cf89f9aa2c473188d6fb674de9f8f6a552924ebd79f16") },
                { 101000, uint256S("0xec5c821be5b16d509f4c29bc9620461768808e5ae40a7b3eb6a7ca260801f939") },
                { 101200, uint256S("0xba713a70f08641ee894c686abc74db7c49b27d2cac5fd6ef811271f20a0fd9ba") },
                { 101400, uint256S("0x821c881b2b92e17a176c2844c8241efa5b48c6a26145fbdda931e4d9a94beda4") },
                { 101600, uint256S("0xac9a4e8e46da7b350b878308a0dfd076273574657d6bc1a68507fc3c134244ec") },
                { 101800, uint256S("0xf2682f5fb2be4a49e65f6efb96ac1ef193bf86dd456a88c30d877f702c2d30fb") },
                { 102000, uint256S("0x90a77896d7c1ac9c52504c5779f4b070530cd4de8047babe443de4c71feef0e4") },
                { 102200, uint256S("0x86bc4eca7ceb31b9fba875bb83866b75e0bae1b19d369773aecbfa04929e3ca2") },
                { 102400, uint256S("0xebede659b70faf3e51988915f45a4b51d0cf68ba56e5d7aba6306675a686abfd") },
                { 102600, uint256S("0xc4aa31c7de323a2a7f4a4471341ea6d45a53a613dcabeae653b7a2ec7ed6f0f5") },
                { 102800, uint256S("0x612e99309f87b8904f9b4e94e6a9c22a3fcf347810c5631d8d09126ae9627d3b") },
                { 103000, uint256S("0xfcc8b4afb2c6bf51132b1bf7c45e19015b4e54d2aed6d0f9afe61a314edf1a1a") },
                { 103200, uint256S("0x93459500d27f3205a074f1e2c60c40cdc95b8f821dda90571240569a50c6fc7f") },
                { 103400, uint256S("0xf699df557176b5776755951642c0c4f7f9c3158a8c68ef22292f3d4fe0de5c40") },
                { 103600, uint256S("0xd7b88efee82e26bb548e30b2649ebae159a041a8488c5fe841140e8ed3ffcb2d") },
                { 103800, uint256S("0xe3bc1f73efd9f01168bb70d47c293be5db5a84c69d03be423859862daa4fb17c") },
                { 104000, uint256S("0xf89deb06a14ebde24cfaf1ff4fb0f545f59a7940e660d498f6c306c6c9b66cde") },
                { 104200, uint256S("0x1e69e87cd16e2bb493bd075fc37bcd66887cf700f883744ab317e82ed68f7626") },
                { 104400, uint256S("0xbff7faf8dad240ab364d28123ad772958d8d8885d8ea07df616f0467073a125c") },
                { 104600, uint256S("0x18088becb8bd6c295a8dddccf9c6528ce4c061a79d5b1a3e5eba351b4119b379") },
                { 104800, uint256S("0xd845bcf10abaa62101120764c6a07ea363d4e2e80e78f8d9e5ab82d27aa88371") },
                { 105000, uint256S("0x27fdb3d2bce66669327e0d6522c2c9cde431491223b9b3e750e87c96279c8175") },
                { 105200, uint256S("0x3f7712a11d4939c916a9fb2e71335e36b576d7350fdfb217976a1173061b3721") },
                { 105400, uint256S("0x8182f437cc0600ed7e02f52f32d85747dac0beff32c4402a4a254c4daeba627b") },
                { 105600, uint256S("0xc1c3790a800015582378f3cb087ec52fb1a35f505e1db9129dd19bb4af0587b2") },
                { 105800, uint256S("0xe42ad428df490039d36243414a217a9c74cf5f078921df797707913bc7756774") },
                { 106000, uint256S("0xf7dfa89a61703f561fbd30782328c03ea2721c2c2cda04046b872303468512ed") },
                { 106200, uint256S("0xcb98bb63ddb0c60bcae43ab4d7c240adf54695145a79b634a1cdb26953119bf1") },
                { 106400, uint256S("0xeb459bb78423a554b15be3416cfb00d18d48f59f2789e1030a79a72c7fe5dab6") },
                { 106600, uint256S("0x42f091051e99884317dd6dfc266fc3960323af483a4951b5edaa40da6dc7fd73") },
                { 106800, uint256S("0x3728bdea37af54baaa403c4143c3fa27b9ed9ba11747bc474349fe721584ff4e") },
                { 107000, uint256S("0xe981b196881cc881a799489c5debb101beabc141b7f3b71c22cd64cd01277cca") },
                { 107200, uint256S("0x903dd3da9ea4b6c5cb0985430c671198ac2fd11fa0fe618cb851482cc5bd57c2") },
                { 107400, uint256S("0x9add7c945e21e0ca8cd9e20ad5580d76b79310e2c14471c7b304a989b4d50ade") },
                { 107600, uint256S("0xf0cb88193dc2c38442a3ecccb7953fd538afe5a8abfea74c10ec4ae7e2fc63ad") },
                { 107800, uint256S("0x80bd2b0e2cd19ec5255072972c6cc6e95e834923e42320a8f345fd71d0b5459f") },
                { 108000, uint256S("0xd7c1c6d6d019ebe460d4bef7f3dc2fd2a4375462eff574560343d47bf314161d") },
                { 108200, uint256S("0x8406b828c4a4f9c399ef6d52be5b4acbb84f4278dc90b5b1d4487ea7ba76db37") },
                { 108400, uint256S("0x6e9badde4d6daafde52cac9603d85848c7c0d76c251cb91d82862054452a9b3b") },
                { 108600, uint256S("0xafefb423024c39f0981f5923a8b06534f63accde56ef93584fa0462cfce9c71a") },
                { 108800, uint256S("0xde357c8d22d4a8ea4e8125edf98139d58d5fbfcc3a33ceeba86499296728dd5f") },
                { 109000, uint256S("0xb186f772f58dabb20be41c0d533944ff739125241648babdc8ad427f04e5a594") },
                { 109200, uint256S("0x2439fcc95e87cfb712dbc4dcbd3f5c4afde1a797af484b7f4d3da0036700c300") },
                { 109400, uint256S("0x8db8691f0e82d2ff2b7cc000b6fa36057aa694751d387a4ee295b7146c835c29") },
                { 109600, uint256S("0xb5bffc5fbcf1f6fbeeff485d37b764148c373009f626f6bf7c8458e26dc10e67") },
                { 109800, uint256S("0xe28df39f110a4a599fece810b07599512a3c5daf1ad7a56d1ca3bcf1adf874d9") },
                { 110000, uint256S("0xc3fa82d07a4ed51b347f3694ff144d654dbccc950092988df9f58aeb2b907dc8") },
                { 110200, uint256S("0x710d22af865cadb4956f4525aa06d25d43a394e322c0ce89153ba98473bfdd36") },
                { 110400, uint256S("0x8238ce3543643ce029ef266b76503bfaef1b5368f8e581946e0390c58f9a8c12") },
                { 110600, uint256S("0x6bceed08b3ca84764342c56695a256bb26fe2e0e204bdcae51e7fe1d16a0358a") },
                { 110800, uint256S("0x081ef73f8eefe84b9a0d26afa1dcf1422b7f7856e65a9ace97d94b5961cc9024") },
                { 111000, uint256S("0xe9946732846962845b25d217aab72b87fbe8502fc4e83d2d45e30ef09daa3ff8") },
                { 111200, uint256S("0xa8b4ffaba983d412e0fa5f92a84cdd4d6cbbede4542e629dc19b7c5b58799060") },
                { 111400, uint256S("0xe594bc426808fd7fb98ad64b6b09834a3323e678a2b9a14508b06ab69f7879ce") },
                { 111600, uint256S("0xedb76d9b771d1522c36b61afbec89df6582f5a6db49083f4647a0e33b97b8398") },
                { 111800, uint256S("0x3971f056b5f11e140965e0e122b370721abd1d2be6c3c14c9f07d3dcdef50bbe") },
                { 112000, uint256S("0xfd78fbf7e6e6274919f12c384e46ea7f5e3ffc2c7a3828a35664622d06885667") },
                { 112200, uint256S("0x540d714fe20d6436b48eb2d5672cc3dbd881dd208e6cef34194d36df5e0d610d") },
                { 112400, uint256S("0xba7262dafdc2322fbc7eed5622293f13b0cb82edfd869585c6da0f5ae4a27456") },
                { 112600, uint256S("0x2b3f3dfe550647445d8e0f76877398e72474cd5e7a847a953d4a24c23da49c19") },
                { 112800, uint256S("0x11e736b1c4c2d2d48d18df13cba43752e5e1717875ff1c91d29a6f6db7ac2957") },
                { 113000, uint256S("0xfa577eb0c02a6f81642a166791dace0d035515c1afaa2f071447d8c462ac88c8") },
                { 113200, uint256S("0x5465bf0e2faecced817ece5f91c9176230a4354dfed92b078d2fe4bcddcbbf81") },
                { 113400, uint256S("0x62e472da5d5857f1f1cf2f23269b1796efa9611e44d323b46ffc6280e1a4963b") },
                { 113600, uint256S("0x3433898f22bacb95ae21fa6c68561bb1c4d14c055f434ecfa029b7598ef53871") },
                { 113800, uint256S("0xf1a58e7e268e5399dd450e38b67ce0e8ffe046950270028a373a24a43ebae922") },
                { 114000, uint256S("0xfe881b2ea8b7481e5233c80fc2d8394d7a5c29484275dd93bce8d0d375f458cf") },
                { 114200, uint256S("0xb02e086b57dcbf91c8f7f7b832c358141ffc464ca84e86992c6468a8e2d94049") },
                { 114400, uint256S("0x62bc98ac04ce8f89417d239b8b868b5957ffb595ccb0acf36bdb87cb5e1a2f66") },
                { 114600, uint256S("0x0089fc038331a49adaf19b6b93d0d3e90951cbe11b713f5a9903b92aee4f57fe") },
                { 114800, uint256S("0x28087fb7f79207ec757639846460ed28945338617fe21e922e762fad3d50765c") },
                { 115000, uint256S("0x5f002fde0487f97652407b5976f309b7de0f95ddfc336a20e5896cdd7fe4906b") },
                { 115200, uint256S("0xcac0f40310f4b72158c0754facbc3de791533bb31011b5bde327699eefa702be") },
                { 115400, uint256S("0x1235fb53cda9ca0eca8f8f4daa5ee6ba8367415b466d17e9fac83242cd89e5f8") },
                { 115600, uint256S("0xebb41351c4e9bd67885be2750134d1736019b1a0d24db6df84b8b3c6a7b6d330") },
                { 115800, uint256S("0x381685232cf8d38f17356f9eb787b54e766c1789f16a074f444dec9298a8645d") },
                { 116000, uint256S("0x5ea5ea3fe879a01ec7f2625cf68b1b703d2d7fcc7dbc9206b34b651ad6533f16") },
                { 116200, uint256S("0x7d59bb1ed0d6ec26fef9ae2bb0fddc51b5e454471755b4100696260321eec1ce") },
                { 116400, uint256S("0x8923470aaf84450efccd758b2d3133cc599cbaa6bb339c61b5b11619f492a65c") },
                { 116600, uint256S("0xb9ade3594e87552d958a8cc27ffb09dd4fa4500556b02c2c2f4211156f505425") },
                { 116800, uint256S("0x9a18c1ad86e1fc4705500beb918356dceb16b8d5ddb96d9fb52e9c8fbae3f69c") },
                { 117000, uint256S("0x83d9faee9a07dfaefcf28c36f6c5532598dc48bdda52617696c4a5455904bcab") },
                { 117200, uint256S("0xef7ec1c484fb3c7486aadb179cdb1ea8a49bb1cd111d6095149d08c00cf9d069") },
                { 117400, uint256S("0xbdbbf082cc1780245fcc4bd89b86d376740a746f362d7b43bf4a5b1531333ae1") },
                { 117600, uint256S("0xa08e09b1a9113ec128b535f1d800114bd63310546de5956c89cb92f775701915") },
                { 117800, uint256S("0x27d81118e2a1aca36fb4f3d1991706f05932a170d3b9040774a4ca997c43fb2c") },
                { 118000, uint256S("0xf640f20483939c0ca4bfea2c42bd11fb6c071e40dd415ed9895ea220c2a19e1c") },
                { 118200, uint256S("0xf1c969f10a65a55fad05462dcd129c3efdec3b3753d13f7169dea945a58b60f5") },
                { 118400, uint256S("0x4b9fada830fa13cec1a3c4f665b6aecb90e3dd46ae86dc48aea6775931905267") },
                { 118600, uint256S("0x9e9438d6677feb2d62e6d03816c34434efdc76b09f63f3cb488d66f01a121b8c") },
                { 118800, uint256S("0x7897e7e0c77d191a95a6af219cbd118d7029ff70a5c23afde72f2518c26d404c") },
                { 119000, uint256S("0x05c1edc9af0474d10c04457c7bb54f75a4d5e9e7432dabdef4ddd5581e9478db") },
                { 119200, uint256S("0x326df925d61bbf3ebfa22f4d27c12a2bef6a4552d3415adac1b404f865e57dee") },
                { 119400, uint256S("0x01dbe2d86e516e4df0894ca4b5cf15141a7bcb4fe7faa0049249baaeef2fb7bd") },
                { 119600, uint256S("0x0237f37735d2394e77d5ebead716cfe14120e79cced1dc07a970c0624f78ef4f") },
                { 119800, uint256S("0xc0352f737ac6cfb7a63cbae9603e51542796e92109377140f13f734a629698d2") },
                { 120000, uint256S("0x0b1ae104b516bbc4f19f4850c6bb499154387b391334ed7f0e93671e11530bbc") },
                { 120200, uint256S("0xe1e18ec813b7a85c9961e848951985884e883c2efa8421616a708969e40a1836") },
                { 120400, uint256S("0xc1499c06ed27e69a0590a0660ae9f81801ad2b84837a24cf10aaae43a55f2ef7") },
                { 120600, uint256S("0x3dd952daf5d83e0af80d2f47cbbeda8314b9909ffa20dbee7e1eadd59fa49d98") },
                { 120800, uint256S("0x7bffd4bd28d88a900d348ca3e0b3a86588979c632fad7555412c830ef894ab52") },
                { 121000, uint256S("0xde15e2e48e4c906d4de2f5d6ed40add4a3c023912fdf5b66be6cc5c5017e92fa") },
                { 121200, uint256S("0x5bbc2fb9d35a7a1433454da402026aeb773e5811ff8d9b021472b4fcdf703e90") },
                { 121400, uint256S("0x86a31807604f2ececce4f8ccfb8a7318d15830537c778102c024ba6bdd585396") },
                { 121600, uint256S("0xb340eadd5de0a50a21c7dad170a75f4e8dbedfcb53fef2cadfb7f397b12dc165") },
                { 121800, uint256S("0x64e2e726f448455f1ea100b15bb2755005915558c71b40380da5ccc3c29529ad") },
                { 122000, uint256S("0x5f60e469b8742068e56147d4e463723952e0395e196e255ad8941835459ad37e") },
                { 122200, uint256S("0x60316bb22560a127d80e4ce9ca44a2462df7c0d8b40228cadfbb07b7f665b5e1") },
                { 122400, uint256S("0x92f691f1a6bb427d510e705d39166bf24d415b3e03535924371692629e528206") },
                { 122600, uint256S("0x4cb613d3b2355d73d1eaab78a672170f6c0bb837dfd45d993575ab34b4c96c71") },
                { 122800, uint256S("0xafdd8516ef9cb9587f54fcde2c424fc4a1f04b38de2a8192b5faf06e209726bb") },
                { 123000, uint256S("0xb503ab001307533401f96f28f53c4747479243a2314b363ca06477234ed29281") },
                { 123200, uint256S("0x8a18e288d431c989062b25645212f0bb81b8e1dd67fae08ce11c6f6eba16ebe6") },
                { 123400, uint256S("0xf73d1ae64f2dd7dbae9e75ed2df36e9d8670b3511531ef4a1e1f5b0323f5c366") },
                { 123600, uint256S("0xf4e8216cd67665f237ca531a459d82957469e2ad29df56bb945816735c26e085") },
                { 123800, uint256S("0x9e5efd879723152841abb9fc652cf4bd399fdd9af6461091b7a8dbfbf66c241d") },
                { 124000, uint256S("0x3387babe46e9d70cb6fec1d8104b741070b86c7d96362b512026ccefe7546774") },
                { 124200, uint256S("0xb46dfee7c6216cf879a9fca146fccddaabd3add8f22a9e441babc77cbff96e48") },
                { 124400, uint256S("0x4f0b60538a76fa749bbda8b17161c0481fe580da0247e984060ff3b92180f450") },
                { 124600, uint256S("0x77f81101883621176d13fcb8a7caee894ccfb9aa9c70754c455936401f97424d") },
                { 124800, uint256S("0xd41baa7818fc194316703439c670755f8783eab8a35f9c8d7012030cb4cf2836") },
                { 125000, uint256S("0xebf85c414e8a830b1723ad9f7a86206e2254089b273ecaac7a0fc8dbb35dc0e1") },
                { 125200, uint256S("0x342c99236d338735e56a3f9ea546edf87c1fc56275dcb61b8633c7cea5b1b85b") },
                { 125400, uint256S("0x9c7e4d73ab0bdded2dddd084d31b1d0b301ff12c50798d769f3ba501419df8d9") },
                { 125600, uint256S("0xd76ecce0ab47075e60e725fce15854e77133523563fc04183935fcd38084ff9b") },
                { 125800, uint256S("0x366ed19f6d3fdd55e98a671db90a3603c2e5bdc7a5d971b0bd3f345d6d7d413b") },
                { 126000, uint256S("0xb4a81eb95d4ea3028b489bd77b045c4278058a6889558967949b4694967302c6") },
                { 126200, uint256S("0x2fae552575ddcd2f280b6a3fa362797ae72de216b4eb044e8c8fe46fe1d074eb") },
                { 126400, uint256S("0x8da82992bdabfdbfeceaaa9f691c6e0c5f23823a463538da752ecfa77f23cee2") },
                { 126600, uint256S("0x96979bb89d506daeec90e4edd8ef2280692cf02e108acd357401b89a64b747e2") },
                { 126800, uint256S("0x183e0ab5c48d3c7f332c7d98bb3c8418c3dfed386ca5e3f4f424c3943d3f7937") },
                { 127000, uint256S("0x323e69f9713a0d5c0a83427e70e4fa5c5e2693cc8ee0e5d4c4e91adb6f982633") },
                { 127200, uint256S("0x4b853cc3acd2ffa7f5f70c5d261ccaa701f200fc8ee12c07581aa184078a9450") },
                { 127400, uint256S("0x2c2178a07dc3a0bbd6434da620817c1f5c55e65c1f281ef16b10b9933270763b") },
                { 127600, uint256S("0x69b2b86cf0afb480a1169edde2814dc55b66e6c4b10452f78cc2089d12c37173") },
                { 127800, uint256S("0xafe0af1e9c119074f5ce6e952c1687219da1a5fa1a2d2305d1a8aba6439495fa") },
                { 128000, uint256S("0x94ebf25c1db0e170e5d3c6529f2e453ce2edac11984ac9b94c1c61eda76d7d42") },
                { 128200, uint256S("0x57c1f48e18c27a6a9cca18b80d0d86e5a71bc93ce88530296160dccbc6ae0f2d") },
                { 128400, uint256S("0xb007a6b1f649208aba2c928af1ecc7c17c77e6e4d80a6d27e8159ee2407a1fd0") },
                { 128600, uint256S("0x6a1bf6195b9111f3238256e954140b23afb6bebfb53599d4917b8894252b2efd") },
                { 128800, uint256S("0x593194a6f6caf0ea808bfe583dbe164abdd5e039c107a9d801c295506e52a2b5") },
                { 129000, uint256S("0xc58f6d8bc07ca5e899440bf487474b09f4e139de83defb6b6f36b8e1c49954ec") },
            }
        };

        chainTxData = ChainTxData{
            // Call by getchaintxstats
            // Data as of block 3971f056b5f11e140965e0e122b370721abd1d2be6c3c14c9f07d3dcdef50bbe (height 111800)
            1541402143, // * UNIX timestamp of last known number of transactions
            127941,     // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.012       // * estimated number of transactions per second after that timestamp
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
        consensus.BHDIP006CheckRelayHeight = consensus.BHDIP006BindPlotterActiveHeight + consensus.nMinerConfirmationWindow * 2;
        consensus.BHDIP006FirstForkBlockHash = uint256S("0x44fe5f2d3e7b9fbf771c1fc2ae400daf0ef31665c3eac3cac3a0e3ba7a968f32");

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
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

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
                // Offset +200. Generate by `createcheckpoint`
                {   8600, uint256S("0x85328fd04bf8ece91dbb0e5d494059517a579c09e1c00cb1699aa832de42f825") },
                {   8800, uint256S("0xf14c42e69b3c198056e07180babde80284b27b5c23824a32f0d83f07ff646f1b") },
                {   9000, uint256S("0xf6d498706e76904cf7404f0d701d542755713d8e238af3f2aeea5c228b0c4d79") },
                {   9200, uint256S("0xd942d1693ece83b1ac615a6e7afeb25572c2fc9141038f771394f776dee71786") },
                {   9400, uint256S("0xa783594a1a2a50c208926f8ea23126b7ee996ff35b7ca108173127ad9f939e60") },
                {   9600, uint256S("0x02e5872a4215f2efdef8d099794e1a0f28ab63b5fd757e1d3191312b7d8ff257") },
                {   9800, uint256S("0x4d4b60e63eed7965adb93da0505fbc8557d8158a2b1f5c466c4c02628dced604") },
                {  10000, uint256S("0x8912d6c4b3666e16db738c5b9253760da60140c6f6da4677c3c65a922c562981") },
                {  10200, uint256S("0x92e5937bfec6d5fcac37140eb1aa2664ff2ded1c94700eabd0d7f660dac5a44d") },
                {  10400, uint256S("0xfb37771afc6e3aa4ec68143ab25e84d01024bdf343381026c5f4fb6e14e0f41e") },
                {  10600, uint256S("0xa136f33c136af5827167ffab5d6abbc37e28bc9f937364cab192e648f84b51be") },
                {  10800, uint256S("0x5ae93a9baa8308d2d617d4ed1fb3c00b87e4a0e6030da4f24ea697266d1c3692") },
                {  11000, uint256S("0x0437ad4d012411f2c2866aa6f7a57d87cdafe88b24eae2c4035b49e9621abbbb") },
                {  11200, uint256S("0x5392c7182127ec85dd98e6722562f1a4acfaa9bcd43f006e98c308580b0341ed") },
                {  11400, uint256S("0xf61b86d776d9a766c166d8591cbe209eb605dd1034ec99852bbf43d0d5a54406") },
                {  11600, uint256S("0xa69dfe619cc688655b1b97d0afdccee7906de1cf53364fd0ffcb45ab53df5be8") },
                {  11800, uint256S("0x8eda07f1153559deb2d3281992e57efed770ab4469578e324a3b365e6b418809") },
                {  12000, uint256S("0xf274f4f16024e66139babad61b953f6e670dcc7ce729519013169491324afa42") },
                {  12200, uint256S("0xe1a0a9ea9feb2a50a1487645e3491245d7315f91648a98d9ee16f951bf1b98c8") },
                {  12400, uint256S("0xf8488fafd7732a0f1a6033e8e5c484f4179e8a2c150770aaa9e54b6a4f8e72c4") },
                {  12600, uint256S("0xbe9e5689e4079414df2d3388b2ba0e814be28ed0fc7a0ed4300d2e2049a4275e") },
                {  12800, uint256S("0xed7d4029a83c504ad56df0f56c3f5475c3c1c4a55fbd91a2b10eec02bf38aff3") },
                {  13000, uint256S("0x3d24ad7d4fb9e8aea19f53a8438c7ab8fb11057b95b0da667d61d826d567b22a") },
                {  13200, uint256S("0xe492ad8c30bc67224d5a8752be1f911655280150c4062d16ecbad55a8a622a6e") },
                {  13400, uint256S("0x64c850c8738829d42610ebcff14d3ad36328012af44cfcd1ab35f136e2ab2a8e") },
                {  13600, uint256S("0x3ff4161e9bc0be45ef5531c1004a08c8db358fbcb6bce518dfcd1054cb70fb01") },
                {  13800, uint256S("0xa9af533d7fe11d354bd82bb627d71ad9ca950bc2fca57161afc00455bd4bd63e") },
                {  14000, uint256S("0x225060edd20c722111a96eb7f1947a9cca58755f524fc8c23a6d64fe7fc5be92") },
                {  14200, uint256S("0x36b130f3d40f2fbe0c155a5e7f28e5a2d321d6c71058ccb836c6759f3433f83d") },
                {  14400, uint256S("0x4f9e709946cab6df9400e141220bddcbd48c1ee6583a0deb6a672a941fdca298") },
                {  14600, uint256S("0xb7ece82a608d49a4a8271df2d78685765c3b913bc5c6cc3404c435f6a2564531") },
                {  14800, uint256S("0x7706c068b9891ea7f159883472fdaa39a4def4ba70df6b75e1adaa0002adbf32") },
                {  15000, uint256S("0x280971724545fa94d13d3d638cac4f7652e55ae83abf43f2b91d87a692cade35") },
                {  15200, uint256S("0x6b7a77818fdd300b8895b89ae0382a99a00b0325d705edd0d7642ef8a344881a") },
                {  15400, uint256S("0x232a865e78ef684b58ca809b1036bbbf7c4499258866276d031198fae4e1e5a0") },
                {  15600, uint256S("0x4e46913b2878167139c8cacb005d1764a06bc7ab2b6b02dbf77dde91405a8958") },
                {  15800, uint256S("0x686a1a496d4b4a3105d5fb71667ee13905e5da9349b69967d5eb23b4b08f24e0") },
                {  16000, uint256S("0x32e35edd797596ce166609b58f6ee6b920f8e60bfc7f4131f98ae21faa8398b7") },
                {  16200, uint256S("0x2919001193aa1c91a12a6781706bec99f38c3e6e5edaecd5b9ee9f220b51681e") },
                {  16400, uint256S("0xe0c30968a9610013caecba184248c68b0a9041bd66d74e8506968e5110b27fa5") },
                {  16600, uint256S("0x3495c0b4c906bf8df5157a32cd1050135271ddbeefbcd16065b5cfeb86aa2c4b") },
                {  16800, uint256S("0x78c484aee4fac3abfb6bf5b2cec4b12d1a8bd8fa35e5518a544c401ec593460d") },
                {  17000, uint256S("0x37df13069ca3e02d06cfd5f20a4895f2300a4bec851c5a28bcba3176fb6bcc5c") },
                {  17200, uint256S("0x19f9f59ad514fe1a9996f85c304221c50b37f70e28e56a84160eb6ee6b037fc1") },
                {  17400, uint256S("0x2e20f3f1e62109787351e8c53ed65492ab3c426541da0f8c9886bfdb6d58c542") },
                {  17600, uint256S("0x05b82006dd22da3d4240bab8f67ea39edc5df99bb5b50bdff6abdf304ce336fa") },
                {  17800, uint256S("0x081bd7d95fe7b81e075e6ae72cbf08b48b37eb4e84edb89660a6bc4675748091") },
                {  18000, uint256S("0xd0b4e5638db1d664dffc561a6c4c9f6bf691c376a36ccbfc412418c4aee03df1") },
                {  18200, uint256S("0xc0d7ce0360ef24826bfaccb3f56ec58361f33624a0bcff17f5250dbec6539cc2") },
                {  18400, uint256S("0x16efe81c2f3a5726c5b27d3f828d9763fdae416a6739bba3af6f24e52cce7e9b") },
                {  18600, uint256S("0x84ee3fd48a2baf871cc01894662522386b0cf9a25c2daac6db11a7d4990ec1ea") },
                {  18800, uint256S("0x10fbf984dcf0c9ff960e6dffaccbc9a09e6f62cd9303ff991d61d11bdcb41a5c") },
                {  19000, uint256S("0x0f8132de13286db54e4a8e4ea173af29c9b959dbbdcc206e674c56e6532406cf") },
                {  19200, uint256S("0x962341534eeace57ec01901d5aaa739b02ac977616846cff04bfba80f91ed879") },
                {  19400, uint256S("0x3664dfbde4ca1432ea923fe3a860ecf357253698105485646a1ece7ec99a57b8") },
                {  19600, uint256S("0x5464a77853768eeeaab979f839501fda75e220286a7060ccff0be54229367024") },
                {  19800, uint256S("0x0a0becad14ce416f648e952ebebf4cb4613d2053773a7cd4fe9275cea2dc5e57") },
                {  20000, uint256S("0xd886caeac8c821716d0cab7a1ffc58836eca7e24193c0fb7cdb0ccf0f08f8eea") },
                {  20200, uint256S("0x8fdc2c82b7580a0e239e6854ca3163e91664d9e490f166097b6156a4ace887c9") },
                {  20400, uint256S("0x901950f64342f91c2aa742db4ebe4ffa428cd74c746c871a305f424104e0954e") },
                {  20600, uint256S("0xaa4e42277be1490e0073596b60aebdbe5985538a9337174e3e8196471866582e") },
                {  20800, uint256S("0x5a38b435bb47752d67a487b4889bed60a814bac60289764e17807853f9607135") },
                {  21000, uint256S("0x276c4ebfbecfd90b9cad397f78907604569f772c91c223247b6f3354e71b0dcd") },
                {  21200, uint256S("0xa72087d2b5dc89603ccad534f0c2cc69c2ea4aac9f4412eafc1f8553dfac8cc6") },
                {  21400, uint256S("0x017599ba5e3d3d7c544cfe0eeea98204021cd9ffc7024a5be51d0bb90fc29876") },
                {  21600, uint256S("0xb537d4a8e1192853305d7e339b993182d585e34b72ea0520765be6d41d5d8140") },
                {  21800, uint256S("0x35a87e36579b077bacbd043b1ff9d2192bd77626c821b4cf4642c6cc54ba6a31") },
                {  22000, uint256S("0x54ebf72c827700d162290d8369321266d78443d43387ed4dacc6bcc8e8dee61c") },
                {  22200, uint256S("0xd68c5fc927284d47b414eaad093b2714cfe7d4d10a0545ce441992d817e9c457") },
                {  22400, uint256S("0x6afbc26f595168e4ce1aa6de53f98b151e978156bd985bfa336eea741f438adc") },
                {  22600, uint256S("0x47676c21d5620f2d892685f58e65ea16a5d81872d731d56eda95cbbfbb570d44") },
                {  22800, uint256S("0xf71b469bff33044a2f5fac4d2aed2cf31648afa4456a5375657193b5e2be959a") },
                {  23000, uint256S("0x0b0885eb92f712cf502c6adeef8e13e7b96c50cecc0e6f9972844be2cd66a578") },
                {  23200, uint256S("0xd603db91e3cbbb4fa9e49490804608057cdc84ff2f3962690b25e3c84836ff37") },
                {  23400, uint256S("0x358d3b36b1878b061e13b6b3d07ccc8b836e8a7d309c4852537848263caa0e00") },
                {  23600, uint256S("0x5ae6f3ea4de3551098d1e70416bc1d02a1c495a9a03dc928d7ea50412e9bf459") },
                {  23800, uint256S("0x473800ed99a85d4297e1432a1737dc335f1b57e74023a457857cd680b6a45e73") },
                {  24000, uint256S("0xb0f1ce1964d04acc6e0ce02db2c1874b83811d973d025b95b8f927c94ba622d6") },
                {  24200, uint256S("0x13a50b92f4778ad1f3f2503074ea4dae1b30e92dd82905a571c647132bd9d53e") },
                {  24400, uint256S("0x0aa69596bbacd0cfc64086b21a7552ee71a04158adba0d5d2049d78de459dfcd") },
                {  24600, uint256S("0x4d5bc72be9686e35d8e9c19ac5a5db74463061b18d7ce6673e7bf1088da861da") },
                {  24800, uint256S("0xcedb957909963b6c1e655154c32d4bb84b6c2fe25c7c627b75e9f196b53b9633") },
                {  25000, uint256S("0xb754a47f674d6489a9c0c2723912f98fb25fccc09c344eba7d7b9e175abd5284") },
                {  25200, uint256S("0x4590c318e25f255c66720e85c1299ca5a829e74f584329c1bd77faba2c07d5d9") },
                {  25400, uint256S("0xb05b8cb7992e5f57bd73967abb779f7c3dee7112e25343cac1fca26abb937933") },
                {  25600, uint256S("0xd7b0e3c601324e6781736694462406bbc4c4556d82d18270dd1d14b98f70366a") },
                {  25800, uint256S("0xf9846c3bab88a03914ac98007fed243904337e93ff544151dbb9d6cd73c9a5d9") },
                {  26000, uint256S("0xbacd9dcc2147915a3e84b0b24addad37c3f57c1cea01ea0483220effeac2ed0f") },
                {  26200, uint256S("0x00e993e8d2ef2df7b4b49bccfc3e34344ced382de590358de9f430e4c9354422") },
                {  26400, uint256S("0x01da2cac89e449a2c08c1d0113a3aa1f20db19b6a44d2ae9524525394be745eb") },
                {  26600, uint256S("0x2f3bf28bed8174efff68e28205ad3c787e392aadbcee2253fb85a3834b3f1b00") },
                {  26800, uint256S("0x7bd250cac8f857c017f7fced374f9a5f9890ce99b38c66d8fb39cde92360a0ce") },
                {  27000, uint256S("0xbf6521f94f267e1a81dc479324340e5065c569f38449556be418e5b0909b9c44") },
                {  27200, uint256S("0x19b1e1d875f54d8c0970e674d75e5ea2efdecc00ad842e234cf3372d581bdd44") },
                {  27400, uint256S("0x94ee6f4d2632cc106f26096e08276816f69cfe6659973590106b637746a7e601") },
                {  27600, uint256S("0x000b11cb10ac59b4b6a1e92e7391ee008bfa9d23e2b6014cd62b47ca64023109") },
                {  27800, uint256S("0xf4f2e881c3ed60642d05450d378ea17be46fb1ea4ffe7b4ab19f7ad2c6f17c6c") },
                {  28000, uint256S("0xd119dc0c48a3071ea2e1522fa758e85717c9a19fbab7542b3890b3076a13851a") },
                {  28200, uint256S("0x5335f9f27bd93fb7eff52efbf64a420bd25e82be7bcffc1385acc9ca8deb05f1") },
                {  28400, uint256S("0xcc771df479eb12b55905aa80907b2af61230ed4b6a3dd977402ae970dae8bf2c") },
                {  28600, uint256S("0x01ca25b69bc0396c52fae4275953e8bbf624994f654c7f5eb236cdfbb3f2dce2") },
                {  28800, uint256S("0x38cfaba3232b4d0d381998dbfd0e5468b39e980f882618eff065ae91efbdfb23") },
                {  29000, uint256S("0x0af437183e3c1d4d1b4d7f47237ac7f504aa1194d6cf58c872841e9d31603302") },
                {  29200, uint256S("0x024084a26a732623b98f47e9aaf1f22064f7d578f4a4adf062b9d5fa60a9ae21") },
                {  29400, uint256S("0x410dde0595150255e005037554d1452fc74416f600d89dde5060f2ff444d603e") },
                {  29600, uint256S("0x177f7b7bca605ff7843bad1d7910db550d285ed4ee5baabcb23711c52d72a98a") },
                {  29800, uint256S("0xe7e706f9a9aa3ae0082353a125eae7e99e49efe87366788a7963459b7d38d342") },
                {  30000, uint256S("0xc8c0367622ced32dd3c4793d974e04d672d8f88115149445f37c6c5950bfe9b2") },
                {  30200, uint256S("0xc5f13540ed0ddc4b093e77981acf073ad2c858b390439c062dcf464f612ccb88") },
                {  30400, uint256S("0x2065040268fd28ef97d004dc1666bc9e4ec3558634c947b5d2f9052997dbdab3") },
                {  30600, uint256S("0x8aa1257fcf39a89bd4bc36aa1690befd39da437cbf94e6e27626041986fa3c86") },
                {  30800, uint256S("0x8dc3518ee5e3b10b5f28b2c531a1bcf9bd8d11116585d346405b0fe718ac6cbc") },
                {  31000, uint256S("0xc5d44ac59d740717fa04e1709666c9e98766c638b7d20fcb9d30bc8c59033a17") },
                {  31200, uint256S("0x129e966eb85961538e6218a88e3c1a44bb800706b483162b533d4c88d7ce47e4") },
                {  31400, uint256S("0x74936f2685bca536667a4b191b2e6efa997e9ce7efc5bfb3254d9ab334abe956") },
                {  31600, uint256S("0x0afbcd4516578b6f2239a2e831eefd1cb3aafebbdd59e782ddc4213c9ad0dcdf") },
                {  31800, uint256S("0xb2fb32f6299b6fed1fd37ece0a948e195d9e8485f35a4fe769421eb153ed32d8") },
                {  32000, uint256S("0xb7f29370d35409bfaf79715785ec44d73cb653c34d80190dced08e19af0d800b") },
                {  32200, uint256S("0x99e89868ee98de2ab982f2d8500651703b6fbd77db09a71e96af48ebec7e9adb") },
                {  32400, uint256S("0xb322dbda5a8ba2e4e71884a051624bc2bcd8129d1452fd30630181753320dc4e") },
                {  32600, uint256S("0x7ffb99bc7122f731de33eaed79ffd7dae108901504d56f5ef72a4935f2690299") },
                {  32800, uint256S("0xff1aecc476842fdcb07d1d4e3b2d28f611805bf781f0f7f6afc952d22c0541d0") },
                {  33000, uint256S("0x21b8ac3f7d40232e4ffd913e91f9bda6f1834812df5806df9af58ad1b17b235b") },
                {  33200, uint256S("0x6bbd62a4c08a2409bf675fd4aed90b13cc7a4cab17312b738240556d5d8f4f6e") },
                {  33400, uint256S("0xc5f7753cbd013887b574f923829e1ff172c7a41dd59b3c2c096a6feb18674676") },
                {  33600, uint256S("0x066563147205288b4e872e7870f9af4c06a0b73f6668e85a59953665951b0f48") },
                {  33800, uint256S("0x8871314ed052d470c6127332bd2bb99329e7d431e591d467d6e8145a0de3eabe") },
                {  34000, uint256S("0x941e0ef9fe8f8c1e1a05fcb4644b655b659f5d5dc64a1d9f946e450bcdd64fd6") },
                {  34200, uint256S("0x0191394b65eadba5c245201c61b9860c462cdd59bb7ee07710664977430a9a0b") },
                {  34400, uint256S("0xb4b924acf3268b434143a7d25271c04c7e94f20eadb27574f84f4c77e8c8da15") },
                {  34600, uint256S("0xe8c6706b38f8ba71470e3b7e41339ceb489b0f7025bfe777f03e89ec501d8e7a") },
                {  34800, uint256S("0xe33dd06ffc8a5b64eda06aa8c7bfd636006d1d4df9c60cbbb68559d7f7f98018") },
                {  35000, uint256S("0xafab1f8f1368a9787b42f41ebc442a99dde6649c36a8f38f17641f310562fd3a") },
                {  35200, uint256S("0x6bf3f89626dfa436b3ab0c46ad69399cc3bc07d52f8bd4ef4ad16499c9faff0c") },
                {  35400, uint256S("0xcaad7c2d5ca4c664ef750c86d5b0b392f5db6eda0f1bcb917815207a73d180c2") },
                {  35600, uint256S("0x18eff9a2ccb1866c84ae73a8c70e2486faa182f4e509571dec26a3e55ed2ae08") },
                {  35800, uint256S("0x1e2ffaee43c7f7a797600b8bcc400709eb6e7b4840c65db69ea955cb6ff0c35f") },
                {  36000, uint256S("0x91f802d19f2d24e3ae85a1fc3e30dd2896bb2469410ed5532d9bb7811427e2b0") },
                {  36200, uint256S("0xd2bf8f0f6ac5fbba798124434e4bcd08c5705a5cf9135054ad6e292f0097a27b") },
                {  36400, uint256S("0x7e97bd05b93b1fe85421beb8fcff347e84c99db89143cdb2424a3f1f6c3cad01") },
                {  36600, uint256S("0x7ba9c5f31225a01cdf6ba519f4e44aa5f82ff6ab148da72af58053f03132b3af") },
                {  36800, uint256S("0x038f628b3c17d57bc91d619ab0443e574c9b8536232c5a9a94d25d4b134ca78f") },
                {  37000, uint256S("0xf5c65d46e2b95bad3ca951cddd03cd77650870d39aa5f756a9ea9490d9040047") },
                {  37200, uint256S("0x48491d5c7f6be9d2b504497ca52950b8e08b809ebb2b05ec2fbf7d7d7247a7fe") },
                {  37400, uint256S("0x584799a4d07468cc3d5e64626b525cd90ec043639558bf6eb1d7f4e2e42fe364") },
                {  37600, uint256S("0xd5386c63f6f5c73e04a1f1280e5482a9272679b6fce12f3897827ac202351361") },
                {  37800, uint256S("0x418a6030246e05577a36a9ab6875c2c9c93fe4de5444eee7d2b925cca03e8f6b") },
                {  38000, uint256S("0x4496f906d81728a522dc5e5e8c4784df4663da9b7063f1e5e6ffd1474ef61fec") },
                {  38200, uint256S("0xaea86c88506cb1ab37f6446dfde3624fea54f5952e03f4fe2889c60d43cced9f") },
                {  38400, uint256S("0xcf2500a988401dbf1f1c6c97c16b275e2dcc620e04375756a32cb5525c63dd46") },
                {  38600, uint256S("0x0029c4f1914c75a0a4b01e01c0e5e88dd948df0ba18ceae86a180f363ee68e76") },
                {  38800, uint256S("0xd0f886c705b8c5ceaa93d21657af6fb7911b013c4eb6256027819410e51969a6") },
                {  39000, uint256S("0x1a16d2bb21d44e0399badc33d5215b32ccaeccd77721af3bd61be66e1db2bfcd") },
                {  39200, uint256S("0x814bd3cd570b67c1261ab75fb4731884777b5cda3e9e2c2d5af2ded8aed87ed7") },
                {  39400, uint256S("0xaa09c0cbefb906480be2094e635fc11c02133fe6a85d982e9e7122c26635c096") },
                {  39600, uint256S("0x3d245a2275105cbd439bbe0316b5a071973a2213693b55bcbcd6ab52f822fb2b") },
                {  39800, uint256S("0xda240dd081bfce036f5002fe0a84f1c4aa06e2b4756b4f74562ad48b11c1d492") },
                {  40000, uint256S("0x5e968add124371c1d5fe4cd2171d45d2c8a11dea1339eb1ade25cb9725a0a56b") },
                {  40200, uint256S("0xeddf5451a8912d27cd5af3bfb358894304f5e2caf2757aded259f2479e8e40b1") },
                {  40400, uint256S("0xbe386442f33b4c35bd15f2c6d04f941d52684be031a4a1409247321f7666289e") },
                {  40600, uint256S("0x7d7a35e15c0e9f2299b6712cd2ae7877cf33d5c0c6cec80b14c9b5f82e810bc0") },
                {  40800, uint256S("0xd70f30d32ac04b398a9fed8a785a9d45c91661cf8194b9f6345f635037c5a5c7") },
                {  41000, uint256S("0xf5aba9e950da5e44d1a8c1d2bdd616fba62a6e6c226492436782ad7fda3bcd72") },
                {  41200, uint256S("0x7e69b9de8f46fa350e59f3dd8ec84c95c1f070f471020d35df1bf7c9043eb33b") },
            }
        };

        chainTxData = ChainTxData{
            // Data as of block d119dc0c48a3071ea2e1522fa758e85717c9a19fbab7542b3890b3076a13851a (height 28000)
            1541402510,
            28197,
            0.003
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
        consensus.BHDIP001NoPledgeHeight = consensus.BHDIP001StartMingingHeight + 10;
        consensus.BHDIP001PledgeAmountPerTB = 3 * COIN;

        consensus.nSubsidyHalvingInterval = 300;
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
        consensus.BHDIP006Height = consensus.BHDIP001NoPledgeHeight + 200;
        consensus.BHDIP006BindPlotterActiveHeight = consensus.BHDIP006Height + 50;
        consensus.BHDIP006CheckRelayHeight = consensus.BHDIP006BindPlotterActiveHeight + consensus.nMinerConfirmationWindow;
        consensus.BHDIP006FirstForkBlockHash = uint256S("0x00");

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
