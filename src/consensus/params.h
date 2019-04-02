// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <amount.h>
#include <uint256.h>

#include <limits>
#include <map>
#include <set>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    /** BitcoinHD Fund address */
    std::string BHDFundAddress;
    std::set<std::string> BHDFundAddressPool;
    /** BitcoinHD fund pre-mining height */
    int BHDIP001StartMingingHeight;
    /** BitcoinHD fund royalty percent */
    int BHDIP001FundRoyaltyPercent;
    /** BitcoinHD fund royalty percent on low pledge */
    int BHDIP001FundRoyaltyPercentOnLowPledge;
    /** BitcoinHD miner no pledge height before */
    int BHDIP001NoPledgeHeight;
    /** BitcoinHD miner pledge amount per TB */
    CAmount BHDIP001PledgeAmountPerTB;

    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;

    /** Block height at which BIP16 becomes active */
    int BIP16Height;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;

    /** View all BHDIP document on https://btchd.org/wiki/BHDIP */
    /** Block height at which BHDIP004 becomes active. Some block error, fork begin height */
    int BHDIP004ActiveHeight;
    /** Block height at which BHDIP004 becomes inactive */
    int BHDIP004InActiveHeight;
    /** Block height at which BHDIP006 becomes active */
    int BHDIP006Height;
    /** Block height at which BHDIP006 bind plotter becomes active */
    int BHDIP006BindPlotterActiveHeight;
    int BHDIP006CheckRelayHeight;
    int BHDIP006LimitBindPlotterHeight;

    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];

    /** Proof of Capacity parameters */
    bool fPocAllowMinDifficultyBlocks;
    int64_t nPowTargetSpacing;
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
