{
    "logging" : {
        "config" : "information",
        "general" : "information",
        "logfile" : false,
        "miner" : "information",
        "nonceSubmitter" : "information",
        "output" : {
            "dirDone" : true,
            "lastWinner" : false,
            "nonceConfirmed" : true,
            "nonceFound" : true,
            "nonceFoundTooHigh" : false,
            "nonceSent" : true,
            "plotDone" : false
        },
        "outputType" : "terminal",
        "path" : "",
        "plotReader" : "information",
        "plotVerifier" : "information",
        "progressBar" : {
            "fancy" : false,
            "steady" : false
        },
        "server" : "fatal",
        "session" : "error",
        "socket" : "off",
        "useColors" : true,
        "wallet" : "fatal"
    },
    "mining" : {
        "benchmark" : {
            "active" : false,
            "interval" : 60
        },
        "bufferChunkCount" : 16,
        "cpuInstructionSet" : "AUTO",
        "getMiningInfoInterval" : 3,
        "gpuDevice" : 0,
        "gpuPlatform" : 0,
        "intensity" : 0,
        "maxBufferSizeMB" : 0,
        "maxPlotReaders" : 0,
        "passphrase" : {
            "algorithm" : "aes-256-cbc",
            "decrypted" : "${passphrase}",
            "deleteKey" : false,
            "encrypted" : "",
            "iterations" : 1000,
            "key" : "",
            "salt" : ""
        },
        "plots" : [${plots}],
        "processorType" : "CPU",
        "rescanEveryBlock" : false,
        "submissionMaxRetry" : 10,
        "submitProbability" : 0.999,
        "targetDeadline" : "${targetDeadline}",
        "timeout" : 45,
        "urls" : {
            "miningInfo" : "${miningInfo}",
            "submission" : "${submission}",
            "wallet" : ""
        },
        "useInsecurePlotfiles" : false,
        "wakeUpTime" : 0,
        "walletRequestRetryWaitTime" : 3,
        "walletRequestTries" : 3
    },
    "webserver" : {
        "start" : false
    }
}