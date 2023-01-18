#ifndef __CA_GLOBAL_H__
#define __CA_GLOBAL_H__
#include <unordered_set>

#include "common/global.h"
#include "proto/ca_protomsg.pb.h"
#include "utils/CTimer.hpp"
#include "ca_txconfirmtimer.h"



namespace global{

    namespace ca{

        // data
        #ifdef PRIMARYCHAIN
            static const std::string kInitAccountBase58Addr = "16psRip78QvUruQr9fMzr8EomtFS1bVaXk";
            static const std::string kGenesisBlockRaw = "08011240306162656230393963333866646635363363356335396231393365613738346561643530343938623135656264613639376432333264663134386362356237641a40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030302a403432613165336664353035666532613764343032366533326430633266323537303864633464616338343739366366373237343766326238353433653135623232b60208011099f393bcaae0ea0222223136707352697037385176557275517239664d7a7238456f6d74465331625661586b3a40343261316533666435303566653261376434303236653332643063326632353730386463346461633834373936636637323734376632623835343365313562324294010a480a403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303010ffffffff0f12420a4047454e4553495320202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202018ffffffff0f4a2c088080feeabaa41b12223136707352697037385176557275517239664d7a7238456f6d74465331625661586b3a240a223136707352697037385176557275517239664d7a7238456f6d74465331625661586b5099f393bcaae0ea02";
            static const uint64_t kGenesisTime = 1653004800000000;
            static const std::string kConfigJson = "{\"info\":{\"name\":\"\",\"logo\":\"\"},\"sync_data\":{\"interval\":10,\"count\":200},\"http_callback\":{\"ip\":\"\",\"path\":\"\",\"port\":0},\"log\":{\"console\":false,\"level\":\"OFF\",\"path\":\"./logs\"},\"server_port\":41514,\"server\":[\"36.152.125.110\",\"211.139.121.162\",\"211.139.122.22\",\"221.130.95.102\",\"221.130.95.110\",\"221.130.95.78\",\"221.178.209.102\",\"221.178.209.14\",\"221.178.209.10\",\"221.178.209.98\",\"36.152.253.86\",\"36.153.194.74\",\"36.153.195.250\",\"36.153.196.254\",\"36.153.197.34\",\"36.153.198.234\",\"36.153.198.242\",\"36.153.198.246\",\"36.153.199.186\",\"36.154.216.186\",\"36.154.216.190\",\"36.154.220.146\",\"36.154.220.150\",\"36.154.220.154\",\"36.154.220.166\",\"36.154.220.78\"],\"ip\":\"\",\"thread_num\":0,\"http_port\":41517,\"version\":\"1.0\"}";
        #elif TESTCHAIN
            static const std::string kInitAccountBase58Addr = "19cjJN6pqEjwtVPzpPmM7VinMtXVKZXEDu";
            static const std::string kGenesisBlockRaw = "08011240613938396462353936653637653538343563313065313532333231613830646362353730663732386361323033303834336363613662646261393837663664621a40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030302a403535626137366362616136653964646261333639646262633635363331373837633435646235643538356361333461366361386433313066623965313539343532b602080110909fcaf8b8bef20222223139636a4a4e367071456a777456507a70506d4d3756696e4d7458564b5a584544753a40353562613736636261613665396464626133363964626263363536333137383763343564623564353835636133346136636138643331306662396531353934354294010a480a403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303010ffffffff0f12420a4047454e4553495320202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202018ffffffff0f4a2c088080e983b1de1612223139636a4a4e367071456a777456507a70506d4d3756696e4d7458564b5a584544753a240a223030303030303030303030303030303030303030303030303030303030303030303050909fcaf8b8bef202";
            static const uint64_t kGenesisTime = 1653004800000000;
            static const std::string kConfigJson = "{\"info\":{\"name\":\"\",\"logo\":\"\"},\"sync_data\":{\"interval\":10,\"count\":200},\"http_callback\":{\"ip\":\"\",\"path\":\"\",\"port\":0},\"log\":{\"console\":false,\"level\":\"OFF\",\"path\":\"./logs\"},\"server_port\":41515,\"server\":[\"120.79.216.93\",\"47.108.52.94\"],\"ip\":\"\",\"thread_num\":0,\"http_port\":41517,\"version\":\"1.0\"}";
        #else // DEVCHAIN
            static const std::string kInitAccountBase58Addr = "1zzF8jNBAXFTPJzhvY45zLKgQmnPLBZ93";
            static const std::string kGenesisBlockRaw = "1080c0bbe4fbbdfb021a40323634616237303938393466346666623130303031623038613339643564333637313639633163356438303662356631656338373534393438326661646136302240303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303240656239346566363661363066353036373564616633376234326465303135343239323264363863356636646235303434353964356566656633656464623262383afc031080c0bbe4fbbdfb022221317a7a46386a4e4241584654504a7a68765934357a4c4b67516d6e504c425a39332a406562393465663636613630663530363735646166333762343264653031353432393232643638633566366462353034343539643565666566336564646232623832fc020a21317a7a46386a4e4241584654504a7a68765934357a4c4b67516d6e504c425a393312b6010a420a403030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303012700a40471d181cd178ca304fbc20ebafa0e10fc2735206f4ba5870c46c5766a9399a7c8ea635f83d1108b48b628028802911538d6c5735e263bdcdeeacc67c66970f0a122c302a300506032b65700321001ab774b60d663caa75dca38ea29fa3742d082b49fe1b620c7ca13b38499fe7bd1a2c088080b68be8ceb70c1221317a7a46386a4e4241584654504a7a68765934357a4c4b67516d6e504c425a393322700a40f47230de8dfdbcf25296039acee93262de086ac37bcc2d97eff09446803ee30808684b4c3202fc31f1cd012bc6856da8788eaea275a65fe338115dc87308b309122c302a300506032b65700321001ab774b60d663caa75dca38ea29fa3742d082b49fe1b620c7ca13b38499fe7bd3a0747656e6573697358ffffffff0f42287b224e616d65223a225472616e73666f726d657273222c2254797065223a2247656e65736973227d";
            static const uint64_t kGenesisTime = 1668988800000000;
            static const std::string kConfigJson = "{\"http_callback\":{\"ip\":\"\",\"path\":\"\",\"port\":0},\"http_port\":41517,\"info\":{\"logo\":\"\",\"name\":\"\"},\"ip\":\"\",\"log\":{\"console\":false,\"level\":\"OFF\",\"path\":\"./logs\"},\"server\":[\"52.52.118.136\",\"13.52.162.66\",\"223.113.164.228\",\"223.113.164.226\",\"223.113.164.229\",\"223.113.164.230\",\"223.113.167.250\",\"223.113.167.246\",\"36.153.133.250\"],\"server_port\":41516,\"sync_data\":{\"count\":50,\"interval\":100},\"thread_num\":256,\"version\":\"1.0\"}";
        #endif

        // consensus
        static const int kConsensus = 8;

        // timer
        static CTimer kBlockPoolTimer("blockpool");
        static CTimer kDataBaseTimer("database");
        // mutex
        static std::mutex kBonusMutex;
        static std::mutex kInvestMutex;
        static std::mutex kBlockBroadcastMutex;

        // ca
        const uint64_t kDecimalNum = 100000000;
        const double   kFixDoubleMinPrecision = 0.000000005;
        const uint64_t kTotalAwardAmount = 130000000;
        const uint64_t kM2 = 70000000;
        const uint64_t kMinStakeAmt = (uint64_t)((double)5000 * kDecimalNum);
        const uint64_t kMinInvestAmt = (uint64_t)((double)5000 * kDecimalNum);
        const std::string kGenesisSign = "Genesis";
        const std::string kTxSign = "Tx";
        const std::string kGasSign = "Gas";
        const std::string kBurnSign = "Burn";
        const std::string kVirtualStakeAddr = "VirtualStake";
        const std::string kVirtualInvestAddr = "VirtualInvest";
        const std::string kVirtualBurnGasAddr = "VirtualBurnGas";
        const uint64_t kUpperBlockHeight = 4;
        const uint64_t kLowerBlockHeight = 1;
        const std::string kStakeTypeNet = "Net";
        const std::string kInvestTypeNormal = "Normal";
        const uint64_t kMinUnstakeHeight = 500;
        const uint64_t kMaxBlockSize = 1024 * 1024 * 1;
        const std::string kVirtualDeployContractAddr = "VirtualDeployContract";

        const int KSign_node_threshold = 15;//15
        const int kNeed_node_threshold = 45;//45

        const uint64_t kMaxSendSize = 100;

        const int TxTimeoutMin = 30;

        const uint64_t kVerifyRange = 600;

        enum class StakeType
        {
            kStakeType_Unknown = 0,
            kStakeType_Node = 1
        };
        
        // Transacatione Type
        enum class TxType
        {
            kTxTypeGenesis = -1,
            kTxTypeUnknown, // unknown
            kTxTypeTx, //normal transaction
            kTxTypeStake, //stake
            kTxTypeUnstake, //unstake
            kTxTypeInvest, //invest
            kTxTypeDisinvest, //disinvest
            kTxTypeDeclaration, //declaration
            kTxTypeDeployContract,
            kTxTypeCallContract,
            kTxTypeBonus = 99//bonus
        };

        // Sync
        enum class SaveType
        {
            SyncNormal,
            SyncFromZero,
            Broadcast,
            Unknow
        };

        enum class BlockObtainMean
        {
            Normal,
            ByPreHash,
            ByUtxo
        };
        const uint64_t sum_hash_range = 100;
    }
}


#endif