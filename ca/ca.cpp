#include "ca.h"

#include "unistd.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <random>
#include <map>
#include <array>
#include <fcntl.h>
#include <thread>
#include <shared_mutex>
#include <iomanip>

#include "proto/interface.pb.h"

#include "db/db_api.h"
#include "ca_sync_block.h"
#include "include/net_interface.h"
#include "net/net_api.h"
#include "net/ip_port.h"
#include "utils/qrcode.h"
#include "utils/string_util.h"
#include "utils/util.h"
#include "utils/time_util.h"
#include "utils/base64.h"
#include "utils/base64_2.h"
#include "utils/bip39.h"
#include "utils/MagicSingleton.h"
#include "utils/hexcode.h"
#include "utils/console.h"
#include "utils/AccountManager.h"

#include "ca_txhelper.h"
#include "ca_test.h"
#include "ca_transaction.h"
#include "ca_global.h"
#include "ca_interface.h"
#include "ca_test.h"
#include "ca_txhelper.h"

#include "ca_txconfirmtimer.h"
#include "ca_block_http_callback.h"
#include "ca_block_http_callback.h"
#include "ca_transaction_cache.h"
#include "api/http_api.h"

#include "ca/ca_CCalBlockGas.h"
#include "ca/ca_AdvancedMenu.h"
#include "ca_blockcache.h"
#include "ca/ca_tranmonitor.h"
#include "ca_protomsg.pb.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"
#include "ca_evmone.h"
#include "ca_vm_interface.h"

bool bStopTx = false;
bool bIsCreateTx = false;


int ca_startTimerTask()
{
    // Blocking thread
    global::ca::kBlockPoolTimer.AsyncLoop(100, [](){ MagicSingleton<BlockHelper>::GetInstance()->Process(); });
    
    //Start patch thread
    MagicSingleton<BlockHelper>::GetInstance()->SeekBlockThread();

    // Block synchronization thread
    MagicSingleton<SyncBlock>::GetInstance()->ThreadStart();


    MagicSingleton<TransactionConfirmTimer>::GetInstance()->timer_start();

    MagicSingleton<TranStroage>::GetInstance();
    MagicSingleton<BlockStroage>::GetInstance();
    MagicSingleton<TranMonitor>::GetInstance()->Process();

    // Run http callback
    return 0;
}

bool ca_init()
{
    // signal(SIGINT, StopProcessHandler);

    RegisterInterface();

    // Register interface with network layer
    RegisterCallback();

    // Register HTTP related interfaces
    ca_register_http_callbacks();

    // Start timer task
    ca_startTimerTask();

    // NTP verification
    checkNtpTime();

    MagicSingleton<CtransactionCache>::GetInstance()->process();
    return true;
}



int ca_endTimerTask()
{

    global::ca::kDataBaseTimer.Cancel();
    return 0;
}

void ca_cleanup()
{

    ca_endTimerTask();
    DBDestory();
}

void ca_print_basic_info()
{
    std::string version = global::kVersion;
    std::string base58 = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    uint64_t balance = 0;
    GetBalanceByUtxo(base58, balance);
    DBReader db_reader;

    uint64_t blockHeight = 0;
    db_reader.GetBlockTop(blockHeight);



    std::string ownID = net_get_self_node_id();

    ca_console infoColor(kConsoleColor_Green, kConsoleColor_Black, true);
    double b = balance / double(100000000);
    cout << infoColor.color();
    cout << "*********************************************************************************" << endl;
    cout << "Version: " << version << endl;
    cout << "Base58: " << base58 << endl;
    cout << "Balance: " << setiosflags(ios::fixed) << setprecision(8) << b << endl;
    cout << "Block top: " << blockHeight << endl;
    cout << "*********************************************************************************" << endl;
    cout << infoColor.reset();
}

void handle_transaction()
{
    std::cout << std::endl
              << std::endl;

    std::string strFromAddr;
    std::cout << "input FromAddr :" << std::endl;
    std::cin >> strFromAddr;

    std::string strToAddr;
    std::cout << "input ToAddr :" << std::endl;
    std::cin >> strToAddr;

    std::string strAmt;
    std::cout << "input amount :" << std::endl;
    std::cin >> strAmt;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strAmt, pattern))
    {
        std::cout << "input amount error ! " << std::endl;
        return;
    }

    std::vector<std::string> fromAddr;
    fromAddr.emplace_back(strFromAddr);
    uint64_t amount = (std::stod(strAmt) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    std::map<std::string, int64_t> toAddrAmount;
    toAddrAmount[strToAddr] = amount;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;

    Vrf info_;
    int ret = TxHelper::CreateTxTransaction(fromAddr, toAddrAmount, top + 1,  outTx,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("CreateTxTransaction error!! ret:{}", ret);
        return;
    }
    


    MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

    { // TODO Test code, which needs to be adjusted separately
        if (fromAddr.size() == 1 && CheckBase58Addr(fromAddr[0], Base58Ver::kBase58Ver_MultiSign))
        {

            {
                if (TxHelper::AddMutilSign("1BKJq6f73jYZBnRSH3rZ7bP7Ro2oYkY7me", outTx) != 0)
                {
                    return;
                }
                outTx.clear_hash();
                outTx.set_hash(getsha256hash(outTx.SerializeAsString()));
            }

            {
                if (TxHelper::AddMutilSign("1QD3H7vyNAGKW3VPEFCvz1BkkqbjLFNaQx", outTx) != 0)
                {
                    return;
                }
                outTx.clear_hash();
                outTx.set_hash(getsha256hash(outTx.SerializeAsString()));
            }

            std::shared_ptr<MultiSignTxReq> req = std::make_shared<MultiSignTxReq>();
            req->set_version(global::kVersion);
            req->set_txraw(outTx.SerializeAsString());

            MsgData msgdata;
            int ret = HandleMultiSignTxReq(req, msgdata);

            return;
        }
    }

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info -> CopyFrom(info_);
    }

    auto msg = make_shared<TxMsgReq>(txMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret = DropshippingTx(msg,outTx);
    }
    else
    {
        ret = DoHandleTx(msg,outTx);
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());

    return;
}

void handle_declaration()
{
    std::cout << std::endl
              << std::endl;

    std::vector<std::string> SignAddr;
    uint64_t num = 0;
    std::cout << "Please enter your alliance account number :" << std::endl;
    std::cin >> num;

    for (int i = 0; i < num; i++)
    {
        std::string addr;
        std::cout << "Please enter your alliance account[" << i << "] :" << std::endl;
        std::cin >> addr;
        SignAddr.emplace_back(addr);
    }

    uint64_t SignThreshold = 0;
    std::cout << "Please enter your MutliSign number( must be >= 2) :" << std::endl;
    std::cin >> SignThreshold;

    std::string strFromAddr;
    std::cout << "input FromAddr :" << std::endl;
    std::cin >> strFromAddr;

    std::string strToAddr;
    std::cout << "input ToAddr :" << std::endl;
    std::cin >> strToAddr;

    std::string strAmt;
    std::cout << "input amount :" << std::endl;
    std::cin >> strAmt;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strAmt, pattern))
    {
        std::cout << "input amount error ! " << std::endl;
        return;
    }

    uint64_t amount = (std::stod(strAmt) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;

    Account multiSignAccount;
    EVP_PKEY_free(multiSignAccount.pkey);
    if (MagicSingleton<AccountManager>::GetInstance()->FindAccount(strToAddr, multiSignAccount) != 0)
    {
        return;
    }

    if (!CheckBase58Addr(multiSignAccount.base58Addr, Base58Ver::kBase58Ver_MultiSign))
    {
        return;
    }

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    int ret = 0;
    CTransaction outTx;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if (TxHelper::CreateDeclareTransaction(strFromAddr, strToAddr, amount, multiSignAccount.pubStr, SignAddr, SignThreshold, top + 1, outTx,isNeedAgent_flag,info_) != 0)
    {
        ERRORLOG("CreateTxTransaction error!! ret = {}", ret);
        return;
    }




    MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = make_shared<TxMsgReq>(txMsg);

    
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }


    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_stake()
{
    std::cout << std::endl
              << std::endl;

    Account account;
    EVP_PKEY_free(account.pkey);
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(account);
    std::string strFromAddr = account.base58Addr;
    std::cout << "stake addr: " << strFromAddr << std::endl;
    std::string strStakeFee;
    std::cout << "Please enter the amount to stake:" << std::endl;
    std::cin >> strStakeFee;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strStakeFee, pattern))
    {
        std::cout << "input stake amount error " << std::endl;
        return;
    }

    TxHelper::PledgeType pledgeType = TxHelper::PledgeType::kPledgeType_Node;

    uint64_t stake_amount = std::stod(strStakeFee) * global::ca::kDecimalNum;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }


    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if (TxHelper::CreateStakeTransaction(strFromAddr, stake_amount, top + 1,  pledgeType, outTx, outVin,isNeedAgent_flag,info_) != 0)
    {
        return;
    }

    MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);
    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    int ret=0;
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }

    if (ret != 0)
    {
        ret -= 100;
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_unstake()
{
    std::cout << std::endl
              << std::endl;

    std::string strFromAddr;
    std::cout << "Please enter unstake addr:" << std::endl;
    std::cin >> strFromAddr;

    DBReader db_reader;
    std::vector<string> utxos;
    db_reader.GetStakeAddressUtxo(strFromAddr, utxos);
    std::reverse(utxos.begin(), utxos.end());
    std::cout << "-- Current pledge amount: -- " << std::endl;
    for (auto &utxo : utxos)
    {
        std::string txRaw;
        db_reader.GetTransactionByHash(utxo, txRaw);
        CTransaction tx;
        tx.ParseFromString(txRaw);
        uint64_t value = 0;
        for (auto &vout : tx.utxo().vout())
        {
            if (vout.addr() == global::ca::kVirtualStakeAddr)
            {
                value = vout.value();
                break;
            }
        }
        std::cout << "utxo: " << utxo << " value: " << value << std::endl;
    }
    std::cout << std::endl;

    std::string strUtxoHash;
    std::cout << "utxo:";
    std::cin >> strUtxoHash;

    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if (TxHelper::CreatUnstakeTransaction(strFromAddr, strUtxoHash, top + 1, outTx, outVin,isNeedAgent_flag,info_) != 0)
    {
        return;
    }


    MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag == TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    int ret=0;
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }
    if (ret != 0)
    {
        ret -= 100;
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_invest()
{
    std::cout << std::endl
              << std::endl;
    std::cout << "AddrList:" << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strToAddr;
    std::cout << "Please enter the addr you want to invest to:" << std::endl;
    std::cin >> strToAddr;
    if (!CheckBase58Addr(strToAddr))
    {
        ERRORLOG("Input addr error!");
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strInvestFee;
    std::cout << "Please enter the amount to invest:" << std::endl;
    std::cin >> strInvestFee;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(strInvestFee, pattern))
    {
        ERRORLOG("Input invest fee error!");
        std::cout << "Input invest fee error!" << std::endl;
        return;
    }
    
    TxHelper::InvestType investType = TxHelper::InvestType::kInvestType_NetLicence;
    uint64_t invest_amount = std::stod(strInvestFee) * global::ca::kDecimalNum;

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateInvestTransaction(strFromAddr, strToAddr, invest_amount, top + 1,  investType, outTx, outVin,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("Failed to create investment transaction! The error code is:{}", ret);
        return;
    }



    MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }
    if (ret != 0)
    {
        ret -= 100;
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_disinvest()
{
    std::cout << std::endl
              << std::endl;

    std::cout << "AddrList : " << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    std::string strToAddr;
    std::cout << "Please enter the addr you want to divest from:" << std::endl;
    std::cin >> strToAddr;
    if (!CheckBase58Addr(strToAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    DBReader db_reader;
    std::vector<string> utxos;
    db_reader.GetBonusAddrInvestUtxosByBonusAddr(strToAddr, strFromAddr, utxos);
    std::reverse(utxos.begin(), utxos.end());
    std::cout << "======================================= Current invest amount: =======================================" << std::endl;
    for (auto &utxo : utxos)
    {
        std::cout << "Utxo: " << utxo << std::endl;
    }
    std::cout << "======================================================================================================" << std::endl;

    std::string strUtxoHash;
    std::cout << "Please enter the utxo you want to divest:";
    std::cin >> strUtxoHash;

    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateDisinvestTransaction(strFromAddr, strToAddr, strUtxoHash, top + 1, outTx, outVin,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("Create divest transaction error!:{}", ret);
        return;
    }



    MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }

    if (ret != 0)
    {
        ret -= 100;
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);

    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_bonus()
{
    CTransaction outTx;
    std::vector<TxHelper::Utxo> outVin;
    std::string strFromAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return;
    }

    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    int ret = TxHelper::CreateBonusTransaction(strFromAddr, top + 1,  outTx, outVin,isNeedAgent_flag,info_);
    if (ret != 0)
    {
        ERRORLOG("Failed to create bonus transaction! The error code is:{}", ret);
        return;
    }
    


    MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

    TxMsgReq txMsg;
    txMsg.set_version(global::kVersion);
    TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }
    auto msg = std::make_shared<TxMsgReq>(txMsg);

    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret=DropshippingTx(msg,outTx);
    }else{
        ret=DoHandleTx(msg,outTx);
    }

    if (ret != 0)
    {
        ret -= 100;
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_AccountManger()
{
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::cout << std::endl
              << std::endl;
    while (true)
    {
        std::cout << "0.Exit" << std::endl;
        std::cout << "1. Set Defalut Account" << std::endl;
        std::cout << "2. Add Account" << std::endl;
        std::cout << "3. Remove " << std::endl;
        std::cout << "4. Import PrivateKey" << std::endl;
        std::cout << "5. Export PrivateKey" << std::endl;

        std::string strKey;
        std::cout << "Please input your choice: " << std::endl;
        std::cin >> strKey;
        std::regex pattern("^[0-6]$");
        if (!std::regex_match(strKey, pattern))
        {
            std::cout << "Invalid input." << std::endl;
            continue;
        }
        int key = std::stoi(strKey);
        switch (key)
        {
        case 0:
            return;
        case 1:
            handle_SetdefaultAccount();
            break;
        case 2:
            gen_key();
            break;
        case 3:
        {
            std::string addr;
            std::cout << "Please enter the address you want to remove :" << std::endl;
            std::cin >> addr;

            if (MagicSingleton<AccountManager>::GetInstance()->DeleteAccount(addr) != 0)
            {
                std::cout << "failed!" << std::endl;
            }
            break;
        }
        case 4:
        {
            std::string pri_key;
            std::cout << "Please input private key :" << std::endl;
            std::cin >> pri_key;

            if (MagicSingleton<AccountManager>::GetInstance()->ImportPrivateKeyHex(pri_key) != 0)
            {
                std::cout << "Save PrivateKey failed!" << std::endl;
            }
            break;
        }
        case 5:
            handle_export_private_key();
            break;
        default:
            std::cout << "Invalid input." << std::endl;
            continue;
        }
    }
}

void handle_SetdefaultAccount()
{
    std::string addr;
    std::cout << "Please enter the address you want to set :" << std::endl;
    std::cin >> addr;
    if (addr[0] == '3')
    {
        std::cout << "The Default account cannot be MultiSign Addr" << std::endl;
        return;
    }

    Account oldAccount;
    EVP_PKEY_free(oldAccount.pkey);
    if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(oldAccount) != 0)
    {
        ERRORLOG("not found DefaultKeyBs58Addr  in the _accountList");
        return;
    }

    if (MagicSingleton<AccountManager>::GetInstance()->SetDefaultAccount(addr) != 0)
    {
        ERRORLOG("Set DefaultKeyBs58Addr failed!");
        return;
    }

    Account newAccount;
    EVP_PKEY_free(newAccount.pkey);
    if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(newAccount) != 0)
    {
        ERRORLOG("not found DefaultKeyBs58Addr  in the _accountList");
        return;
    }

    if (!CheckBase58Addr(oldAccount.base58Addr, Base58Ver::kBase58Ver_Normal) ||
        !CheckBase58Addr(newAccount.base58Addr, Base58Ver::kBase58Ver_Normal))
    {
        return;
    }

    // update base 58 addr
    NodeBase58AddrChangedReq req;
    req.set_version(global::kVersion);

    NodeSign *oldSign = req.mutable_oldsign();
    oldSign->set_pub(oldAccount.pubStr);
    std::string oldSignature;
    if (!oldAccount.Sign(getsha256hash(newAccount.base58Addr), oldSignature))
    {
        return;
    }
    oldSign->set_sign(oldSignature);

    NodeSign *newSign = req.mutable_newsign();
    newSign->set_pub(newAccount.pubStr);
    std::string newSignature;
    if (!newAccount.Sign(getsha256hash(oldAccount.base58Addr), newSignature))
    {
        return;
    }
    newSign->set_sign(newSignature);

    MagicSingleton<PeerNode>::GetInstance()->set_self_id(newAccount.base58Addr);
    MagicSingleton<PeerNode>::GetInstance()->set_self_identity(newAccount.pubStr);
    std::vector<Node> publicNodes = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    for (auto &node : publicNodes)
    {
        net_com::send_message(node, req, net_com::Compress::kCompress_False, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_2);
    }
    std::cout << "Set Default account success" << std::endl;
}
string readFileIntoString(string filename)
{
	ifstream ifile(filename);
	ostringstream buf;
	char ch;
	while(buf&&ifile.get(ch))
    {
        buf.put(ch);
    }
	return buf.str();
}
void handle_deploy_contract()
{
        std::cout << std::endl
              << std::endl;

    std::cout << "AddrList : " << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }


    std::string deploy_amount;
    std::cout << "deploy_amount :" << std::endl;
    std::cin >> deploy_amount;
    std::regex pattern("^\\d+(\\.\\d+)?$");
    if (!std::regex_match(deploy_amount, pattern))
    {
        std::cout << "Input amount error! " << std::endl;
        return;
    }

    uint64_t amount = (std::stod(deploy_amount) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
    DBReader data_reader;
    uint64_t top = 0;
	if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return ;
    }

    uint32_t nContractType;
    std::cout << "Please enter contract type: (0: EVM) " << std::endl;
    std::cin >> nContractType;

    CTransaction outTx;
    int ret = 0 ;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if(nContractType == 0)
    {
        std::string code;
        string fn="./contract.txt";
        code=readFileIntoString(fn);
        if(code.empty())
        {
            return;
        }        
        std::cout << "code :" << code << std::endl;
        Account launchAccount;
        if(MagicSingleton<AccountManager>::GetInstance()->FindAccount(strFromAddr, launchAccount) != 0)
        {
            ERRORLOG("Failed to find account {}", strFromAddr);
            return;
        }
        std::string OwnerEvmAddr = evm_utils::generateEvmAddr(launchAccount.pubStr);
        Evmone vm(code);
        ret = TxHelper::CreateDeployContractTransaction(vm, strFromAddr, amount, top + 1, outTx, OwnerEvmAddr, isNeedAgent_flag, info_);
        if(ret != 0)
        {
            ERRORLOG("Failed to create DeployContract transaction! The error code is:{}", ret);
            return;
        }        
    }
    else
    {
        return;
    }

	TxMsgReq txMsg;
	txMsg.set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

	if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = make_shared<TxMsgReq>(txMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret = DropshippingTx(msg,outTx);
    }
    else
    {
        ret = DoHandleTx(msg,outTx);
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}

void handle_call_contract()
{

    std::cout << std::endl
              << std::endl;

    std::cout << "AddrList : " << std::endl;
    MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();

    std::string strFromAddr;
    std::cout << "Please enter your addr:" << std::endl;
    std::cin >> strFromAddr;
    if (!CheckBase58Addr(strFromAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;
    }

    DBReader data_reader;
    std::vector<std::string> vecDeployers;
    data_reader.GetAllDeployerAddr(vecDeployers);
    std::cout << "=====================deployers=====================" << std::endl;
    for(auto& deployer : vecDeployers)
    {
        std::cout << "deployer: " << deployer << std::endl;
    }
    std::cout << "=====================deployers=====================" << std::endl;
    std::string strToAddr;
    std::cout << "Please enter to addr:" << std::endl;
    std::cin >> strToAddr;
    if(!CheckBase58Addr(strToAddr))
    {
        std::cout << "Input addr error!" << std::endl;
        return;        
    }

    std::vector<std::string> vecDeployUtxos;
    data_reader.GetDeployUtxoByDeployerAddr(strToAddr, vecDeployUtxos);
    std::cout << "=====================deployed utxos=====================" << std::endl;
    for(auto& deploy_utxo : vecDeployUtxos)
    {
        std::cout << "deployed utxo: " << deploy_utxo << std::endl;
    }
    std::cout << "=====================deployed utxos=====================" << std::endl;
    std::string strTxHash;
    std::cout << "Please enter tx hash:" << std::endl;
    std::cin >> strTxHash;
    
    // args means selector + parameters
    std::string strInput;
    std::cout << "Please enter args:" << std::endl;
    std::cin >> strInput;
    if(strInput.substr(0, 2) == "0x")
    {
        strInput = strInput.substr(2);
    }

    uint64_t top = 0;
	if (DBStatus::DB_SUCCESS != data_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return ;
    }


    CTransaction outTx;
    CTransaction tx;
    std::string tx_raw;
    if (DBStatus::DB_SUCCESS != data_reader.GetTransactionByHash(strTxHash, tx_raw))
    {
        ERRORLOG("get contract transaction failed!!");
        return ;
    }
    if(!tx.ParseFromString(tx_raw))
    {
        ERRORLOG("contract transaction parse failed!!");
        return ;
    }
    

    nlohmann::json data_json = nlohmann::json::parse(tx.data());
    nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
    int vm_type = tx_info["VmType"].get<int>();
 
    int ret = 0;
    uint64_t amount = 0;
    TxHelper::vrfAgentType isNeedAgent_flag;
    Vrf info_;
    if (vm_type == VmInterface::VmType::EVM)
    {
        Account launchAccount;
        if(MagicSingleton<AccountManager>::GetInstance()->FindAccount(strFromAddr, launchAccount) != 0)
        {
            ERRORLOG("Failed to find account {}", strFromAddr);
            return;
        }
        std::string OwnerEvmAddr = evm_utils::generateEvmAddr(launchAccount.pubStr);
        Evmone vm;
        ret = TxHelper::CreateCallContractTransaction(vm, strFromAddr, strToAddr, strTxHash, strInput, amount, top + 1,  outTx, OwnerEvmAddr, isNeedAgent_flag, info_);
        if(ret != 0)
        {
            ERRORLOG("Create call contract transaction failed! ret:{}", ret);        
            return;
        }
    }
    else
    {
        return;
    }

    TxMsgReq txMsg;
	txMsg.set_version(global::kVersion);
    TxMsgInfo * txMsgInfo = txMsg.mutable_txmsginfo();
    txMsgInfo->set_type(0);
    txMsgInfo->set_tx(outTx.SerializeAsString());
    txMsgInfo->set_height(top);

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info -> CopyFrom(info_);

    }

    if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf)
    {
        Vrf * new_info=txMsg.mutable_vrfinfo();
        new_info->CopyFrom(info_);

    }

    auto msg = make_shared<TxMsgReq>(txMsg);
    std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr)
    {
        ret = DropshippingTx(msg,outTx);
    }
    else
    {
        ret = DoHandleTx(msg,outTx);
    }

    MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);
    DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
}
void handle_export_private_key()
{
    std::cout << std::endl
              << std::endl;
    std::string fileName("account_private_key.txt");
    ofstream file;
    file.open(fileName);
    std::string addr;
    std::cout << "please input the addr you want to export" << std::endl;
    std::cin >> addr;

    Account account;
    EVP_PKEY_free(account.pkey);
    MagicSingleton<AccountManager>::GetInstance()->FindAccount(addr, account);

    file << "Please use Courier New font to view" << std::endl
         << std::endl;

    file << "Base58 addr: " << addr << std::endl;
    std::cout << "Base58 addr: " << addr << std::endl;

    char out_data[1024] = {0};
    int data_len = sizeof(out_data);
    mnemonic_from_data((const uint8_t *)account.priStr.c_str(), account.priStr.size(), out_data, data_len);
    file << "Mnemonic: " << out_data << std::endl;
    std::cout << "Mnemonic: " << out_data << std::endl;

    std::string strPriHex = Str2Hex(account.priStr);
    file << "Private key: " << strPriHex << std::endl;
    std::cout << "Private key: " << strPriHex << std::endl;

    file << "QRCode:";
    std::cout << "QRCode:";

    QRCode qrcode;
    uint8_t qrcodeData[qrcode_getBufferSize(5)];
    qrcode_initText(&qrcode, qrcodeData, 5, ECC_MEDIUM, strPriHex.c_str());

    file << std::endl
         << std::endl;
    std::cout << std::endl
              << std::endl;

    for (uint8_t y = 0; y < qrcode.size; y++)
    {
        file << "        ";
        std::cout << "        ";
        for (uint8_t x = 0; x < qrcode.size; x++)
        {
            file << (qrcode_getModule(&qrcode, x, y) ? "\u2588\u2588" : "  ");
            std::cout << (qrcode_getModule(&qrcode, x, y) ? "\u2588\u2588" : "  ");
        }

        file << std::endl;
        std::cout << std::endl;
    }

    file << std::endl
         << std::endl
         << std::endl
         << std::endl
         << std::endl
         << std::endl;
    std::cout << std::endl
              << std::endl
              << std::endl
              << std::endl
              << std::endl
              << std::endl;

    ca_console redColor(kConsoleColor_Red, kConsoleColor_Black, true);
    std::cout << redColor.color() << "You can also view above in file:" << fileName << " of current directory." << redColor.reset() << std::endl;
    return;
}


int get_chain_height(unsigned int &chainHeight)
{
    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        return -1;
    }
    chainHeight = top;
    return 0;
}

void net_register_chain_height_callback()
{
    net_callback::register_chain_height_callback(get_chain_height);
}

/**
 * @description: Registering Callbacks
 * @param {*}
 * @return {*}
 */
void RegisterCallback()
{
    net_register_callback<FastSyncGetHashReq>(HandleFastSyncGetHashReq);
    net_register_callback<FastSyncGetHashAck>(HandleFastSyncGetHashAck);
    net_register_callback<FastSyncGetBlockReq>(HandleFastSyncGetBlockReq);
    net_register_callback<FastSyncGetBlockAck>(HandleFastSyncGetBlockAck);

    net_register_callback<SyncGetSumHashReq>(HandleSyncGetSumHashReq);
    net_register_callback<SyncGetSumHashAck>(HandleSyncGetSumHashAck);
    net_register_callback<SyncGetHeightHashReq>(HandleSyncGetHeightHashReq);
    net_register_callback<SyncGetHeightHashAck>(HandleSyncGetHeightHashAck);
    net_register_callback<SyncGetBlockReq>(HandleSyncGetBlockReq);
    net_register_callback<SyncGetBlockAck>(HandleSyncGetBlockAck);

    net_register_callback<SyncFromZeroGetSumHashReq>(HandleFromZeroSyncGetSumHashReq);
    net_register_callback<SyncFromZeroGetSumHashAck>(HandleFromZeroSyncGetSumHashAck);
    net_register_callback<SyncFromZeroGetBlockReq>(HandleFromZeroSyncGetBlockReq);
    net_register_callback<SyncFromZeroGetBlockAck>(HandleFromZeroSyncGetBlockAck);

    net_register_callback<GetBlockByUtxoReq>(HandleBlockByUtxoReq);
    net_register_callback<GetBlockByUtxoAck>(HandleBlockByUtxoAck);

    net_register_callback<GetBlockByHashReq>(HandleBlockByHashReq);
    net_register_callback<GetBlockByHashAck>(HandleBlockByHashAck);

    // PCEnd correlation
    net_register_callback<TxMsgReq>(HandleTx); // PCEnd transaction flow
    net_register_callback<TxMsgAck>(HandleDoHandleTxAck);
    net_register_callback<BlockMsg>(HandleBlock);                                         // PCEnd transaction flow

    net_register_callback<BuildBlockBroadcastMsgAck>(HandleAddBlockAck);
    
    net_register_callback<TxPendingBroadcastMsg>(HandleTxPendingBroadcastMsg);   // Transaction pending broadcast

    net_register_callback<BuildBlockBroadcastMsg>(HandleBuildBlockBroadcastMsg); // Building block broadcasting
    net_register_callback<MultiSignTxReq>(HandleMultiSignTxReq);
    net_register_chain_height_callback();
}

void TestCreateTx(const std::vector<std::string> &addrs, const int &sleepTime)
{
    if (addrs.size() < 2)
    {
        std::cout << "Insufficient number of accounts" << std::endl;
        return;
    }
#if 0
    bIsCreateTx = true;
    while (1)
    {
        if (bStopTx)
        {
            break;
        }
        int intPart = rand() % 10;
        double decPart = (double)(rand() % 100) / 100;
        double amount = intPart + decPart;
        std::string amountStr = std::to_string(amount);

        std::cout << std::endl << std::endl << std::endl << "=======================================================================" << std::endl;
        CreateTx("1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu", "18RM7FNtzDi41QEU5rAnrFdVaGBHvhTTH1", amountStr.c_str(), NULL, 6, "0.01");
        std::cout << "=====Transaction initiator:1vkS46QffeM4sDMBBjuJBiVkMQKY7Z8Tu" << std::endl;
        std::cout << "=====Transaction recipient:18RM7FNtzDi41QEU5rAnrFdVaGBHvhTTH1" << std::endl;
        std::cout << "=====Transaction amount:" << amountStr << std::endl;
        std::cout << "=======================================================================" << std::endl << std::endl << std::endl << std::endl;

        sleep(sleepTime);
    }
    bIsCreateTx = false;

#endif

#if 1
    bIsCreateTx = true;
    for (int i = 0; i < addrs.size(); i++)
    {
        if (bStopTx)
        {
            std::cout << "Close the deal!" << std::endl;
            break;
        }
        int intPart = rand() % 10;
        double decPart = (double)(rand() % 100) / 100;
        std::string amountStr = std::to_string(intPart  + decPart );


        std::string from, to;
        if (i >= addrs.size() - 1)
        {
            from = addrs[addrs.size() - 1];
            to = addrs[0];
            i = 0;
        }
        else
        {
            from = addrs[i];
            to = addrs[i + 1];
        }
        if (from != "")
        {
            if (!MagicSingleton<AccountManager>::GetInstance()->IsExist(from))
            {
                DEBUGLOG("Illegal account.");
                continue;
            }
        }
        else
        {
            DEBUGLOG("Illegal account. from base58addr is null !");
            continue;
        }

        std::cout << std::endl
                  << std::endl
                  << std::endl
                  << "=======================================================================" << std::endl;

        std::vector<std::string> fromAddr;
        fromAddr.emplace_back(from);
        std::map<std::string, int64_t> toAddrAmount;
        uint64_t amount = (stod(amountStr) + global::ca::kFixDoubleMinPrecision) * global::ca::kDecimalNum;
        if(amount == 0)
        {
            std::cout << "aomunt = 0" << std::endl;
            DEBUGLOG("aomunt = 0");
            continue;
        }
        toAddrAmount[to] = amount;



        DBReader db_reader;
        uint64_t top = 0;
        if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
        {
            ERRORLOG("db get top failed!!");
            continue;
        }

        CTransaction outTx;
        TxHelper::vrfAgentType isNeedAgent_flag;
        Vrf info_;
        int ret = TxHelper::CreateTxTransaction(fromAddr, toAddrAmount, top + 1,  outTx,isNeedAgent_flag,info_);
        if (ret != 0)
        {
            ERRORLOG("CreateTxTransaction error!!");
            continue;
        }
        MagicSingleton<TranMonitor>::GetInstance()->AddTranMonitor(outTx);

        TxMsgReq txMsg;
        txMsg.set_version(global::kVersion);
        TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
        txMsgInfo->set_type(0);
        txMsgInfo->set_tx(outTx.SerializeAsString());
        txMsgInfo->set_height(top);
        
        if(isNeedAgent_flag== TxHelper::vrfAgentType::vrfAgentType_vrf){
            Vrf * new_info=txMsg.mutable_vrfinfo();
            new_info->CopyFrom(info_);

        }


        auto msg = make_shared<TxMsgReq>(txMsg);

        std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
        if(isNeedAgent_flag==TxHelper::vrfAgentType::vrfAgentType_vrf && outTx.identity() != defaultBase58Addr){

            ret=DropshippingTx(msg,outTx);
        }else{
            ret=DoHandleTx(msg,outTx);
         }
        DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
        MagicSingleton<TranMonitor>::GetInstance()->SetDoHandleTxStatus(outTx, ret);

        std::cout << "=====Transaction initiator:" << from << std::endl;
        std::cout << "=====Transaction recipient:" << to << std::endl;
        std::cout << "=====Transaction amount:" << amountStr << std::endl;
        std::cout << "=======================================================================" << std::endl
                  << std::endl
                  << std::endl
                  << std::endl;

        usleep(sleepTime);
    }
    bIsCreateTx = false;
#endif
}

void ThreadStart()
{
    std::vector<std::string> addrs;
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    int sleepTime = 8;
    std::thread th(TestCreateTx, addrs, sleepTime);
    th.detach();
}

int checkNtpTime()
{
    // Ntp check
    int64_t getNtpTime = MagicSingleton<TimeUtil>::GetInstance()->getNtpTimestamp();
    int64_t getLocTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();

    int64_t tmpTime = abs(getNtpTime - getLocTime);

    std::cout << "UTC Time: " << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(getLocTime) << std::endl;
    std::cout << "Ntp Time: " << MagicSingleton<TimeUtil>::GetInstance()->formatUTCTimestamp(getNtpTime) << std::endl;

    if (tmpTime <= 1000000)
    {
        DEBUGLOG("ntp timestamp check success");
        return 0;
    }
    else
    {
        DEBUGLOG("ntp timestamp check fail");
        std::cout << "time check fail" << std::endl;
        return -1;
    }
}





