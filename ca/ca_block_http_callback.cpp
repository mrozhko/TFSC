#include "ca_block_http_callback.h"
#include "net/httplib.h"
#include "common/config.h"
#include "include/ScopeGuard.h"
#include "include/logging.h"
#include "ca_txhelper.h"
#include "ca_global.h"
#include "utils/MagicSingleton.h"
#include <functional>
#include <iostream>
#include <sstream>
#include <random>
#include "db/db_api.h"

CBlockHttpCallback::CBlockHttpCallback() : running_(false),ip_("localhost"),port_(11190),path_("/donetBrowser/block")
{
    Config::HttpCallback httpCallback = {};
    MagicSingleton<Config>::GetInstance()->GetHttpCallback(httpCallback);
    if (!httpCallback.ip.empty() && httpCallback.port > 0)
    {
        this->Start(httpCallback.ip, httpCallback.port, httpCallback.path);
    }
    else
    {
        ERRORLOG("Http callback is not config!");
    }
}

bool CBlockHttpCallback::AddBlock(const std::string& block)
{
    if (block.empty())
        return false;
    std::unique_lock<std::mutex> lck(add_mutex_);
    addblocks_.push_back( block );
    cvadd_.notify_all();

    return true;
}

bool CBlockHttpCallback::AddBlock(const CBlock& block)
{
    std::string json = ToJson(block);
    return AddBlock(json);
}

bool CBlockHttpCallback::RollbackBlockStr(const std::string& block)
{
      if (block.empty())
        return false;
        
    std::unique_lock<std::mutex> lck(rollback_mutex_);
    rollbackblocks_.push_back( block );
    cvrollback_.notify_all();

    return true;
}


bool CBlockHttpCallback::RollbackBlock(const CBlock& block)
{
    std::string json = ToJson(block);
    return RollbackBlockStr(json);
}


int CBlockHttpCallback::AddBlockWork(const std::string &method)
{
    while (running_)
    {
        std::string currentBlock;
        {
            std::unique_lock<std::mutex> lck(add_mutex_);
            while (addblocks_.empty())
            {
                DEBUGLOG("Enter waiting for condition variable.");
                cvadd_.wait(lck);
            }
            DEBUGLOG("Handle the first block...");
            currentBlock = addblocks_.front();
            addblocks_.erase(addblocks_.begin());
        }

        SendBlockHttp(currentBlock,method);
    }

    return true;
}


int CBlockHttpCallback::RollbackBlockWork(const std::string &method)
{
    while (running_)
    {
        std::string currentBlock;
        {
            std::unique_lock<std::mutex> lck(rollback_mutex_);
            while (rollbackblocks_.empty())
            {
                DEBUGLOG("Enter waiting for condition variable.");
                cvrollback_.wait(lck);
            }
            DEBUGLOG("Handle the first block...");
            currentBlock = rollbackblocks_.front();
            rollbackblocks_.erase(rollbackblocks_.begin());
        }
        SendBlockHttp(currentBlock,method);
    }

    return true;
}

bool CBlockHttpCallback::Start(const std::string& ip, int port,const std::string& path)
{
    ip_ = ip;
    port_ = port;
    path_ = path;
    running_ = true;
    const std::string method1 = "/addblock";
    const std::string method2 = "/rollbackblock";
    work_addblock_thread_ = std::thread(std::bind(&CBlockHttpCallback::AddBlockWork, this, method1));
    work_rollback_thread_ = std::thread(std::bind(&CBlockHttpCallback::RollbackBlockWork, this, method2));
    work_addblock_thread_.detach();
    work_rollback_thread_.detach();
    return true;
}

void CBlockHttpCallback::Stop()
{
    running_ = false;
}

bool CBlockHttpCallback::IsRunning()
{
    return running_;
}

bool CBlockHttpCallback::SendBlockHttp(const std::string& block,const std::string &method)
{
    httplib::Client client(ip_, port_);
    std::string path = path_ + method;
    auto res = client.Post(path.data(), block, "application/json");
    if (res)
    {
        DEBUGLOG("status:{}, Content-Type:{}, body:{}", res->status, res->get_header_value("Content-Type"), res->body);
    }
    else
    {
        DEBUGLOG("Client post failed");
    }

    return (bool)res;
}

std::string CBlockHttpCallback::ToJson(const CBlock& block)
{
    nlohmann::json jsonBlock;
    jsonBlock["block_hash"] = block.hash();
    jsonBlock["block_height"] = block.height();
    jsonBlock["block_time"] = block.time();


    CTransaction tx;
    for (auto & t : block.txs())
    {
        if(t.type() == global::ca::kTxSign)
        {
            tx = t;
            // TODO There is an error here, all post-trade conversion jsons should be removed
            break;
        }

    }

    jsonBlock["transaction"]["hash"] = tx.hash();

    std::vector<std::string> owners = TxHelper::GetTxOwner(tx);
    for (auto& txOwner : owners)
    {
        jsonBlock["transaction"]["from"].push_back(txOwner);
    }

    uint64_t amount = 0;
    if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
    {
        nlohmann::json data = nlohmann::json::parse(tx.data());
        global::ca::TxType txType = (global::ca::TxType)tx.txtype();
        jsonBlock["transaction"]["type"] = txType;
        if (txType == global::ca::TxType::kTxTypeUnstake)
        {
            nlohmann::json txInfo = data["TxInfo"].get<nlohmann::json>();
            std::string redeemUtxo = txInfo["UnstakeUtxo"];

            std::string txRaw;
            DBReader db_reader;
            if ( db_reader.GetTransactionByHash(redeemUtxo, txRaw) == 0)
            {
                CTransaction utxoTx;
                utxoTx.ParseFromString(txRaw);
                std::string fromAddrTmp;
                uint64_t value = 0;

                for (int i = 0; i < utxoTx.utxo().vout_size(); i++)
                {
                    const CTxOutput & txout = utxoTx.utxo().vout(i);
                    if (txout.addr() != global::ca::kVirtualStakeAddr)
                    {
                        fromAddrTmp = txout.addr();
                        value = txout.value();
                        continue;
                    }
                    amount = txout.value();
                }
                if (!fromAddrTmp.empty())
                {
                    nlohmann::json out;

                    double ret = ((double)value / (double)global::ca::kDecimalNum);
                    std::stringstream ss;
                    ss << std::setiosflags(std::ios::fixed)<<std::setprecision(8) << ret;
                    std::string str = ss.str();  
                    
                    out["pub"] = fromAddrTmp;
                    out["value"] = str;
                    jsonBlock["transaction"]["to"].push_back(out);
                }
            }
        }
        else if (txType == global::ca::TxType::kTxTypeDisinvest)
    {
        nlohmann::json txInfo = data["TxInfo"].get<nlohmann::json>();
        std::string disinvestUtxo = txInfo["DisinvestUtxo"];
		
		std::string txRaw;
        DBReader db_reader;
		
		if ( db_reader.GetTransactionByHash(disinvestUtxo, txRaw) == 0)
        {
			CTransaction utxoTx;
            utxoTx.ParseFromString(txRaw);
            std::string fromAddrTmp;
            uint64_t value = 0;

            for (int i = 0; i < utxoTx.utxo().vout_size(); i++)
            {
                const CTxOutput & txout = utxoTx.utxo().vout(i);
                if (txout.addr() != global::ca::kVirtualInvestAddr)
                {
                    fromAddrTmp = txout.addr();
                    value = txout.value();
                    continue;
                }
                amount = txout.value();
            }
            if (!fromAddrTmp.empty())
            {
                nlohmann::json out;

                double ret = ((double)value / global::ca::kDecimalNum);
                std::stringstream ss;
	            ss << std::setiosflags(std::ios::fixed)<<std::setprecision(8) <<ret;
	            std::string str = ss.str(); 
                
                out["pub"] = fromAddrTmp;
                out["value"] = str;
                jsonBlock["transaction"]["to"].push_back(out);
            }
        }
    }
    }
    for (auto & txOut : tx.utxo().vout())
    {
        if (owners.end() != find(owners.begin(), owners.end(), txOut.addr()))
        {
            continue;
        }
        else
        {
            amount += txOut.value();


            double ret = ((double)txOut.value() / global::ca::kDecimalNum);
            std::stringstream ss;
	        ss << std::setiosflags(std::ios::fixed)<<std::setprecision(8) <<ret;
	        std::string str = ss.str(); 
           
            nlohmann::json out;
            out["pub"] = txOut.addr();
            out["value"] = str;
            jsonBlock["transaction"]["to"].push_back(out);
        }
    }

    double ret = ((double)amount / global::ca::kDecimalNum);
    std::stringstream ss;
	ss << std::setiosflags(std::ios::fixed)<<std::setprecision(8) << ret;
	std::string str = ss.str(); 
  
    jsonBlock["transaction"]["amount"] = str;
    std::string json = jsonBlock.dump(4);
    return json;
}

void CBlockHttpCallback::Test()
{
    std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_int_distribution<int> dist(1, 32767);

    std::stringstream stream;
    stream << "Test http callback, ID: " << dist(mt);
    std::string test_str = stream.str();
    AddBlock(test_str);
}

void CBlockHttpCallback::Test2()
{
    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        return ;
    }
    if (top >  20)
    {
        top = 20;
    }

    for (uint32_t height = top; height > 0; --height)
    {
        std::vector<std::string> blockHashs;
        if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(height, blockHashs))
        {
            continue ;
        }

        for (auto& blkHash : blockHashs)
        {
            std::string blockStr;
            if (DBStatus::DB_SUCCESS != db_reader.GetBlockByBlockHash(blkHash, blockStr))
            {
                continue ;
            }

            CBlock cblock;
            cblock.ParseFromString(blockStr);

            AddBlock(cblock);
        }
    }
}
