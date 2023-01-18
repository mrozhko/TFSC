#include "api/http_api.h"
#include "ca_global.h"
#include "ca_transaction.h"
#include "../net/peer_node.h"
#include "../utils/json.hpp"
#include "../net/httplib.h"
#include "../utils/string_util.h"
#include "../utils/base64.h"
#include "block.pb.h"
#include "utils/MagicSingleton.h"
#include <algorithm>
#include <string>
#include "../include/ScopeGuard.h"
#include "ca_txhelper.h"
#include "../include/net_interface.h"
#include "../net/net_api.h"
#include "utils/base64_2.h"
#include <sstream>
#include "api/jcAPI.h"

#include "ca/ca_AdvancedMenu.h"
#include "ca_global.h"
#include "../net/global.h"
#include "../utils/string_util.h"
#include <cctype>//toupper/tolower
#include <algorithm>//transform
#include "db/db_api.h"
#include "db/cache.h"
#include "ca/ca_CCalBlockGas.h"
#include "utils/AccountManager.h"
#include "utils/AccountManager.h"
#include "net/peer_node_cache.h"
#include "ca/ca_algorithm.h"

 static bool flag = true;

void ca_register_http_callbacks()
{
    HttpServer::registerCallback("/", api_jsonrpc);
    HttpServer::registerCallback("/block", api_print_block);
    HttpServer::registerCallback("/info", api_info);
    //    HttpServer::registerCallback("/info_queue", api_info_queue);
    HttpServer::registerCallback("/get_block", api_get_block);
//    HttpServer::registerCallback("/get_block_hash", api_get_block_hash);
//    HttpServer::registerCallback("/get_block_by_hash", api_get_block_by_hash);
//    HttpServer::registerCallback("/get_tx_owner", api_get_tx_owner);
//    HttpServer::registerCallback("/test_create_multi_tx", test_create_multi_tx);
//    HttpServer::registerCallback("/get_db_key", api_get_db_key);
//    HttpServer::registerCallback("/add_block_callback", add_block_callback_test);
//    HttpServer::registerCallback("/rollbackblock", rollback_block_callback_test);
//    HttpServer::registerCallback("/cache_info", api_cache_info);
//
    HttpServer::registerCallback("/pub", api_pub);
    HttpServer::registerCallback("/startautotx", api_start_autotx);
    HttpServer::registerCallback("/endautotx", api_end_autotx);
    HttpServer::registerCallback("/autotxstatus", api_status_autotx);
    HttpServer::registerCallback("/filterheight", api_filter_height);
    HttpServer::registerCallback("/peernodecache", api_print_peernodecache);

//
//    //json rpc=========
//    HttpServer::registerJsonRpcCallback("jsonrpc_test", jsonrpc_test);
    HttpServer::registerJsonRpcCallback("get_height", jsonrpc_get_height);
    HttpServer::registerJsonRpcCallback("get_balance", jsonrpc_get_balance);
//    HttpServer::registerJsonRpcCallback("get_gas", jsonrpc_get_gas);
//    HttpServer::registerJsonRpcCallback("get_txids_by_height", jsonrpc_get_txids_by_height);
//    HttpServer::registerJsonRpcCallback("get_tx_by_txid", jsonrpc_get_tx_by_txid);
//    HttpServer::registerJsonRpcCallback("create_tx_message", jsonrpc_create_tx_message);
//    HttpServer::registerJsonRpcCallback("send_tx", jsonrpc_send_tx);
//    HttpServer::registerJsonRpcCallback("generate_wallet", jsonrpc_generate_wallet);
//    HttpServer::registerJsonRpcCallback("generate_sign", jsonrpc_generate_sign);
//    HttpServer::registerJsonRpcCallback("send_multi_tx", jsonrpc_send_multi_tx);
//    HttpServer::registerJsonRpcCallback("get_pending_transaction", jsonrpc_get_pending_transaction);
//    HttpServer::registerJsonRpcCallback("get_failure_transaction", jsonrpc_get_failure_transaction);
//    HttpServer::registerJsonRpcCallback("get_block_info_list", jsonrpc_get_block_info_list);
//    HttpServer::registerJsonRpcCallback("confirm_transaction", jsonrpc_confirm_transaction);
//
//    HttpServer::registerJsonRpcCallback("get_tx_by_addr_and_height", jsonrpc_get_tx_by_addr_and_height);
//    HttpServer::registerJsonRpcCallback("get_utxo", jsonrpc_get_utxo);

    //Start http
    HttpServer::start();
}

//void add_block_callback_test(const Request &req, Response &res)
//{
//    DEBUGLOG("Receive callback request from Client: {}", req.body);
//    res.set_content(req.body, "text/plain"); // "application/json"
//}
//
//void rollback_block_callback_test(const Request &req, Response &res)
//{
//    DEBUGLOG("Receive callback request from Client: {}", req.body);
//    cout << "Receive callback request from Client: {}" << endl;
//
//    {
//        cout << "req.body=" << req.body << endl;
//    }
//
//    res.set_content(req.body, "text/plain"); // "application/json"
//}
//
//nlohmann::json jsonrpc_test(const nlohmann::json &param)
//{
//    std::string param1 = param["param1"].get<std::string>();
//    nlohmann::json ret;
//    ret["result"]["echo param"] = param1;
//    return ret;
//}
//
////-------
void api_pub(const Request &req, Response &res)
{
   std::ostringstream oss;
   MagicSingleton<ProtobufDispatcher>::GetInstance()->task_info(oss);
   oss << "queue_read:" << global::queue_read.msg_queue_.size() << std::endl;
   oss << "queue_work:" << global::queue_work.msg_queue_.size() << std::endl;
   oss << "queue_write:" << global::queue_write.msg_queue_.size() << std::endl;
   oss << "\n"
       << std::endl;

   double total = .0f;
   oss << "------------------------------------------" << std::endl;
   for (auto &item : global::reqCntMap)
   {
       total += (double) item.second.second;//Data size
       oss.precision(3);//Keep 3 decimal places
       // The type of data					Number of calls								 Convert MB
       oss << item.first << ": " << item.second.first << " size: " << (double) item.second.second / 1024 / 1024
           << " MB" << std::endl;
   }
   oss << "------------------------------------------" << std::endl;
   oss << "Total: " << total / 1024 / 1024 << " MB" << std::endl;//The total size

   oss << std::endl;
   oss << std::endl;

   oss << "amount:" << std::endl;
   std::vector<std::string> baselist;

   MagicSingleton<AccountManager>::GetInstance()->GetAccountList(baselist);
   for (auto &i : baselist)
   {
       uint64_t amount = 0;
       GetBalanceByUtxo(i, amount);
       oss << i + ":" + std::to_string(amount) << std::endl;
   }

   oss << std::endl << std::endl;

   std::vector<Node> pubNodeList = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
   oss << "Public PeerNode size is: " << pubNodeList.size() << std::endl;
   oss << MagicSingleton<PeerNode>::GetInstance()->nodelist_info(pubNodeList);//Convert all public network node data to string for storage
   res.set_content(oss.str(), "text/plain");
}
//
//
void api_jsonrpc(const Request &req, Response &res)
{
   nlohmann::json ret;
   ret["jsonrpc"] = "2.0";
   try
   {
       auto json = nlohmann::json::parse(req.body);

       std::string method = json["method"];

       auto p = HttpServer::rpc_cbs.find(method);
       if (p == HttpServer::rpc_cbs.end())
       {
           ret["error"]["code"] = -32601;
           ret["error"]["message"] = "Method not found";
           ret["id"] = "";
       } else
       {
           auto params = json["params"];
           ret = HttpServer::rpc_cbs[method](params);
           try
           {
               ret["id"] = json["id"].get<int>();
           }
           catch (const std::exception &e)
           {
               ret["id"] = json["id"].get<std::string>();
           }
           ret["jsonrpc"] = "2.0";
       }
   }
   catch (const std::exception &e)
   {
       ret["error"]["code"] = -32700;
       ret["error"]["message"] = "Internal error";
       ret["id"] = "";
   }
   res.set_content(ret.dump(4), "application/json");
}
//
//void api_get_db_key(const Request &req, Response &res)
//{
//    std::string key;
//    if (req.has_param("key"))
//    {
//        key = req.get_param_value("key");
//    }
//
//    std::string value;
//    DBReader().ReadData(key, value);
//    res.set_content(value, "text/plain");
//}
//
void api_print_block(const Request &req, Response &res)
{
   int num = 100;
   if (req.has_param("num"))
   {
       num = atol(req.get_param_value("num").c_str());
   }
   std::string str = printBlocks(num, req.has_param("pre_hash_flag"));
   res.set_content(str, "text/plain");
}
//
//void api_info_queue(const Request &req, Response &res)
//{
//    std::ostringstream oss;
//    oss << "queue_read:" << global::queue_read.msg_queue_.size() << std::endl;
//    oss << "queue_work:" << global::queue_work.msg_queue_.size() << std::endl;
//    oss << "queue_write:" << global::queue_write.msg_queue_.size() << std::endl;
//    oss << "\n"
//        << std::endl;
//
//    double total = .0f;
//    oss << "------------------------------------------" << std::endl;
//    for (auto &item : global::reqCntMap)
//    {
//        total += (double) item.second.second;
//        oss.precision(3);
//        oss << item.first << ": " << item.second.first << " size: " << (double) item.second.second / 1024 / 1024
//            << " MB" << std::endl;
//    }
//    oss << "------------------------------------------" << std::endl;
//    oss << "Total: " << total / 1024 / 1024 << " MB" << std::endl;
//
//    res.set_content(oss.str(), "text/plain");
//}
//
void api_info(const Request &req, Response &res)
{

   std::ostringstream oss;

   oss << "queue:" << std::endl;
   oss << "queue_read:" << global::queue_read.msg_queue_.size() << std::endl;
   oss << "queue_work:" << global::queue_work.msg_queue_.size() << std::endl;
   oss << "queue_write:" << global::queue_write.msg_queue_.size() << std::endl;
   oss << "\n"
       << std::endl;

   oss << "amount:" << std::endl;
   std::vector<std::string> baselist;
   
   MagicSingleton<AccountManager>::GetInstance()->GetAccountList(baselist);
   for (auto &i : baselist)
   {
       uint64_t amount = 0;
       GetBalanceByUtxo(i, amount);
       oss << i + ":" + std::to_string(amount) << std::endl;
   }
   oss << "\n"
       << std::endl;

   std::vector<Node> nodeList = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
   oss << "Public PeerNode size is: " << nodeList.size() << std::endl;
   oss << MagicSingleton<PeerNode>::GetInstance()->nodelist_info(nodeList);

   oss << std::endl << std::endl;

   res.set_content(oss.str(), "text/plain");
}
//
//
void api_get_block(const Request &req, Response &res)
{
    nlohmann::json blocks;

    int top = 0;
    if (req.has_param("top"))
    {
        top = atol(req.get_param_value("top").c_str());
    }
    int num = 0;
    if (req.has_param("num"))
    {
        num = atol(req.get_param_value("num").c_str());
    }

    num = num > 500 ? 500 : num;

    if (top < 0 || num <= 0)
    {
        ERRORLOG("api_get_block top < 0||num <= 0");
        return;
    }

	DBReader db_reader;
    uint64_t mytop = 0;
    db_reader.GetBlockTop(mytop);
    if (top > (int) mytop)
    {
        ERRORLOG("api_get_block begin > mytop");
        return;
    }
    int k = 0;
    for (auto i = top; i <= top + num; i++)
    {
        std::vector<std::string> vBlockHashs;
        db_reader.GetBlockHashsByBlockHeight(i, vBlockHashs);

        for (auto hash : vBlockHashs)
        {
            string strHeader;
            db_reader.GetBlockByBlockHash(hash, strHeader);
            blocks[k++] = httplib::detail::base64_encode(strHeader);
        }
    }

   res.set_content(blocks.dump(4), "application/json");
}

void api_filter_height(const Request &req, Response &res)
{
    std::ostringstream oss;

    DBReader db_reader;
    uint64_t myTop = 0;
    db_reader.GetBlockTop(myTop);

    std::vector<Node> nodeList = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
    std::vector<Node> filterNodes;

    for(auto & node : nodeList)
    {
        if(node.height == myTop)
        {
            filterNodes.push_back(node);
        }
    }

    oss << "My Top : " << myTop << std::endl;
    oss << "Public PeerNode size is: " << filterNodes.size() << std::endl;
    oss << MagicSingleton<PeerNode>::GetInstance()->nodelist_info(filterNodes);

    oss << std::endl << std::endl;

   res.set_content(oss.str(), "text/plain");

}

void api_print_peernodecache(const Request &req, Response &res)
{
    std::ostringstream oss;

    vector<Node> peer_node_cache_ = MagicSingleton<PeerNodeCache>::GetInstance()->GetNodeCache();
	peer_node_cache_.push_back(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());

    std::vector<Node> eligible_nodes;

    for (const auto &node : peer_node_cache_)
    {
        int ret = VerifyBonusAddr(node.base58address);

        int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
        if (stake_time > 0 && ret == 0)
        {
            eligible_nodes.push_back(node);
        }
    }

    oss << MagicSingleton<PeerNode>::GetInstance()->nodelist_info(eligible_nodes);
    oss << std::endl << std::endl;
    
    res.set_content(oss.str(), "text/plain");
}

void api_start_autotx(const Request &req, Response &res)
{
    // std::ostringstream oss; 
    // oss << "end auto tx:" << std::endl;
    if(!flag)
    {
        std::cout<<"flag ="<<flag<<std::endl;
        std::cout<<"api_start_autotx is going "<<std::endl;
        return ;
    }
   
    // int tranNum = 0;
    // if (req.has_param("tranNum"))
    // {
    //     tranNum = atol(req.get_param_value("tranNum").c_str());
    // }
    int Interval = 0;
    if (req.has_param("Interval"))
    {
        Interval = atol(req.get_param_value("Interval").c_str());
    }
    int Interval_frequency = 0;
    if (req.has_param("Interval_frequency"))
    {
        Interval_frequency = atol(req.get_param_value("Interval_frequency").c_str());
    }

   
    std::cout<<"Interval ="<<Interval<<std::endl;
    std::cout<<"Interval_frequency ="<<Interval_frequency<<std::endl;
    std::vector<std::string> addrs;

    //MagicSingleton<AccountManager>::GetInstance()->PrintAllAccount();
    MagicSingleton<AccountManager>::GetInstance()->GetAccountList(addrs);

    std::vector<std::string>::iterator it = std::find(addrs.begin(),addrs.end(),MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
    if(it != addrs.end())
    {
        addrs.erase(it);
    }

    //std::random_shuffle(addrs.begin(),addrs.end());

    flag = false;
    
    ThreadTest::set_StopTx_flag(flag);
    std::thread th(&ThreadTest::test_createTx,Interval_frequency, addrs, Interval);
    th.detach();
    return;
   
}
void api_status_autotx(const Request &req, Response &res)
{
    std::ostringstream oss; 
    bool flag = false;
    ThreadTest::get_StopTx_flag(flag);
    if(!flag)
    {
        oss << "auto tx is going :" << std::endl;
    }
    else
    {
         oss << "auto tx is end!:" << std::endl;
    }
    res.set_content(oss.str(), "text/plain");
}

void api_end_autotx(const Request &req, Response &res)
{
    std::ostringstream oss; 
    oss << "end auto tx:" << std::endl;
  
    flag = true;
    ThreadTest::set_StopTx_flag(flag);
    res.set_content(oss.str(), "text/plain");
}



nlohmann::json jsonrpc_get_height(const nlohmann::json &param)
{
    DBReader db_reader;
    uint64_t top = 0;
    db_reader.GetBlockTop(top);

   nlohmann::json ret;
   ret["result"]["height"] = std::to_string(top);
   return ret;
}

nlohmann::json jsonrpc_get_balance(const nlohmann::json &param)
{
   nlohmann::json ret;
   std::string address;
   try
   {
       if (param.find("address") != param.end())
       {
           address = param["address"].get<std::string>();
       }
       else
       {
           throw std::exception();
       }
   }
   catch (const std::exception &e)
   {
       ret["error"]["code"] = -32602;
       ret["error"]["message"] = "Invalid params";
       return ret;
   }

   if (!CheckBase58Addr(address))
   {
       ret["error"]["code"] = -1;
       ret["error"]["message"] = "address is invalid ";
       return ret;
   }

   uint64_t balance = 0;
   if (GetBalanceByUtxo(address.c_str(), balance) != 0)
   {
       ret["error"]["code"] = -2;
       ret["error"]["message"] = "search balance failed";
       return ret;
   }
   ret["result"]["balance"] = balance;
   return ret;
}
