#include "dispatcher.h"
#include <string>
#include "../include/logging.h"
#include "net.pb.h"
#include "common.pb.h"
#include "handle_event.h"
#include "./peer_node.h"
#include "utils/compress.h"
#include <utility>
#include "global.h"
#include "common/global.h"
#include "logging.h"
#include "common/task_pool.hpp"
#include "utils/MagicSingleton.h"

int ProtobufDispatcher::handle(const MsgData &data)
{
    CommonMsg common_msg;
    int r = common_msg.ParseFromString(data.pack.data);
    if (!r)
    {
        ERRORLOG("parse CommonMsg error");
        return -1;
    }

    std::string type = common_msg.type();
    {
        //  statistics
        std::lock_guard<std::mutex> lock(global::g_mutex_req_cnt_map);
        global::reqCntMap[type].first += 1;
        global::reqCntMap[type].second += common_msg.data().size();
    }
    
    if (common_msg.version() != global::kNetVersion)
    {
        ERRORLOG("common_msg.version() {}", common_msg.version());
        return -2;
    }

    if (type.size() == 0)
    {
        ERRORLOG("handle type is empty");
        return -3;
    }

    const Descriptor *des = google::protobuf::DescriptorPool::generated_pool()->FindMessageTypeByName(type);
    if (!des)
    {
        ERRORLOG("cannot create Descriptor for {}", type.c_str());
        return -4;
    }

    const Message *proto = google::protobuf::MessageFactory::generated_factory()->GetPrototype(des);
    if (!proto)
    {
        ERRORLOG("cannot create Message for {}", type.c_str());
        return -5;
    }

    string sub_serialize_msg;
    if (common_msg.compress())
    {
        Compress uncpr(std::move(common_msg.data()), common_msg.data().size() * 10);
        sub_serialize_msg = uncpr.m_raw_data;
    }
    else
    {
        sub_serialize_msg = std::move(common_msg.data());
    }

    MessagePtr sub_msg(proto->New());
    r = sub_msg->ParseFromString(sub_serialize_msg);
    if (!r)
    {
        ERRORLOG("bad msg for protobuf for {}", type.c_str());
        return -6;
    }

    auto task_pool = MagicSingleton<taskPool>::GetInstance();
    std::string name = sub_msg->GetDescriptor()->name();
    auto p1 = ca_protocbs_.find(name);
    if (p1 != ca_protocbs_.end())
    {
        DEBUGLOG("ca_protocbs_ message type {}", sub_msg->GetDescriptor()->name().c_str());
        task_pool->commit_ca_task(p1->second, sub_msg, data);
    }
    auto broadcast_map= broadcast_protocbs_.find(name);
    if (broadcast_map != broadcast_protocbs_.end())
    {
        DEBUGLOG("broadcast_protocbs_ message type {}", sub_msg->GetDescriptor()->name().c_str());
        task_pool->commit_broadcast_task(broadcast_map->second, sub_msg, data);
        return 0;
    }
    auto p2 = net_protocbs_.find(name);
    if (p2 != net_protocbs_.end())
    {
        DEBUGLOG("net_protocbs_ message type {}", sub_msg->GetDescriptor()->name().c_str());
        task_pool->commit_net_task(p2->second, sub_msg, data);
        return 0;
    }
    else
    {
        ERRORLOG("unknown message type {}", sub_msg->GetDescriptor()->name().c_str());
        return -7;
    }
}

void ProtobufDispatcher::registerAll()
{
    net_registerCallback<RegisterNodeReq>(handleRegisterNodeReq);
    net_registerCallback<RegisterNodeAck>(handleRegisterNodeAck);
    net_registerCallback<SyncNodeReq>(handleSyncNodeReq);
    net_registerCallback<SyncNodeAck>(handleSyncNodeAck);
    
    net_registerCallback<BroadcastMsgReq>(handleBroadcastMsgReq);
    
    net_registerCallback<PrintMsgReq>(handlePrintMsgReq);
    net_registerCallback<PingReq>(handlePingReq);
    net_registerCallback<PongReq>(handlePongReq);
    net_registerCallback<EchoReq>(handleEchoReq);
    net_registerCallback<EchoAck>(handleEchoAck);
    net_registerCallback<NodeHeightChangedReq>(handleNodeHeightChangedReq);
    net_registerCallback<NodeBase58AddrChangedReq>(handleNodeBase58AddrChangedReq);
    broadcast_registerCallback<BuildBlockBroadcastMsg>(handleBroadcastMsg);//Broadcast forwarding callbacks
}

void ProtobufDispatcher::task_info(std::ostringstream& oss)
{
    auto task_pool = MagicSingleton<taskPool>::GetInstance();
    oss << "ca_active_task:" << task_pool->ca_active() << std::endl;
    oss << "ca_pending_task:" << task_pool->ca_pending() << std::endl;
    oss << "==================================" << std::endl;
    oss << "net_active_task:" << task_pool->net_active() << std::endl;
    oss << "net_pending_task:" << task_pool->net_pending() << std::endl;
    oss << "==================================" << std::endl;
    oss << "broadcast_active_task:" << task_pool->broadcast_active() << std::endl;
    oss << "broadcast_pending_task:" << task_pool->broadcast_pending() << std::endl;
    oss << "==================================" << std::endl;

}
