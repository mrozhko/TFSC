#ifndef __TASK_POOL_H__
#define __TASK_POOL_H__
#define BOOST_BIND_NO_PLACEHOLDERS

#include "net/dispatcher.h"
#include "utils/MagicSingleton.h"
#include "./config.h"
#include <boost/threadpool.hpp>
using boost::threadpool::pool; 

class taskPool{

public:
    taskPool():ca_taskPool(MagicSingleton<Config>::GetInstance()->GetThreadNum()),net_taskPool(8),broadcast_taskPool(18){}
    void commit_ca_task(ProtoCallBack func, MessagePtr sub_msg, const MsgData &data)
    {
        ca_taskPool.schedule(boost::bind(func, sub_msg, data));
    }
    void commit_net_task(ProtoCallBack func, MessagePtr sub_msg, const MsgData &data)
    {
        net_taskPool.schedule(boost::bind(func, sub_msg, data));
    }

    void commit_broadcast_task(ProtoCallBack func, MessagePtr sub_msg, const MsgData &data)
    {
        broadcast_taskPool.schedule(boost::bind(func, sub_msg, data));
    }

    /*! Returns the number of tasks which are currently executed.
    * \return The number of active tasks. 
    */  
    size_t ca_active() const
    {
      return ca_taskPool.active();
    }


    /*! Returns the number of tasks which are ready for execution.    
    * \return The number of pending tasks. 
    */  
    size_t ca_pending() const
    {
      return ca_taskPool.pending();
    }

    /*! Returns the number of tasks which are currently executed.
    * \return The number of active tasks. 
    */  
    size_t net_active() const
    {
      return net_taskPool.active();
    }


    /*! Returns the number of tasks which are ready for execution.    
    * \return The number of pending tasks. 
    */  
    size_t net_pending() const
    {
      return net_taskPool.pending();
    }


    size_t broadcast_active() const
    {
      return broadcast_taskPool.active();
    }


    size_t broadcast_pending() const
    {
      return broadcast_taskPool.pending();
    }

private:
    pool ca_taskPool;
    pool net_taskPool;
    pool broadcast_taskPool;
};

#endif // __TASK_POOL_H__