#include "ca/ca_blockstroage.h"
#include "utils/VRF.hpp"



void BlockStroage::StartTimer()
{
    	
        //Notifications for inspections at regular intervals
	_block_timer.AsyncLoop(100, [this](){
		BlockCheck();
	});
}


int BlockStroage::AddBlock(const BlockMsg &msg)
{
	std::unique_lock<std::mutex> lck(_block_mutex_);

    CBlock block;
    block.ParseFromString(msg.block());

	std::vector<BlockMsg> msgVec;
	msgVec.push_back(msg); 
    //Self-add does not have its own signature on the block at this time
	_BlockMap.insert(std::pair<uint64_t,std::vector<BlockMsg>>(block.time(),msgVec));

	DEBUGLOG("add TranStroage");
	lck.unlock();

    return 0;
}

int BlockStroage::UpdateBlock(const BlockMsg &msg)
{
    std::unique_lock<std::mutex> lck(_block_mutex_);

    CBlock block;
    block.ParseFromString(msg.block());

    if(block.sign_size() != 2)
    {
		ERRORLOG("sign  size != 2");
        return -1;
    }


	for(auto &i : _BlockMap)
	{
		
		if(block.time() != i.first || i.second.size() == global::ca::kConsensus)
		{
			continue;
		}
        
		i.second.push_back(msg);

		if(i.second.size() == global::ca::kConsensus)
		{
		
            //Combined into BlockMsg
			composeEndBlockmsg(i.second);	
		}
	}
	lck.unlock();

	return 0;
}


void BlockStroage::BlockCheck()
{
    std::unique_lock<std::mutex> lck(_block_mutex_);

	std::vector<uint64_t> timeKey;
	for(auto &i : _BlockMap)
	{
        BlockMsg copyendmsg_ = i.second.at(0); // Spelled TxMsgReq

        CBlock block;
        block.ParseFromString(copyendmsg_.block());
        
        if(block.time() == 0 )
        {
            INFOLOG("block.time == 0,time = {}",block.time());
            continue;
        }

        if(block.time() != i.first)
        {
            timeKey.push_back(block.time()); 
            continue;
        }
        
        int64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
        const int64_t kTenSecond = (int64_t)1000000 * 10; // TODO::10s

        DEBUGLOG("block.sign_size() =  {}",block.sign_size());
        if( abs(nowTime - (int64_t)block.time()) >= kTenSecond)
        {
            ERRORLOG("Add to failure list");
            timeKey.push_back(block.time());
            copyendmsg_.Clear();

        }
        else if(block.sign_size() == global::ca::kConsensus)
        {
            DEBUGLOG("begin add cache block");
           
            //Verify Block flow verifies the signature of the node
            std::pair<std::string, std::vector<std::string>> nodes_pair;
            
            MagicSingleton<VRF>::GetInstance()->getVerifyNodes(block.hash(), nodes_pair);
            
            //Block signature node in cache
            std::vector<std::string> cache_nodes = nodes_pair.second;
            
            //The signature node in the block flow
            std::vector<std::string> verify_nodes;
            for(auto &item : block.sign())
            {
                verify_nodes.push_back(GetBase58Addr(item.pub()));
                
            }

            
            //Compare whether the nodes in the two containers are consistent
            for(auto & sign_node : verify_nodes)
            {
                if(std::find(cache_nodes.begin(), cache_nodes.end(), sign_node) == cache_nodes.end())
                {
                    DEBUGLOG(" The nodes in the two containers are inconsistent = {}",sign_node);
                    timeKey.push_back(block.time());
                    continue;
                }
            }

           
            //After the verification is passed, the broadcast block is directly built
            if(block.version() >=0)
            {
                MagicSingleton<BlockMonitor>::GetInstance()->SendBroadcastAddBlock(copyendmsg_.block(),block.height());
                INFOLOG("Start to broadcast BuildBlockBroadcastMsg...");
            }
            else
            {
                std::cout << "The version is too low. Please update the version!" << std::endl;
            }
            
            timeKey.push_back(block.time());
            copyendmsg_.Clear();
        }

	}
	if(!timeKey.empty())
	{
		for (auto &time : timeKey)
		{
			Remove(time);
		}
	}
	timeKey.clear();    
}

void BlockStroage::composeEndBlockmsg(std::vector<BlockMsg> &msgvec)
{
	for(auto &msg : msgvec)
	{  
        CBlock block;
        block.ParseFromString(msg.block());

        if(block.sign_size() == 1)     // Exclude yourself
        {
            continue;
        }

        if(block.sign_size() != 2)
        {
            continue;
        }
        else
        {
            CBlock endBlock;
            endBlock.ParseFromString(msgvec[0].block()); 


            CSign * sign  = endBlock.add_sign();
            // sign->set_id(composeBlock.sign(1).id());
            sign->set_pub(block.sign(1).pub());
            sign->set_sign(block.sign(1).sign());


            msgvec[0].set_block(endBlock.SerializeAsString());

        }    
    }        
        
	
}


void BlockStroage::Remove(const uint64_t &time)
{
	for(auto iter = _BlockMap.begin(); iter != _BlockMap.end();)
	{
		if (iter->first == time)
		{
			iter = _BlockMap.erase(iter);
			DEBUGLOG("BlockStroage::Remove");
		}
		else
		{
			iter++;
		}
	}
}







