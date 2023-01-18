#include "ca/ca_transtroage.h" 
#include "db/db_api.h"
#include "ca_transaction.h"
#include "utils/AccountManager.h"
#include "utils/TFSbenchmark.h"


/*********************************Broadcast circulation**************************************/


void TranStroage::Start_Timer()
{
	
	//Notifications for inspections at regular intervals
	
	_timer.AsyncLoop(100, [this](){
		Check();
	});
}

void TranStroage::Check()
{
	std::unique_lock<std::mutex> lck(_TranMap_mutex_);

	
	std::vector<uint64_t> timeKey;
	for(auto &i : _TranMap)
	{
			TxMsgReq copyendmsg_ = i.second.at(0);  //Spelled TxMsgReq
			CTransaction tx;
			if (!tx.ParseFromString(copyendmsg_.txmsginfo().tx()))
			{
				ERRORLOG("Failed to deserialize transaction body! time = {}",tx.time());
				continue;
			}
			
			if(tx.time() == 0 )
			{
				INFOLOG("tx.time == 0,time = {}",tx.time());
				continue;
			}

			if(tx.time() != i.first)
			{
				timeKey.push_back(tx.time());
				continue;
			}
			
			int64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
			const int64_t kTenSecond = (int64_t)1000000 * 10; // TODO::10s
			
			if( abs(nowTime - (int64_t)tx.time()) >= kTenSecond)
			{
				ERRORLOG("Transaction flow time timeout");
				timeKey.push_back(tx.time());
				copyendmsg_.Clear();

			}
			else if(copyendmsg_.signnodemsg_size() == global::ca::kConsensus)
			{
				DEBUGLOG("begin add cache ");

				for(auto & item : tx.verifysign())
				{
					DEBUGLOG("dohandletx verify sign addr = {} ", GetBase58Addr(item.pub()));
				}

				int ret = VerifyTxMsgReq(copyendmsg_);
				if(ret != 0)
				{
					ERRORLOG("VerifyTxMsgReq failed! ret = {} ",ret );
					continue;
				}
				// Return to the originating node
				std::string blockHash;
				DBReader db_reader;
				auto db_status = db_reader.GetBlockHashByTransactionHash(tx.hash(), blockHash);
				if (db_status != DBStatus::DB_SUCCESS && db_status != DBStatus::DB_NOT_FOUND)
				{
					timeKey.push_back(tx.time());
					DEBUGLOG("GetBlockHashByTransactionHash failed! ");
					continue;
				}

				if(!blockHash.empty() || MagicSingleton<CtransactionCache>::GetInstance()->exist_in_cache(tx.hash()))
				{
					// If it is found, it indicates that the block has been added or in the block cache
					timeKey.push_back(tx.time());
					DEBUGLOG("Already in cache!");
					continue;
				}

				ret = MagicSingleton<CtransactionCache>::GetInstance()->add_cache(tx, copyendmsg_);	

				if( 0 != ret)
				{
					ret -= 900;
					ERRORLOG("HandleTx BuildBlock failed! ret = {} , time = {}",ret,tx.time());
				}
				
				timeKey.push_back(tx.time());
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
	
int TranStroage::Add(const TxMsgReq &msg )
{
	CTransaction tx;
	if (!tx.ParseFromString(msg.txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}

	std::unique_lock<std::mutex> lck(_TranMap_mutex_);
	std::vector<TxMsgReq> msgVec;
	msgVec.push_back(msg);
	_TranMap.insert(std::pair<uint64_t,std::vector<TxMsgReq>>(tx.time(),msgVec));

	DEBUGLOG("add TranStroage");
	lck.unlock();

	return 0;
}
 
int TranStroage::Update(const TxMsgReq &msg )
{
	std::unique_lock<std::mutex> lck(_TranMap_mutex_);


	DEBUGLOG("TranStroage::Update1");
	bool flag = false;
	CTransaction tx;
	if (!tx.ParseFromString(msg.txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -1;
	}
	 MagicSingleton<TFSBenchmark>::GetInstance()->AddTransactionSignReceiveMap(tx.hash());

	if(msg.signnodemsg_size() != 2)
	{
		ERRORLOG("msg.signnodemsg_size() != 2");
		return -2;
	}

	for(auto &i : _TranMap)
	{
		
		if(tx.time() != i.first || i.second.size() == global::ca::kConsensus)
		{
			
			continue;
		}

		for(auto const & item  :i.second)
		{
			if(item.signnodemsg_size() == 1 || item.prevblkhashs_size() == 0 )
			{
				continue;
			}
			std::string addr = GetBase58Addr(item.signnodemsg(1).pub());
			if(addr == GetBase58Addr(msg.signnodemsg(1).pub()))
			{
				flag = true;
				DEBUGLOG("addr = {} , msg addr = {}",addr,GetBase58Addr(msg.signnodemsg(1).pub()));
				break;
			}
		}

		if(flag)
		{
			ERRORLOG("2 nodes can Transaction continue");
			continue;
		}

		i.second.push_back(msg);

		if(i.second.size() == global::ca::kConsensus)
		{
			DEBUGLOG("TranStroage::Update");
			// Combined into endTxMsg
			composeEndmsg(i.second);
			CTransaction tx_;
			if (!tx_.ParseFromString(i.second.at(0).txmsginfo().tx()))
			{
				ERRORLOG("Failed to deserialize transaction body!");
				return -3;
			}

			MagicSingleton<TranMonitor>::GetInstance()->SetComposeStatus(tx_);
			MagicSingleton<TFSBenchmark>::GetInstance()->CalculateTransactionSignReceivePerSecond(tx.hash(), MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
			
		}
	}
	lck.unlock();

	return 0;
}

void TranStroage::Remove(const uint64_t &time)
{
	for(auto iter = _TranMap.begin(); iter != _TranMap.end();)
	{
		if (iter->first == time)
		{
			iter = _TranMap.erase(iter);
			DEBUGLOG("TranStroage::Remove");
		}
		else
		{
			iter++;
		}
	}
}

void TranStroage::composeEndmsg( std::vector<TxMsgReq> &msgvec)
{
	DEBUGLOG("TranStroage::composeEndmsg");

	for(auto &i : msgvec)
	{
		
		if(i.signnodemsg_size() == 1 || i.prevblkhashs_size() == 0 )
		{
			continue;
		}

		if(i.signnodemsg_size() != 2 )
		{
			continue;
		}
		else
		{
			
			DEBUGLOG("TranStroage::composeEndmsg1");
			CTransaction tx_end;
			if (!tx_end.ParseFromString(msgvec[0].txmsginfo().tx()))
			{
				ERRORLOG("Failed to deserialize transaction body!");
				return ;
			}

			CTransaction tx_compose;
			if (!tx_compose.ParseFromString(i.txmsginfo().tx()))
			{
				ERRORLOG("Failed to deserialize transaction body!");
				return ;
			}


			CSign * end_sign =  tx_end.add_verifysign();
			end_sign->set_sign(tx_compose.verifysign(1).sign());
			end_sign->set_pub(tx_compose.verifysign(1).pub());

			SignNodeMsg * nodeMsg = msgvec[0].add_signnodemsg();
			nodeMsg->set_id(i.signnodemsg(1).id());
			nodeMsg->set_sign(i.signnodemsg(1).sign());
			nodeMsg->set_pub(i.signnodemsg(1).pub());

			for(int j = 0 ; j < i.prevblkhashs_size() ; j++)
			{
				msgvec[0].add_prevblkhashs(i.prevblkhashs(j));
			}

			tx_end.clear_hash();
			tx_end.set_hash(getsha256hash(tx_end.SerializeAsString()));
			msgvec[0].mutable_txmsginfo()->set_tx(tx_end.SerializeAsString());
		}
	}
}
