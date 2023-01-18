#include <unordered_map>

#include "ca_transaction_cache.h"
#include "ca_transaction.h"
#include "utils/json.hpp"
#include "db/db_api.h"

#include "ca/ca_txhelper.h"
#include "utils/MagicSingleton.h"
#include "ca_algorithm.h"
#include "../utils/time_util.h"
#include "utils/AccountManager.h"
#include "ca_tranmonitor.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"
#include "ca_checker.h"
#include "utils/TFSbenchmark.h"

const int CtransactionCache::build_interval_ = 3 * 1000;
const time_t CtransactionCache::tx_expire_interval_  = 10;
const int CtransactionCache::build_threshold_ = 1000000;
const double CtransactionCache::decision_threshold_ = 0.8; 


int CreateBlock(std::vector<TransactionEntity>& txs,const string& preblkhash,CBlock& cblock)
{
	cblock.Clear();

	// Fill version
	cblock.set_version(0);

	// Fill time
	uint64_t time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	cblock.set_time(time);

	// Fill preblockhash
	if(preblkhash.empty())
	{
		ERRORLOG("Preblkhash is empty!");
		return -1;
	}
	cblock.set_prevhash(preblkhash);

	// Fill height
	uint64_t prevBlockHeight = txs.front().get_txmsg().txmsginfo().height();
	uint64_t cblockHeight = ++prevBlockHeight;
	DBReader db_reader;
	uint64_t myTop = 0;
	db_reader.GetBlockTop(myTop);
	if ( (myTop  > global::ca::kUpperBlockHeight) && (myTop - global::ca::kUpperBlockHeight > cblockHeight))
	{
		ERRORLOG("CblockHeight is invalid!");
		return -2;
	}
	else if (myTop + global::ca::kLowerBlockHeight < cblockHeight)
	{
		ERRORLOG("CblockHeight is invalid!");
		return -3;
	}
	cblock.set_height(cblockHeight);

	// Fill tx
	for(auto& tx : txs)
	{
		// Add major transaction
		CTransaction * major_tx = cblock.add_txs();
		*major_tx = tx.get_transaction();
		
		{
			// Add sign transaction 
			CTransaction sign_tx;
			int ret = CreateSignTransaction(*major_tx, sign_tx);
			if(ret != 0)
			{
				ERRORLOG("Create sign transaction failed!");
				return ret - 100;
			}
			CTransaction * tx1 = cblock.add_txs();
			*tx1 = sign_tx;
		}

		{
			// add burn
			CTransaction burn_tx;
			int ret = CreateBurnTransaction(*major_tx, burn_tx);
			if(ret != 0)
			{
				ERRORLOG("Create burn transaction failed!");
				return ret - 200;
			}

			CTransaction * tx2 = cblock.add_txs();
			*tx2 = burn_tx;
		}
		
		auto tx_hash = major_tx->hash();
	}

	// Fill merkleroot
	cblock.set_merkleroot(ca_algorithm::CalcBlockMerkle(cblock));
	// Fill hash
	cblock.set_hash(getsha256hash(cblock.SerializeAsString()));

    MagicSingleton<TFSBenchmark>::GetInstance()->AddBlockContainsTransactionAmountMap(cblock.hash(), txs.size());


	return 0;
}

int BuildBlock(std::vector<TransactionEntity>& txs,const string& preblkhash, bool build_first)
{
	if(txs.empty() || preblkhash.empty())
	{
		ERRORLOG("Txs or preblkhash is empty!");
		return -1;
	}

	CBlock cblock;
	int ret = CreateBlock(txs, preblkhash,cblock);
	if (cblock.hash().empty())
	{
		ERRORLOG("Create block failed!");
		return ret - 1000;
	}
	
	std::string serBlock = cblock.SerializeAsString();
	std::set<CBlock, compator::BlockTimeAscending> blocks;
	MagicSingleton<BlockHelper>::GetInstance()->GetBroadcastBlock(blocks);
	if(Checker::CheckConflict(cblock, blocks))
	{
		ERRORLOG("Block pool has conflict!");
		return -2;
	}

	ca_algorithm::PrintBlock(cblock);
	ret = ca_algorithm::VerifyBlock(cblock);
	if(ret != 0)
	{
		ret = ret - 2000;
		ERRORLOG("Verify block failed! ret:{}", ret);
		return ret;
	}


    BlockMsg blockmsg;
    blockmsg.set_version(global::kVersion);
    blockmsg.set_time(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
    blockmsg.set_block(serBlock);


    for(auto &tx : cblock.txs())
    {
        if(GetTransactionType(tx) != kTransactionType_Tx)
        {
            continue;
        }
        uint64_t handleTxHeight =  cblock.height() - 1;
        TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
        if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
        {
            continue;
        }

        std::pair<std::string,Vrf>  vrf;
        
        CTransaction copyTx = tx;
        copyTx.clear_hash();
        copyTx.clear_verifysign();
        std::string tx_hash = getsha256hash(copyTx.SerializeAsString());
        std::cout<<"buildBlock tx_hash:"<< tx_hash <<std::endl;
        if(!MagicSingleton<VRF>::GetInstance()->getVrfInfo(tx_hash, vrf))
        {
            ERRORLOG("getVrfInfo failed!");
            return -3000;
        }
        Vrf *vrfinfo  = blockmsg.add_vrfinfo();
        vrfinfo ->CopyFrom(vrf.second);

    }

    auto msg = make_shared<BlockMsg>(blockmsg);
	ret = DoHandleBlock(msg);
    if(ret != 0)
    {
        ERRORLOG("DoHandleBlock failed The error code is {}",ret);
        return ret -4000;
    }
    
	return 0;
}

CtransactionCache::CtransactionCache()
{
    build_timer_.AsyncLoop(
        build_interval_, 
        [=](){ blockbuilder_.notify_one(); }
        );
}

int CtransactionCache::add_cache(const CTransaction& transaction, const TxMsgReq& sendTxMsg)
{
    std::unique_lock<mutex> locker(cache_mutex_);
    uint64_t height = sendTxMsg.txmsginfo().height() + 1;

    int res = ca_algorithm::MemVerifyTransactionTx(transaction);
    if (res != 0)
    {
        return res - 1000;
    }

    res = ca_algorithm::VerifyTransactionTx(transaction, height);
    if (res != 0)
    {
        return res - 2000;
    }

    res = ca_algorithm::VerifyCacheTranscation(transaction);
    if (res != 0)
    {
        return res - 3000;
    }

    //  Check for conflicts and verify
    if(check_conflict(transaction, sendTxMsg) )
    {
        TRACELOG("transaction {} hash conflict, maybe already exist in transaction cache", transaction.hash()); 
        return -1;
    }
    auto find = cache_.find(height); 
    if(find == cache_.end()) 
    {
        cache_[height] = std::list<TransactionEntity>{}; 
    }

    time_t add_time = time(NULL);
    cache_.at(height).push_back(TransactionEntity(transaction, sendTxMsg, add_time)) ;
    for(auto tx_entity: cache_)
    {
        if (tx_entity.second.size() >= build_threshold_)
        {
            blockbuilder_.notify_one();
        }
    }
    return 0;
}

bool CtransactionCache::process()
{
    build_thread_ = std::thread(std::bind(&CtransactionCache::processing_func, this));
    build_thread_.detach();
    return true;
}

bool CtransactionCache::check_conflict(const CTransaction& transaction, const TxMsgReq& SendTxMsg)
{
    std::set<CBlock, compator::BlockTimeAscending> blocks; //Block pool
    MagicSingleton<BlockHelper>::GetInstance()->GetBroadcastBlock(blocks);
                
    return Checker::CheckConflict(transaction, cache_, SendTxMsg.txmsginfo().height() + 1) 
                || Checker::CheckConflict(transaction, pending_cache_, SendTxMsg.txmsginfo().height() + 1)
                || Checker::CheckConflict(transaction, blocks);
}

void CtransactionCache::processing_func()
{
    while (true)
    {
        std::unique_lock<mutex> locker(cache_mutex_);
        blockbuilder_.wait(locker);
        
        std::vector<cache_iter> empty_height_cache;
        for(auto cache_entity = cache_.begin(); cache_entity != cache_.end(); ++cache_entity)
        {
            if(cache_entity == cache_.end())
            {
                break;
            }
            std::list<tx_entities_iter> build_txs = get_needed_cache(cache_entity->second);
            std::list<StatisticEntity> statistic_info = get_statistic_info(build_txs);
            std::string pre_block_hash; 
            bool build_first;
            int res = filter_current_transaction(statistic_info, build_txs, pre_block_hash, build_first);
            if(res != 0) 
            {
                TRACELOG("{} build tx fail,no transaction match filter rule", res);
                tear_down(build_txs, false, empty_height_cache, cache_entity);
                continue;
            }
            std::vector<TransactionEntity> build_caches;
            for(auto iter : build_txs)
            {
                build_caches.push_back(*iter);
            }
            res = BuildBlock(build_caches, pre_block_hash, false);
            if(res != 0)
            {
                ERRORLOG("{} build block fail", res);
                tear_down(build_txs, false, empty_height_cache, cache_entity);
                continue;
            }
            std::lock_guard<mutex> locker(pending_cache_mutex_);
            auto find = pending_cache_.find(cache_entity->first); 
            if(find == pending_cache_.end()) 
            {
                pending_cache_[cache_entity->first] = std::list<TransactionEntity>{}; 
            }
            for(auto tx_iter : build_txs)
            {
                pending_cache_[cache_entity->first].push_back(*tx_iter);
            }
            tear_down(build_txs, true, empty_height_cache, cache_entity);
        }
        for(auto cache: empty_height_cache)
        {
            cache_.erase(cache);
        }
        locker.unlock();
        
    }
    
}

void CtransactionCache::generate_statistic_info(const TransactionEntity& tx_entity, std::list<StatisticEntity>& statistic_list)
{
    std::unordered_map<std::string, int> hash_count;
    
    auto pre_hashes =  tx_entity.get_txmsg().prevblkhashs();//  Get the pre-hash array from tx_entity get txmsg
    for(const auto& hash : pre_hashes)
    {
        auto find = hash_count.find(hash);
        if(find == hash_count.end())
        {
            hash_count[hash] = 0;
        }
        hash_count.at(hash) += 1;
    }
    
    uint32_t sign_count =  tx_entity.get_transaction().consensus() - 1;

    for(const auto& item : hash_count)
    {
        double percentage = item.second / sign_count; // Counts the percentage of signers who own the hash of the preceding block
        if(percentage >= decision_threshold_)
        {
            auto pre_hash = item.first;
            auto tx_hash = tx_entity.get_transaction().hash();
            auto find_result = find_if(statistic_list.begin(), statistic_list.end(), 
                                        [&pre_hash](const StatisticEntity& statistic_info)
                                        {
                                            return pre_hash == statistic_info.pre_block_hash_;
                                        } 
                                    );
            if(find_result == statistic_list.end())
            {
                statistic_list.push_back({pre_hash, {tx_hash}, 1});
            }
            else
            {
                find_result->transaction_hashes_.push_back(tx_hash);
                if(percentage < find_result->percentage_)
                {
                    find_result->percentage_ = percentage;
                } 
            }          
        }
        else
        {
        }
    }
}

std::list<CtransactionCache::StatisticEntity> CtransactionCache::get_statistic_info(const std::list<tx_entities_iter>& tx_entities)
{
    std::list<StatisticEntity> statistic_info;
    for(const auto tx_entity : tx_entities)
    {
        generate_statistic_info(*tx_entity, statistic_info);
    }
    return statistic_info;
}

int CtransactionCache::filter_current_transaction(std::list<StatisticEntity>& statistic_info, 
                                                    std::list<tx_entities_iter>& tx_entities,  
                                                    std::string& pre_block_hash, 
                                                    bool& build_first  /*Do you want to build a block first*/ )
{
    if(statistic_info.empty())
    {
        ERRORLOG("There are no eligible transactions");
        return -1;
    }

    
    //Gets the block hash locally at that height
    auto height = tx_entities.front()->get_txmsg().txmsginfo().height();
    std::vector<std::string> local_block_hashes;
    DBReader db_reader;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(height, local_block_hashes))
    {
        ERRORLOG("fail to get block hashes at height {}", height);
        return -2;
    }
    statistic_info.sort([](const StatisticEntity& e1, const StatisticEntity& e2) {return e1.pre_block_hash_ < e2.pre_block_hash_;});
    sort(local_block_hashes.begin(), local_block_hashes.end(), [](const std::string& e1, const std::string& e2){return e1 < e2;});

    // Get the pre-block hash that is present in StatisticEntity and locally available
    std::vector<StatisticEntity> intersect_hash;
    std::set_intersection(statistic_info.begin(), statistic_info.end()
                                        , local_block_hashes.begin(), local_block_hashes.end()
                                        ,back_inserter(intersect_hash), hash_comparator()
                                     );

    if(intersect_hash.empty())
    {
        
        ERRORLOG("There are no eligible transactions");
        return -3;
    }
    auto end = statistic_info.end();
    auto statistic_compator = [](decltype(statistic_info.begin()) iter)
    {
        return [iter](const StatisticEntity& statistic_info){ return iter->pre_block_hash_ == statistic_info.pre_block_hash_;}; 
    };

    statistic_info.sort([](const StatisticEntity& e1, const StatisticEntity& e2) {return e1.percentage_ > e2.percentage_;}); // Sort statistics for easy filtering  Sort statistics for easy filtering 
    for(auto iter = statistic_info.begin(); iter != end; ++iter)
    {
        auto statistic_entity_percentage = iter->percentage_;
        if(statistic_entity_percentage == 1 
            && find_if(intersect_hash.begin(), intersect_hash.end(), statistic_compator(iter)) != intersect_hash.end()
            )
            //There are 100% of the cases in the local and StatisticEntity
        {
            build_first = true;
            pre_block_hash = iter->pre_block_hash_;
            return 0;
        }

        if(decision_threshold_ <= statistic_entity_percentage < (decision_threshold_ + 0.1)
            && find_if(intersect_hash.begin(), intersect_hash.end(), statistic_compator(iter)) == intersect_hash.end()
            )
            //There are no local cases but there are conditions in the StatisticEntity and the proportion is between the threshold and the threshold plus 10%.
        {
            statistic_info.erase(iter);
        }
    }

    if(statistic_info.empty())
    //If the cached value is not locally available but is present in the StatisticEntity and the proportion reaches between the threshold and the threshold plus 10%, the packaging fails
    {
        ERRORLOG("There are no eligible transactions");
        return -4;
    }
    
    //Other cases
    build_first = false;
    auto first_statstic = statistic_info.begin();//  Get the hash of the first statistic (with the highest percentage).
    pre_block_hash = first_statstic->pre_block_hash_;

    std::vector<std::string> tx_hashes = first_statstic->transaction_hashes_;
    for(auto iter = tx_entities.begin(); iter != tx_entities.end(); ++iter)
    {
        if(std::find(tx_hashes.begin(), tx_hashes.end(), (*iter)->get_transaction().hash()) == tx_hashes.end())
        {
            tx_entities.erase(iter);
        }
    }
    return 0;

}

std::list<CtransactionCache::tx_entities_iter> CtransactionCache::get_needed_cache(const std::list<TransactionEntity>& txs)
{
    std::list<tx_entities_iter> build_caches;

    if(txs.empty())
    {
        return build_caches;
    }

    tx_entities_iter iter = txs.begin();
    tx_entities_iter end = txs.end();

    for(int i = 0; i < build_threshold_ && iter != end; ++i, ++iter) 
    {
        build_caches.push_back(iter);
    }        


    return build_caches;
}

bool CtransactionCache::remove_processed_transaction(const  std::list<tx_entities_iter>& tx_entities_iter, const bool build_success, std::list<TransactionEntity>& tx_entities)
{
    // Delete successful or failed transactions for block building
    for(auto iter : tx_entities_iter)
    {
        std::string hash = iter->get_transaction().hash();
        tx_entities.erase(iter);
        std::string message;
        if(build_success)
        {
            message = " successfully packaged";
        }
        else
        {
            message = " packaging fail";
        }
        std::cout << "transaction " << hash << message << std::endl;
    }
    
    // Check for expired transactions
    for(auto tx_entity = tx_entities.begin(); tx_entity != tx_entities.end(); ++tx_entity)
    {
        time_t current_time = time(NULL);
        if((current_time - tx_entity->get_timestamp()) > tx_expire_interval_)
        {
            TRACELOG("transaction {} has expired", tx_entity->get_transaction().hash());
            std::cout << "transaction expired: " << tx_entity->get_transaction().hash() << std::endl;
        }
    }

    if(tx_entities.empty())
    {
        return false;
    }            
    return true;
}

bool CtransactionCache::remove_pending_transaction(const std::string& tx_hash)
{
    std::lock_guard<mutex> locker(pending_cache_mutex_);
    auto end = pending_cache_.end();
    for(auto pending_item = pending_cache_.begin();  pending_item != end; ++pending_item)
    {
        auto& cache_list = pending_item->second;
        auto end = cache_list.end();
        auto result = find_if(cache_list.begin(), end, 
                            [&tx_hash](const TransactionEntity& tx_entity)
                            {
                                return tx_entity.get_transaction().hash() == tx_hash;
                            });
        if(result != end)
        {
            cache_list.erase(result);
            if(cache_list.empty())
            {
                pending_cache_.erase(pending_item);
            }
            TRACELOG("success remove transaction cache {}", tx_hash);
            return true;             
        }
    }

    TRACELOG("fail to remove transaction cache {}，not exist or already been removed", tx_hash);
    return false;
}

void CtransactionCache::get_cache(std::map<uint64_t, std::list<TransactionEntity>>& cache)
{
    cache = cache_;
}

bool CtransactionCache::exist_in_cache(const std::string& hash)
{
    std::unique_lock<mutex> cache_locker(cache_mutex_);
    
    if(find_tx(cache_, hash))
    {
        return true;
    } 
    cache_locker.unlock();

    std::unique_lock<mutex> pending_cache_locker(pending_cache_mutex_);
    
    if(find_tx(pending_cache_, hash))
    {
        return true;
    } 
    pending_cache_locker.unlock();

    return false;
}

bool CtransactionCache::find_tx(const std::map<uint64_t/*height*/  ,std::list<TransactionEntity>>& cache, const std::string& tx_hash)
{
    if(cache.empty())
    {
        return false;
    }
    for(auto item = cache.begin();  item != cache.end(); ++item)
    {
        auto cache_list = item->second;
        auto end = cache_list.end();
        auto result = find_if(cache_list.begin(), end, 
                            [&tx_hash](const TransactionEntity& tx_entity)
                            {
                                return tx_entity.get_transaction().hash() == tx_hash;
                            });
        if(result != end)
        {
            return true;             
        }
    }
    return false;
}
        
void CtransactionCache::tear_down(const  std::list<tx_entities_iter>& tx_entities_iters, const bool build_success, std::vector<cache_iter>& empty_height_cache , cache_iter cache_entity)
{
    if(!remove_processed_transaction(tx_entities_iters, build_success, cache_entity->second))
    {
        empty_height_cache.push_back(cache_entity);         
    }
}

