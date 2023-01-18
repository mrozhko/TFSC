#ifndef __CA_TRANSACTION_CACHE__
#define __CA_TRANSACTION_CACHE__

#include "../proto/transaction.pb.h"
#include "../proto/ca_protomsg.pb.h"
#include "utils/CTimer.hpp"
#include "ca/ca_transactionentity.h"


#include <map>
#include <list>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <string>



//Transaction cache class. After the transaction flow ends, add the transaction to this class. Pack blocks every time a certain interval elapses or when the number of transactions reaches a certain number.
class CtransactionCache
{
    private:
    
    //Used to store statistical information
        struct StatisticEntity
        {
            // Pre-block hash
            std::string pre_block_hash_;
            // The hash of the transaction that owns the hash of that previous block
            std::vector<std::string> transaction_hashes_;
            // The hash is the percentage of all transactions
            double percentage_;
        };

        typedef std::list<TransactionEntity>::const_iterator tx_entities_iter;
        typedef std::map<uint64_t, std::list<TransactionEntity>>::iterator cache_iter;

        struct hash_comparator
        {
            bool operator()(const StatisticEntity& p_left, const std::string& p_right)
            {
                return p_left.pre_block_hash_ < p_right;
            }
            bool operator()(const std::string& p_left, const StatisticEntity& p_right)
            {
                return p_left < p_right.pre_block_hash_;
            }
        };

    private:
        // Transaction container
        std::map<uint64_t/*height*/  ,std::list<TransactionEntity>> cache_;
        // The mutex of the transaction container
        std::mutex cache_mutex_;
        // Condition variables are used to package blocks
        std::condition_variable blockbuilder_;
        // Timers are used for packing at specific time intervals
        CTimer build_timer_;
        // Thread variables are used for packaging
        std::thread build_thread_;
        // Packing interval
        static const int build_interval_;
        // Transaction expiration interval
        static const time_t tx_expire_interval_;
        // Packaging threshold
        static const int build_threshold_;
        //  Decision threshold (percentage) 
        static const double decision_threshold_; 
        // Transaction pending container
        std::map<uint64_t/*height*/  ,std::list<TransactionEntity>> pending_cache_;
        // The transaction holds the mutex of the container
        std::mutex pending_cache_mutex_;

    public:
        CtransactionCache();
        ~CtransactionCache() = default;
        // Add a cache
        int add_cache(const CTransaction& transaction, const TxMsgReq& SendTxMsg);
        //  Start the packaging block building thread 
        bool process();
        // Check for conflicting (overloaded) block pool calls
        bool check_conflict(const CTransaction& transaction, const TxMsgReq& SendTxMsg);
        // Get the transaction cache
        void get_cache(std::map<uint64_t, std::list<TransactionEntity>>& cache); 
        // Query the cache for the existence of a transaction
        bool exist_in_cache(const std::string& hash);
        // Delete the pending transaction cache
        bool remove_pending_transaction(const std::string& tx_hash);

       

    private:
        // Threading functions
        void processing_func(); 
        // Generate hash statistics that meet the criteria
        void generate_statistic_info(const TransactionEntity&  tx_entity, std::list<StatisticEntity>& statistic_list);
        // Obtain the pre-hash statistics of the flow node
        std::list<StatisticEntity> get_statistic_info(const std::list<tx_entities_iter>& tx_entities);
        // Filter packaged transactions
        int filter_current_transaction(std::list<StatisticEntity>& static_info, 
                                                            std::list<tx_entities_iter>& tx_entities, 
                                                            std::string& pre_block_hash, 
                                                            bool& build_first /*Whether to build a block first*/);
        // Get the cache that needs to be blocked
        std::list<tx_entities_iter>  get_needed_cache(const std::list<TransactionEntity>& txs);
        // Delete the block building cache and expired cache
        //  Return value: Whether there are still transactions at that height
        bool remove_processed_transaction(const  std::list<tx_entities_iter>& tx_entities_iter, const bool build_success, std::list<TransactionEntity>& tx_entities);
        // Check if a transaction is in a cache
        bool find_tx(const std::map<uint64_t/*height*/  ,std::list<TransactionEntity>>& cache, const std::string& tx_hash);
        // Clean up functions
        void tear_down(const  std::list<tx_entities_iter>& tx_entities_iters, const bool build_success, std::vector<cache_iter>& empty_height_cache , cache_iter cache_entity);
};
#endif
