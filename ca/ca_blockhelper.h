#ifndef _CA_BLOCKHELPER_H
#define _CA_BLOCKHELPER_H

#include <stack>
#include <mutex>
#include <string>
#include <map>
#include <thread>
#include <condition_variable>
#include <atomic>

#include "ca_sync_block.h"
#include "ca_global.h"

namespace compator
{
    struct BlockTimeAscending
    {
        bool operator()(const CBlock &a, const CBlock &b) const
        {
            if(a.height() == b.height()) return a.time() < b.time();
            else if(a.height() < b.height()) return true;
            return false;
        }
    };
}
struct MissingBlock
{
	std::string hash_;
	uint64_t time_;
    std::shared_ptr<bool> tx_or_block_; // 0 is the block, hash 1 is utxo
    std::shared_ptr<bool> trigger;
    std::shared_ptr<uint64_t> trigger_count;
    MissingBlock(const std::string& hash, const uint64_t& time, const bool& tx_or_block)
    {
        hash_ = hash;
        time_ = time;
        tx_or_block_ = std::make_shared<bool>(tx_or_block);
        trigger = std::make_shared<bool>(false);
        trigger_count = std::make_shared<uint64_t>(0);
    }
	bool operator<(const struct MissingBlock & right)const  
	{
		if (this->hash_ == right.hash_)     //Deduplication according to hash_
		{
			return false;
		}
		else
		{
			return time_ < right.time_; //Small top heap
		}
	}
};

class BlockHelper
{
    public:
        BlockHelper();

        int VerifyFlowedBlock(const CBlock& block);
        int SaveBlock(const CBlock& block, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean);

        void SetMissingPrehash();
        void ResetMissingPrehash();
        void PushMissUTXO(const std::string& utxo);  
        void PopMissUTXO();

        static bool obtain_chain_height(uint64_t& chain_height);

        void Process();
        void SeekBlockThread();
        void AddBroadcastBlock(const CBlock& block);
        void AddSyncBlock(const std::map<uint64_t, std::set<CBlock, CBlockCompare>> &sync_block_data, global::ca::SaveType type);
        void AddFastSyncBlock(const std::map<uint64_t, std::set<CBlock, CBlockCompare>> &sync_block_data, global::ca::SaveType type);
        void AddRollbackBlock(const std::map<uint64_t, std::set<CBlock, CBlockCompare>> &sync_block_data);
        void AddMissingBlock(const CBlock& block);
        void AddSeekBlock(std::vector<std::pair<CBlock,std::string>>& seek_blocks);
        void GetBroadcastBlock(std::set<CBlock, compator::BlockTimeAscending>& block);

        int DealDoubleSpend(const CBlock& block, const CTransaction& tx, const std::string& missing_utxo);

    private:
        bool VerifyHeight(const CBlock& block, uint64_t ownblockHeight);
        bool GetMissBlock();
        void PostMembershipPancellationProcess(const CBlock &block);
        void PostTransactionProcess(const CBlock &block);
        int PreSaveProcess(const CBlock& block, global::ca::SaveType saveType, global::ca::BlockObtainMean obtainMean);
        int RollbackBlocks();

        std::mutex helper_mutex;
        std::atomic<bool> missing_prehash;
        std::stack<std::string> missing_utxos;

        std::set<CBlock, compator::BlockTimeAscending> broadcast_blocks; //Broadcast over the block that needs to be joined polled
        std::set<CBlock, compator::BlockTimeAscending> sync_blocks; //Synchronize the blocks that need to be joined polling
        std::set<CBlock, compator::BlockTimeAscending> fast_sync_blocks; //Quickly synchronize over the block polling that needs to be joined 
        std::map<uint64_t, std::set<CBlock, CBlockCompare>> rollback_blocks; //Blocks that need to be rolled back are polled
        std::map<uint64_t, std::multimap<std::string, CBlock>> pending_blocks; //Since there is no block waiting to join before the hash is triggered
        std::map<std::string, std::pair<uint64_t, CBlock>> hash_pending_blocks; //Find blocks found by the block protocol polling
        std::vector<CBlock> utxo_missing_blocks; //The block found by finding UTXO's protocol polling
        std::set<MissingBlock> missing_blocks; //Wait for the hash polling that triggers the blockfinding protocol
        std::set<std::string> DoubleSpend_blocks;

        const static int max_missing_block_size = 10;
        const static int max_missing_uxto_size = 10;
        const static int sync_save_fail_tolerance = 2;
        std::thread seek_thread_;
        std::mutex seek_mutex_;
        condition_variable seek_condition_;
        std::atomic<bool> seek_thread_start{true};
};

static int GetUtxoFindNode(uint32_t num, uint64_t self_node_height, const std::vector<std::string> &pledge_addr,
                            std::vector<std::string> &send_node_ids);
int SendBlockByUtxoReq(const std::string &utxo);
int SendBlockByUtxoAck(const std::string &utxo, const std::string &addr, const std::string &msg_id);
int HandleBlockByUtxoReq(const std::shared_ptr<GetBlockByUtxoReq> &msg, const MsgData &msgdata);
int HandleBlockByUtxoAck(const std::shared_ptr<GetBlockByUtxoAck> &msg, const MsgData &msgdata);

int SendBlockByHashReq(const std::map<std::string, bool> &missingHashs);
int SendBlockByHashAck(const std::map<std::string, bool> &missingHashs, const std::string &addr, const std::string &msg_id);
int HandleBlockByHashReq(const std::shared_ptr<GetBlockByHashReq> &msg, const MsgData &msgdata);
int HandleBlockByHashAck(const std::shared_ptr<GetBlockByHashAck> &msg, const MsgData &msgdata);

#endif