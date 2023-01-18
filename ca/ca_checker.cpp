#include "ca/ca_checker.h"

#include "utils/base58.h"

bool Checker::CheckConflict(const CTransaction &tx, const std::map<uint64_t, std::list<TransactionEntity>> &cache, int height)
{
    CTransaction cur_tx;
    for(const auto& pairHeightTxs : cache)
    {
        if(pairHeightTxs.first > height)
        {
            continue;
        }

        for(const auto& tx_entity : pairHeightTxs.second)
        {
            cur_tx = tx_entity.get_transaction();
            if(CheckConflict(cur_tx, tx) == true)
            {
                return true;
            }
        }
    }

    return false;
}

bool Checker::CheckConflict(const CTransaction &tx, const std::set<CBlock, compator::BlockTimeAscending> &blocks)
{
    for (const auto& block : blocks)
    {
        for(const auto& cur_tx : block.txs())
        {
            if(GetTransactionType(tx) != kTransactionType_Tx)
            {
                continue;
            }

            if(CheckConflict(cur_tx, tx) == true)
            {
                return true;
            }
        }
    }

    return false;
}

bool Checker::CheckConflict(const CBlock &block, const std::set<CBlock, compator::BlockTimeAscending> &blocks)
{
    for (const auto& current_block : blocks)
    {
        if(CheckConflict(current_block, block) == true)
        {
            return true;
        }
    }

    return false;
}

bool Checker::CheckConflict(const CBlock &block1, const CBlock &block2)
{
    for(const auto& tx1 : block1.txs())
    {
        if(GetTransactionType(tx1) != kTransactionType_Tx)
        {
            continue;
        }

        for(const auto& tx2 : block2.txs())
        {
            if(GetTransactionType(tx2) != kTransactionType_Tx)
            {
                continue;
            }

            if(CheckConflict(tx1, tx2) == true)
            {
                return true;
            }
        }
    }

    return false;
}

bool Checker::CheckConflict(const CTransaction &tx1, const CTransaction &tx2)
{
    std::vector<std::string> vec1;
    for(const auto& vin : tx1.utxo().vin())
    {
        for (auto & prevout : vin.prevout())
        {
            vec1.push_back(prevout.hash() + "_" + GetBase58Addr(vin.vinsign().pub()));
        }
    }

    std::vector<std::string> vec2;
    for(const auto& vin : tx2.utxo().vin())
    {
        for (auto & prevout : vin.prevout())
        {
            vec2.push_back(prevout.hash() + "_" + GetBase58Addr(vin.vinsign().pub()));
        }
    }

    std::vector<std::string> vecIntersection;
    std::sort(vec1.begin(), vec1.end());
    std::sort(vec2.begin(), vec2.end());
    std::set_intersection(vec1.begin(), vec1.end(), vec2.begin(), vec2.end(), std::back_inserter(vecIntersection));
    return !vecIntersection.empty();
}