#include "ca_txconfirmtimer.h"
#include <iostream>
#include <cassert>
#include "../utils/time_util.h"
#include "utils/MagicSingleton.h"

#include "ca_txconfirmtimer.h"

#include "../include/logging.h"
#include "ca_tranmonitor.h"
#include "ca_blockhelper.h"


const int TxConfirmation::DEFAULT_CONFIRM_TOTAL = 100;
bool TxConfirmation::is_confirm_ok()
{
    static const float SUCCESS_FACTOR = 0.60;
    const int MIN_CONFIRM_COUNT = (int)(total * SUCCESS_FACTOR);
    return ((count + failed_count) >= MIN_CONFIRM_COUNT);
}

bool TxConfirmation::is_success()
{
    static const float SUCCESS_FACTOR = 0.60;
    return get_success_rate() >= SUCCESS_FACTOR;
}

float TxConfirmation::get_success_rate()
{
    int sum_count = count + failed_count;
    if (sum_count <= 0)
    {
        return 0.0;
    }

    float f_success_count = (float)count;
    float f_sum_count = (float)sum_count;
    return (f_success_count / f_sum_count);
}

int TxConfirmation::get_success_count()
{
    return count;
}


TransactionConfirmTimer::TransactionConfirmTimer()
{
    tx_confirmation_.reserve(128);
}

bool TransactionConfirmTimer::is_confirm_ok(const std::string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);
    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            return txconfirm.is_confirm_ok();
        }
    }
    return false;
}

bool TransactionConfirmTimer::is_success(const std::string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);
    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            return txconfirm.is_success();
        }
    }
    return false;
}

float TransactionConfirmTimer::get_success_rate(const std::string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);
    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            return txconfirm.get_success_rate();
        }
    }
    return 0.0;
}

void TransactionConfirmTimer::add(CTransaction& tx, int total/* = TxConfirmation::DEFAULT_CONFIRM_TOTAL*/)
{
    TxConfirmation confirmation;
    confirmation.tx = tx;
    confirmation.startstamp = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    confirmation.count = 0;
    confirmation.total = total;

    std::lock_guard<std::mutex> lck(mutex_);
    tx_confirmation_.push_back(confirmation);
}

void TransactionConfirmTimer::add(const std::string& tx_hash, int total/* = TxConfirmation::DEFAULT_CONFIRM_TOTAL*/)
{
    CTransaction tx;
    tx.set_hash(tx_hash);
    add(tx, total);
}

bool TransactionConfirmTimer::remove(const std::string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto iter = tx_confirmation_.begin(); iter != tx_confirmation_.end(); ++iter)
    {
        if (iter->tx.hash() == tx_hash)
        {
            tx_confirmation_.erase(iter);
            return true;
        }
    }
    return false;
}

int TransactionConfirmTimer::get_count(const std::string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            return txconfirm.count;
        }
    }

    return 0;
}

void TransactionConfirmTimer::update_count(const std::string& tx_hash, CBlock& block)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            ++txconfirm.count;
            txconfirm.block = block;
            break;
        }
    }
}

int TransactionConfirmTimer::get_failed_count(const std::string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            return txconfirm.failed_count;
        }
    }

    return 0;
}

void TransactionConfirmTimer::update_failed_count(const std::string& tx_hash)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            ++txconfirm.failed_count;
            break;
        }
    }
}

void TransactionConfirmTimer::confirm()
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto iter = tx_confirmation_.begin(); iter != tx_confirmation_.end();)
    {
        uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
        static const uint64_t CONFIRM_WAIT_TIME = 1000000 * 6;
        if ((nowTime - iter->startstamp) >= CONFIRM_WAIT_TIME)
        {
            std::cout << "confirm " << std::endl;
            if (iter->is_success())
            {
                MagicSingleton<BlockHelper>::GetInstance()->AddBroadcastBlock(iter->block);
            }
            else
            {
                MagicSingleton<TranMonitor>::GetInstance()->AddFailureList(iter->tx);

            }
            DEBUGLOG("Handle confirm: iter->count:{}, hash:{}", iter->count, iter->tx.hash());

            iter = tx_confirmation_.erase(iter);
        }
        else
        {
            ++iter;
        }
    }
}

void TransactionConfirmTimer::timer_start()
{
    this->timer_.AsyncLoop(1000 * 2, TransactionConfirmTimer::timer_process, this);
}

void TransactionConfirmTimer::timer_process(TransactionConfirmTimer* timer)
{
    assert(timer != nullptr);
    
    timer->confirm();
}

void TransactionConfirmTimer::update_id(const std::string& tx_hash,std::string&id)
{
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            txconfirm.ids.push_back(id);
            break;
        }
    }
}


void TransactionConfirmTimer::get_ids(const std::string& tx_hash,std::vector<std::string>&ids)
 {
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
           ids = txconfirm.ids;
           break;
        }
    }
 }

 bool TransactionConfirmTimer::is_not_exist_id(const std::string& tx_hash, const std::string& id)
 {
    std::lock_guard<std::mutex> lck(mutex_);

    for (auto& txconfirm : tx_confirmation_)
    {
        if (txconfirm.tx.hash() == tx_hash)
        {
            auto iter = std::find(txconfirm.ids.begin(), txconfirm.ids.end(), id);
            return (iter == txconfirm.ids.end());
        }
    }

    return true;
 }