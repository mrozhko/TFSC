#include "TFSbenchmark.h"
#include "time_util.h"
#include "MagicSingleton.h"
#include "db/db_api.h"
#include "include/logging.h"
#include <sys/time.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include "json.hpp"
#include <sys/sysinfo.h>

static const double conversion_number = 1000000.0;
static const uint64_t conversion_number_u = 1000000;
static const std::string benchmark_filename = "benchmark.json";

TFSBenchmark::TFSBenchmark() : benchmarkSwitch(false), transactionInitiateAmount(0), transactionInitiateHeight(0)
{
    auto memory_check_thread = std::thread(
            [this]()
            {
                while (true)
                {
                    struct sysinfo sys_info;
                    if (!sysinfo(&sys_info))
                    {
                        uint64_t mem_free_total = sys_info.freeram / 1024 / 1024; //unit MB
                        DEBUGLOG("memory left {} MB could be used", mem_free_total);
                    }
                    sleep(60);
                }
            }
    );
    memory_check_thread.detach();
};

void TFSBenchmark::OpenBenchmark()
{
    benchmarkSwitch = true;
    std::ofstream filestream;
    filestream.open(benchmark_filename, std::ios::trunc);
    if (!filestream)
    {
        std::cout << "Open benchmark file failed!can't print benchmark to file" << std::endl;
        return;
    }
    nlohmann::json init_content = nlohmann::json::array();
    filestream << init_content.dump();
    filestream.close();
}

void TFSBenchmark::Clear()
{
    if (!benchmarkSwitch)
    {
        return;
    }
    benchmarkSwitch = false;
    std::cout << "please wait" << std::endl;
    sleep(5);
    transactionInitiateMap.clear();
    transactionInitiateCache.clear();
    transactionVerifyMap.clear();
    agentTransactionReceiveMap.clear();
    transactionSignReceiveMap.clear();
    transactionSignReceiveCache.clear();
    blockContainsTransactionAmountMap.clear();
    blockVerifyMap.clear();
    blockPoolSaveMap.clear();
    transactionInitiateAmount = 0;
    transactionInitiateHeight = 0;
    std::cout << "clear finish" << std::endl;
    benchmarkSwitch = true;

}
void TFSBenchmark::SetTransactionInitiateBatchSize(uint32_t amount)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    batchSize = amount;
}

void TFSBenchmark::AddTransactionInitiateMap(uint64_t start, uint64_t end)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(transactionInitiateMapMutex);
    transactionInitiateMap.push_back({start, end});
    if (transactionInitiateMap.size() == batchSize)
    {
        CaculateTransactionInitiateAmountPerSecond();
    }
    
}

void TFSBenchmark::CaculateTransactionInitiateAmountPerSecond()
{
    if (!benchmarkSwitch)
    {
        return;
    }
    if (transactionInitiateMap.empty())
    {
        return;
    }
    
    uint64_t time_diff_sum = 0;
    for(auto time_record : transactionInitiateMap)
    {
        time_diff_sum = (time_record.second - time_record.first) + time_diff_sum;
    }

    double transactionInitiatesCostPerTransaction = (double)time_diff_sum / (double)transactionInitiateMap.size();
    double transactionInitiatesPerSecond = (double)transactionInitiateMap.size() / ((double)time_diff_sum / conversion_number); 
    transactionInitiateCache[transactionInitiateMap.front().first] = {transactionInitiatesCostPerTransaction, transactionInitiatesPerSecond};
    transactionInitiateMap.clear();
}

void TFSBenchmark::ClearTransactionInitiateMap()
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(transactionInitiateMapMutex);
    transactionInitiateMap.clear();
}

void TFSBenchmark::AddtransactionMemVerifyMap(const std::string& tx_hash, uint64_t cost_time)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(transactionVerifyMapMutex);
    auto found = transactionVerifyMap.find(tx_hash);
    if (found == transactionVerifyMap.end())
    {
        transactionVerifyMap[tx_hash] = verify_time_record();
    }

    auto& record = transactionVerifyMap.at(tx_hash);
    record.mem_verify_time = cost_time;
    record.mem_verify_amount_per_second = (double)1 / ((double)cost_time / conversion_number);
    if (record.db_verify_time != 0)
    {
        record.total_verify_time = record.mem_verify_time + record.db_verify_time;
        record.total_verify_amount_per_second = (double)1 / ((double) record.total_verify_time / conversion_number);
    }
    
}

void TFSBenchmark::AddtransactionDBVerifyMap(const std::string& tx_hash, uint64_t cost_time)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(transactionVerifyMapMutex);
    auto found = transactionVerifyMap.find(tx_hash);
    if (found == transactionVerifyMap.end())
    {
        transactionVerifyMap[tx_hash] = verify_time_record();
    }

    auto& record = transactionVerifyMap.at(tx_hash);
    record.db_verify_time = cost_time;
    record.db_verify_amount_per_second = (double)1 / ((double)cost_time / conversion_number);

    if (record.mem_verify_time != 0)
    {
        record.total_verify_time = record.mem_verify_time + record.db_verify_time;
        record.total_verify_amount_per_second = (double)1 / ((double) record.total_verify_time / conversion_number);
    }
}

void TFSBenchmark::AddAgentTransactionReceiveMap(const std::shared_ptr<TxMsgReq> &msg)
{
    if (!benchmarkSwitch)
    {
        return;
    }
	CTransaction tx_benchmark_tmp;
	if (tx_benchmark_tmp.ParseFromString(msg->txmsginfo().tx()) && tx_benchmark_tmp.verifysign_size() == 0)
	{
        std::lock_guard<std::mutex> lock(agentTransactionReceiveMapMutex);
        auto& tx_hash = tx_benchmark_tmp.hash();
        auto found = agentTransactionReceiveMap.find(tx_hash);
        if (found != agentTransactionReceiveMap.end())
        {
            return;
        }
        agentTransactionReceiveMap[tx_hash] = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	}

}

void TFSBenchmark::AddTransactionSignReceiveMap(const std::string& tx_hash)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(transactionSignReceiveMapMutex);
    auto found = transactionSignReceiveMap.find(tx_hash);
    if (found == transactionSignReceiveMap.end())
    {
        transactionSignReceiveMap[tx_hash] = {};
    }
    auto& time_record = transactionSignReceiveMap.at(tx_hash);
    time_record.push_back(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());
}

void TFSBenchmark::CalculateTransactionSignReceivePerSecond(const std::string& tx_hash, uint64_t compose_time)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(transactionSignReceiveMapMutex);
    auto found = transactionSignReceiveMap.find(tx_hash);
    if (found == transactionSignReceiveMap.end())
    {
        return;
    }
    auto& time_record = transactionSignReceiveMap.at(tx_hash);
    auto span_time = compose_time - time_record.front();
    transactionSignReceiveCache[tx_hash] = {span_time, (double)1 / ((double)span_time / conversion_number)};
}

void TFSBenchmark::AddBlockContainsTransactionAmountMap(const std::string& block_hash, int tx_amount)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(blockContainsTransactionAmountMapMutex);
    blockContainsTransactionAmountMap[block_hash] = tx_amount;
}

void TFSBenchmark::AddBlockVerifyMap(const std::string& block_hash, uint64_t cost_time)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(blockVerifyMapMutex);
    auto found = blockVerifyMap.find(block_hash);
    if (found != blockVerifyMap.end())
    {
        return;
    }
    
    blockVerifyMap[block_hash] = {cost_time, (double)1 / ((double) cost_time / conversion_number) };
}

void TFSBenchmark::IncreaseTransactionInitiateAmount()
{
    if (!benchmarkSwitch)
    {
        return;
    }
    ++transactionInitiateAmount;
    if(transactionInitiateHeight == 0)
    {
        DBReader dBReader;
        uint64_t top = 0;
        if (DBStatus::DB_SUCCESS != dBReader.GetBlockTop(top))
        {
            ERRORLOG("GetBlockTop fail");
        }
        transactionInitiateHeight = top + 1;
    }
}

void TFSBenchmark::PrintTxCount()
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::cout << "there're " << transactionInitiateAmount << 
                " simple transactions hash been initiated since height " << transactionInitiateHeight << std::endl;
}

void TFSBenchmark::AddBlockPoolSaveMapStart(const std::string& block_hash)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(blockPoolSaveMapMutex);
    auto found = blockPoolSaveMap.find(block_hash);
    if (found == blockPoolSaveMap.end())
    {
        blockPoolSaveMap[block_hash] = {MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp(), 0};
    }
}

void TFSBenchmark::AddBlockPoolSaveMapEnd(const std::string& block_hash)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(blockPoolSaveMapMutex);
    auto found = blockPoolSaveMap.find(block_hash);
    if (found == blockPoolSaveMap.end())
    {
        return;
    }
    auto& record = blockPoolSaveMap.at(block_hash);
    if (record.first == 0)
    {
        return;
    }
    record.second = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
}

void TFSBenchmark::PrintBenchmarkSummary(bool export_to_file)
{
    if (!benchmarkSwitch)
    {
        return;
    }
    
    nlohmann::json benchmark_json;
    if (export_to_file)
    {
         std::ifstream readfilestream;
        readfilestream.open(benchmark_filename);
        if (!readfilestream)
        {
            std::cout << "Open benchmark file failed!can't print benchmark to file" << std::endl;
            return;
        }
        std::string content;
        readfilestream >> content;
        try
        {
            benchmark_json = nlohmann::json::parse(content);
        }
        catch(const std::exception& e)
        {
            std::cout << "benchmark json parse fail" << std::endl;
            return;
        }
        readfilestream.close();
    } 

    nlohmann::json benchmark_item_json;
    if (!transactionInitiateCache.empty())
    {
        std::lock_guard<std::mutex> lock(transactionInitiateMapMutex);
        double cost_sum = 0;
        for(auto record : transactionInitiateCache)
        {
            cost_sum += record.second.first;
        }
        double transactionTimeCostAverage = cost_sum / transactionInitiateCache.size();
        double transactionAmountPerSecond = (double) 1 / (transactionTimeCostAverage / conversion_number);
        
        if (export_to_file)
        {
            std::ostringstream stream;
            stream << transactionAmountPerSecond;
            benchmark_item_json["ÿ���ܹ�������ٱ�һ��һ����"] = stream.str();
        }
        else
        {
            std::cout << "transaction launch per second: " << transactionAmountPerSecond << std::endl;
        }
    }
    else
    {
        if (export_to_file)
        {
            benchmark_item_json["ÿ���ܹ�������ٱ�һ��һ����"] = "";
        }
    }

    if (!transactionVerifyMap.empty())
    {
        std::lock_guard<std::mutex> lock(transactionVerifyMapMutex);
        uint64_t mem_cost_sum = 0;
        uint64_t db_cost_sum = 0;
        uint64_t total_cost_sum = 0;
        int skip_count = 0;
        for(auto record : transactionVerifyMap)
        {
            if (record.second.mem_verify_time == 0 
                || record.second.db_verify_time == 0
                || record.second.total_verify_time == 0)
            {
                skip_count++;
                continue;
            }
            
            mem_cost_sum += record.second.mem_verify_time;
            db_cost_sum += record.second.db_verify_time;
            total_cost_sum += record.second.total_verify_time;
        }
        double mem_cost_average = (double)mem_cost_sum / (double)(transactionVerifyMap.size() - skip_count);
        double db_cost_average = (double)db_cost_sum / (double)(transactionVerifyMap.size() - skip_count);
        double total_cost_average = (double)total_cost_sum / (double)(transactionVerifyMap.size() - skip_count);
        double mem_verify_per_second = (double) 1 / (mem_cost_average / conversion_number);
        double db_verify_per_second = (double) 1 / (db_cost_average / conversion_number);
        double total_verify_per_second = (double) 1 / (total_cost_average / conversion_number);
        if (export_to_file)
        {
            std::ostringstream total_stream;
            total_stream << total_verify_per_second;
            std::ostringstream mem_stream;
            mem_stream << mem_verify_per_second;
            std::ostringstream db_stream;
            db_stream << db_verify_per_second;
            benchmark_item_json["Verifiable transactions per second"] = total_stream.str();
            benchmark_item_json["Verifiable transactions per second (memory) (pcs)"] = mem_stream.str();
            benchmark_item_json["Verifiable transactions per second (database) (pcs)"] = db_stream.str();
        }
        else
        {
            std::cout << "transaction verify per second: " << total_verify_per_second 
                  << " (mem verify: " << mem_verify_per_second << " db verify: " << db_verify_per_second << ")" << std::endl;
        }

    }
    else
    {
        if (export_to_file)
        {
            benchmark_item_json["Verifiable transactions per second"] = "";
            benchmark_item_json["Verifiable transactions per second (memory) (pcs)"] = "";
            benchmark_item_json["Verifiable transactions per second (database) (pcs)"] = "";
        }
    }

    if (!agentTransactionReceiveMap.empty())
    {
        std::lock_guard<std::mutex> lock(agentTransactionReceiveMapMutex);
        std::map<uint64_t, uint64_t> hit_cache;
        for(auto record : agentTransactionReceiveMap)
        {
            uint64_t time = record.second / conversion_number_u;
            auto found = hit_cache.find(time);
            if (found == hit_cache.end())
            {
                hit_cache[time] = 1;
            }
            auto& hit_times = found->second;
            hit_times += 1;
        }

        uint64_t max_hit_times = 0;
        for(auto hits : hit_cache)
        {
            if (hits.second > max_hit_times)
            {
                max_hit_times = hits.second;
            }
        }
        if (export_to_file)
        {
            std::ostringstream stream;
            stream << max_hit_times;
            benchmark_item_json["Number of transactions per second"] = stream.str();
        }
        else
        {
            std::cout << "max receive transaction amount per second from internet: " << max_hit_times << std::endl;
        }
    }
    else
    {
        if (export_to_file)
        {
            benchmark_item_json["Number of transactions per second"] = "";
        }
    }

    if(!transactionSignReceiveMap.empty())
    {
        std::lock_guard<std::mutex> lock(transactionSignReceiveMapMutex);

        uint64_t transaction_compose_cost_sum = 0;
        for(auto record : transactionSignReceiveCache)
        {
            transaction_compose_cost_sum += record.second.first;
        }

        double transaction_compose_cost_average = (double)transaction_compose_cost_sum / (double)transactionSignReceiveCache.size();
        double transaction_compose_amout_per_second = (double)1 / (transaction_compose_cost_average / conversion_number);
        if (export_to_file)
        {
            std::ostringstream stream;
            stream << transaction_compose_amout_per_second;
            benchmark_item_json["How many signed transactions per second can be collected from the network and combined into a complete transaction body(s)"] = stream.str();
        }
        else
        {
            std::cout << "sign receiver and compose per second: " << transaction_compose_amout_per_second << std::endl;
        }
    }
    else
    {
        if (export_to_file)
        {
            benchmark_item_json["How many signed transactions per second can be collected from the network and combined into a complete transaction body(s)"] = "";
        }
    }

    if (!blockContainsTransactionAmountMap.empty())
    {
        std::lock_guard<std::mutex> lock(blockContainsTransactionAmountMapMutex);
        uint64_t tx_amount_sum = 0;
        for(auto record : blockContainsTransactionAmountMap)
        {
            tx_amount_sum += record.second;
        }
        double tx_amount_average = (double)tx_amount_sum / (double)blockContainsTransactionAmountMap.size();
        if (export_to_file)
        {
            std::ostringstream stream;
            stream << tx_amount_average;
            benchmark_item_json["How many transactions per second can be packed into a complete block(s)"] = stream.str();
        }
        else
        {
            std::cout << "block contain transaction amount average: " << tx_amount_average << std::endl;
        }
    }
    else
    {
        if (export_to_file)
        {
            benchmark_item_json["How many transactions per second can be packed into a complete block(s)"] = "";
        }
    }

    if (!blockVerifyMap.empty())
    {
        std::lock_guard<std::mutex> lock(blockVerifyMapMutex);
        uint64_t block_verify_cost_sum = 0;
        for(auto record : blockVerifyMap)
        {
            block_verify_cost_sum += record.second.first;
        }
        double block_verify_cost_average = (double)block_verify_cost_sum / (double)blockVerifyMap.size();
        if (export_to_file)
        {
            std::ostringstream stream;
            stream << block_verify_cost_average;
            benchmark_item_json["Block pool block validation time (microseconds)"] = stream.str();
        }
        else
        {
            std::cout << "block verify cost average: " << block_verify_cost_average << std::endl;
        }
    }
    else
    {
        if (export_to_file)
        {
            benchmark_item_json["Block pool block validation time (microseconds)"] = "";
        }
    }
    
    if (!blockPoolSaveMap.empty())
    {
        std::lock_guard<std::mutex> lock(blockPoolSaveMapMutex);
        uint64_t block_save_time_sum = 0;
        int fail_count = 0;
        for(auto record : blockPoolSaveMap)
        {
            if (record.second.second <= record.second.first)
            {
                fail_count++;
                continue;
            }
            
            block_save_time_sum += (record.second.second - record.second.first);
        }
        double block_save_time_average = (double)block_save_time_sum / (double)(blockPoolSaveMap.size() - fail_count);
        if (export_to_file)
        {
            std::ostringstream stream;
            stream << block_save_time_average;
            benchmark_item_json["Block pool chunk storage time to database (microseconds)"] = stream.str();
        }
        else
        {
            std::cout << "block pool stay time average: " << block_save_time_average << std::endl;
        }
    }
    else
    {
        if (export_to_file)
        {
            benchmark_item_json["Block pool chunk storage time to database (microseconds)"] = "";
        }
    }

    if (export_to_file)
    {
        std::ofstream filestream;
        filestream.open(benchmark_filename, std::ios::trunc);
        if (!filestream)
        {
            std::cout << "Open benchmark file failed!can't print benchmark to file" << std::endl;
            return;
        }
        benchmark_json.push_back(benchmark_item_json);
        filestream << benchmark_json.dump();
        filestream.close();
    } 
    return ;

}