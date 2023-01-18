#include "ca_evmone.h"

#include <evmc/hex.hpp>
#include <evmone/evmone.h>
#include "utils/json.hpp"
#include "utils/console.h"
#include "utils/base64.h"
#include "utils/AccountManager.h"
#include <proto/transaction.pb.h>
#include <db/db_api.h>
#include "utils/base58.h"
#include "ca_transaction.h"
#include "mpt/trie.h"
#include "ca_global.h"
#include "include/logging.h"
#include "utils/ContractUtils.h"
#include <future>
#include <chrono>

static const double pay_percent = 0.01;

int ExecuteByEvmone(const evmc_message& msg,
                    const evmc::bytes& code,
	                DonHost& host,
                    std::string& strOutput)
{
    // Create a virtual machine
    struct evmc_vm* pvm = evmc_create_evmone();
    if (!pvm)
    {
        return -1;
    }
    if (!evmc_is_abi_compatible(pvm))
    {
        return -2;
    }
    evmc::VM vm{pvm};

    auto async_execute = [&vm](Host& host, evmc_revision rev, const evmc_message& msg, const uint8_t* code, size_t code_size)
    {
        return vm.execute(host, rev, msg, code, code_size);
    };
    std::future<evmc::result> future_result = std::async(std::launch::async, async_execute, std::ref(host), EVMC_LATEST_STABLE_REVISION, std::ref(msg), code.data(), code.size());

    std::future_status status = future_result.wait_for(std::chrono::seconds(10));
    if (status == std::future_status::timeout)
    {
        ERRORLOG(RED "Evmone execution failed timeout!" RESET); 
        return -3;
    }
    evmc::result result = future_result.get();
    // Returns the result of the execution
    int64_t gas_used = msg.gas - result.gas_left;
    DEBUGLOG("Result: {}", result.status_code);
    if (result.status_code != EVMC_SUCCESS)
	{
		ERRORLOG(RED "Evmone execution failed!" RESET);  
        strOutput = std::string_view(reinterpret_cast<const char *>(result.output_data), result.output_size);
	    DEBUGLOG("Output:   {}", strOutput);   	
		return -4;
	}

	strOutput = std::move(evmc::hex({result.output_data, result.output_size}));
    
	DEBUGLOG("Output: {}", strOutput);
    return 0;    
}

int Evmone::DeployContract(const std::string& OwnerEvmAddr,
                   const std::string& strInput,
                   std::string& strOutput,
                   DonHost& host)
{
    // code
    const auto code = evmc::from_hex(strInput);

    // msg
    evmc_address&& evmAddr = evm_utils::stringToEvmAddr(OwnerEvmAddr);
    evmc::address create_address = {{0,1,2}};
    evmc_message create_msg{};
    create_msg.kind = EVMC_CREATE;
    create_msg.recipient = create_address;
    create_msg.sender = evmAddr;
    create_msg.gas = PseudoInfinite;

    struct evmc_tx_context tx_context = {
        .tx_origin = evmAddr
    };
    host.tx_context = tx_context;

    return ExecuteByEvmone(create_msg, code, host, strOutput);
}

int Evmone::CallContract(const std::string& OwnerEvmAddr,
                 const std::string& strDeployer,
                 const std::string& strDeployHash,
                 const std::string& strInput,
                 std::string& strOutput,
                 DonHost& host)
{
    // check whether the addr has deployed the tx hash
    DBReader data_reader;
    std::vector<std::string> vecDeployHashs;
    auto ret = data_reader.GetDeployUtxoByDeployerAddr(strDeployer, vecDeployHashs);
    if(ret != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetDeployUtxoByDeployerAddr failed!");
        return -1;
    }
    auto iter = std::find(vecDeployHashs.cbegin(), vecDeployHashs.cend(), strDeployHash);
    if(iter == vecDeployHashs.cend())
    {
        ERRORLOG("Transaction has not been deployed at this address!");
        return -2;
    }
    std::string ContractAddress = evm_utils::generateEvmAddr(strDeployer + strDeployHash);//GenContractAddress(strDeployer, strDeployHash);
    std::string deployHash;
    if(data_reader.GetContractDeployUtxoByContractAddr(ContractAddress, deployHash) != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetContractDeployUtxoByContractAddr failed!");
        return -3;
    }
    std::string txRaw;
    if(data_reader.GetTransactionByHash(deployHash, txRaw) != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetTransactionByHash failed!");
        return -4;
    }
    CTransaction deployTx;
    if(!deployTx.ParseFromString(txRaw))
    {
        ERRORLOG("Transaction Parse failed!");
        return -5;
    }

    std::string strCode;
    uint64_t amount = 0;
    evmc::bytes code;
    evmc::bytes input;
    try
    {
        nlohmann::json data_json = nlohmann::json::parse(deployTx.data());
        nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
        strCode = tx_info["Output"].get<std::string>();
        amount = tx_info["deploy_amount"].get<uint64_t>();
        if(strCode.empty())
        {
            return -6;
        }
        code = evmc::from_hex(strCode);
        input = evmc::from_hex(strInput);

    }
    catch(const std::exception& e)
    {
        ERRORLOG("can't parse deploy contract transaction");
        return -7;
    }
    // msg
    evmc_address&& evmAddr = evm_utils::stringToEvmAddr(OwnerEvmAddr);;
    evmc_message msg{};
    msg.kind = EVMC_CALL;
    msg.input_data = input.data();
    msg.input_size = input.size();
    msg.recipient = evm_utils::stringToEvmAddr(ContractAddress);
    msg.sender = evmAddr;
    msg.gas = PseudoInfinite;

    struct evmc_tx_context tx_context = {
        .tx_origin = evmAddr
    };
    host.tx_context = tx_context;

    // host
    std::string strPrevTxHash;
	ret = data_reader.GetLatestUtxoByContractAddr(ContractAddress, strPrevTxHash);
    if(ret != DBStatus::DB_SUCCESS)
    {
		ERRORLOG("GetLatestUtxoByContractAddr failed!");
        return -8;        
    }

    CTransaction PrevTx;
    std::string tx_raw;
	ret = data_reader.GetTransactionByHash(strPrevTxHash, tx_raw);

    if(ret != DBStatus::DB_SUCCESS)    
    {
		ERRORLOG("GetTransactionByHash failed!");
        return -9;   
    }

    if(!PrevTx.ParseFromString(tx_raw))
    {
		ERRORLOG("parse failed!");
        return -10;   
    }
    
	std::string rootHash;
    try
    {
        nlohmann::json jPrevData = nlohmann::json::parse(PrevTx.data());
        nlohmann::json jPrevStorage = jPrevData["TxInfo"]["Storage"];
        if(!jPrevStorage.is_null())
        {
            global::ca::TxType tx_type = (global::ca::TxType)PrevTx.txtype();
            if(tx_type == global::ca::TxType::kTxTypeDeployContract)
            {
                rootHash = jPrevStorage[std::string("_") + "rootHash"].get<std::string>();
            }
            else
            {
                rootHash = jPrevStorage[ContractAddress + "_" + "rootHash"].get<std::string>();
            }
        }
        
    }
    catch(...)
    {
		ERRORLOG("Parsing failed!");  
        return -11;
    }

    host.accounts[msg.recipient].CreateTrie(rootHash, ContractAddress);
    host.accounts[msg.recipient].set_code(code);
    host.payment.push_back(std::make_pair(strDeployer, amount * pay_percent));
    int res = ExecuteByEvmone(msg, code, host, strOutput);
    return res == 0 ? 0 : res - 100 ; 
}

void Evmone::getStorage(const DonHost& host, nlohmann::json& jStorage)
{
    for(const auto &account : host.accounts)
    {
        std::pair<std::string, std::string> rootHash;
        std::map<std::string, std::string> dirtyhash;
        std::shared_ptr<trie> root = account.second.StorageRoot;
        root->save();
        root->GetBlockStorage(rootHash, dirtyhash);

        if(rootHash.first.empty())
        {
            continue;
        }
        jStorage[root->mContractAddr + "_" + "rootHash"] = rootHash.first;
        if (!rootHash.second.empty())
        {
            jStorage[root->mContractAddr + "_" + rootHash.first] = rootHash.second;
        }
        
        for(auto it : dirtyhash)
        {
            jStorage[root->mContractAddr + "_" + it.first] = it.second;
        }
    }
}
void test_address_mapping()
{
    Account defaultAccount;
    MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount);
    std::cout<< "strFromAddr:" << defaultAccount.base58Addr <<std::endl;
    std::cout<< "EvmAddress:" << evm_utils::getEvmAddr(defaultAccount.pubStr) << std::endl;
}

Evmone::Evmone() : VmInterface() , type_(VmType::EVM) {}

Evmone::Evmone(std::string code) : VmInterface(), code_(code), type_(VmType::EVM) {}

int Evmone::CreateDeployContractTransaction(const std::string & fromAddr,
                                        uint64_t deploy_amount,
                                        uint64_t height,
                                        CTransaction &outTx,
                                        TxHelper::vrfAgentType &type,
                                        Vrf & info_,
                                        const std::string& OwnerEvmAddr)
{

    nlohmann::json jTxInfo;
    std::vector<std::pair<std::string, uint64_t>> transferrings;
    std::vector<std::pair<std::string, uint64_t>> call_amount;
    int ret = GenContractDeployOutput(OwnerEvmAddr, deploy_amount, jTxInfo, transferrings, call_amount);
    if(ret != 0)
    {
        return ret;
    }

    uint64_t gas = 0;
    uint64_t cost = 0;
    ret = VmInterface::FillOutTx(fromAddr, global::ca::kVirtualDeployContractAddr, jTxInfo, deploy_amount, height, gas, cost, outTx, transferrings, call_amount, type, info_);
    if(ret != 0)
    {
        return ret;
    }

    ret = VmInterface::FillOutTxDataAndHashField( height, gas, cost, global::ca::TxType::kTxTypeDeployContract, outTx);
    if(ret != 0)
    {
        return ret;
    }

	return 0;
}

int Evmone::CreateCallContractTransaction(const std::string & fromAddr,
                                        const std::string & toAddr,
                                        const std::string & txHash,											
                                        const std::string & strInput,
                                        uint64_t call_amount,
                                        uint64_t height,
                                        CTransaction & outTx,
                                        TxHelper::vrfAgentType &type,
                                        Vrf & info_,
                                        const std::string& OwnerEvmAddr)
{
    nlohmann::json jTxInfo;
    std::vector<std::pair<std::string, uint64_t>> transferrings;
    std::vector<std::pair<std::string, uint64_t>> call_amounts;
    int ret = GenContractExecuteOutput(OwnerEvmAddr, fromAddr, toAddr, txHash, strInput, jTxInfo, transferrings, call_amounts);
    if(ret != 0)
    {
        return ret;
    }

    uint64_t gas = 0;
    uint64_t cost = 0;
    ret = VmInterface::FillExecuteOutTx(fromAddr, toAddr, jTxInfo, call_amount, height, gas, cost, outTx, transferrings, call_amounts, type, info_);
    if(ret != 0)
    {
        return ret;
    }

    ret = VmInterface::FillExecuteOutTxDataAndHashField( height, gas, cost, outTx);
    if(ret != 0)
    {
        return ret;
    }

	return 0;
}

int Evmone::GenContractDeployOutput(const std::string& OwnerEvmAddr, uint64_t deploy_amount, nlohmann::json& jTxInfo, std::vector<std::pair<std::string, uint64_t>>& transferrings, std::vector<std::pair<std::string, uint64_t>>& call_amount)
{
    std::string strOutput;
    Account defaultAccount;
    DonHost host;
	int ret = DeployContract(OwnerEvmAddr, code_, strOutput, host);
	if (ret != 0)
	{
		ERRORLOG("Evmone failed to deploy contract!");
		ret -= 300;
		return ret;
	}
    jTxInfo["Version"] = 0;
    jTxInfo["OwnerEvmAddr"] = OwnerEvmAddr;
	jTxInfo["VmType"] = type_;
    jTxInfo["Input"]= code_;
    jTxInfo["Output"] = strOutput;
	jTxInfo["deploy_amount"] = deploy_amount;

    transferrings = host.coin_transferrings;
    call_amount = host.payment;

    ret = ContractInfoAdd(host, jTxInfo, global::ca::TxType::kTxTypeDeployContract);
    if(ret != 0)
    {
        DEBUGLOG("ContractInfoAdd error! ret:{}", ret);
        return -1;
    }
    return 0;
}

int Evmone::GenContractExecuteOutput(const std::string& OwnerEvmAddr, 
                                    const std::string& fromAddr,
                                    const std::string& toAddr,
                                    const std::string& txHash,
                                    const std::string& strInput,
                                    nlohmann::json& jTxInfo,
                                    std::vector<std::pair<std::string, uint64_t>>& transferrings,
                                    std::vector<std::pair<std::string, uint64_t>>& call_amount)
{
	std::string strOutput;
    Account defaultAccount;
    DonHost host;
    
	int ret = Evmone::CallContract(OwnerEvmAddr, toAddr, txHash, strInput, strOutput, host);
	if (ret != 0)
	{
		ERRORLOG("Evmone failed to call contract!");
		ret -= 300;
		return ret;
	}

	DBReader data_reader;
	std::string strPrevTxHash;
    std::string ContractAddress = evm_utils::generateEvmAddr(toAddr + txHash);
    if (data_reader.GetLatestUtxoByContractAddr(ContractAddress, strPrevTxHash) != DBStatus::DB_SUCCESS)
    {
        ERRORLOG("GetLatestUtxo of ContractAddr {} fail", toAddr);
        return -1;
    }
    jTxInfo["Version"] = 0;
    jTxInfo["OwnerEvmAddr"] = OwnerEvmAddr;
    jTxInfo["VmType"] = type_;
	jTxInfo["DeployerAddr"] = toAddr;	
	jTxInfo["DeployHash"] = txHash;
	jTxInfo["Input"] = strInput;
	jTxInfo["Output"] = strOutput;

    transferrings = host.coin_transferrings;
    call_amount = host.payment;
    ret = ContractInfoAdd(host, jTxInfo, global::ca::TxType::kTxTypeCallContract);
    if(ret != 0)
    {
        DEBUGLOG("ContractInfoAdd error! ret:{}", ret);
        return -2;
    }
    return 0;
}

int Evmone::ContractInfoAdd(const DonHost& host, nlohmann::json& jTxInfo, global::ca::TxType TxType)
{
    nlohmann::json jStorage;
    getStorage(host, jStorage);
    jTxInfo["Storage"] = jStorage;

    DBReader data_reader;
    std::map<std::string,std::string> items;
    evmc::address create_address = {{0,1,2}};
    for(auto &account : host.accounts)
    {
        if(TxType == global::ca::TxType::kTxTypeDeployContract && account.first == create_address)
        {
            continue;
        }
        std::string strPrevTxHash;
        std::string callAddress = account.second.StorageRoot->mContractAddr;
        if (data_reader.GetLatestUtxoByContractAddr(callAddress, strPrevTxHash) != DBStatus::DB_SUCCESS)
        {
            ERRORLOG("GetLatestUtxo of ContractAddr {} fail", callAddress);
            return -1;
        }
        items[callAddress] = strPrevTxHash;
    }
    jTxInfo["PrevHash"] = items;

    for(auto &it : host.recorded_logs)
    {
        nlohmann::json logmap;
        logmap["creator"] = evm_utils::EvmAddrToString(it.creator);
        logmap["data"] = evmc::hex({it.data.data(), it.data.size()});
        for(auto& topic : it.topics)
        {
            logmap["topics"].push_back(evmc::hex({topic.bytes, sizeof(topic.bytes)}));
        }
        jTxInfo["log"].push_back(logmap);
    }
    return 0;
}