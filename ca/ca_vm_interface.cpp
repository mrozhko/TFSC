#include "ca_vm_interface.h"
#include "utils/time_util.h"
#include "utils/AccountManager.h"
#include "ca_transaction.h"
#include "utils/console.h"
#include "ca_evmone.h"
#include "ca_txhelper.h"

int VmInterface::FillOutTx(const std::string & fromAddr,
					const std::string & toAddr,
					nlohmann::json& jTxInfo,
                    uint64_t amount,
                    uint64_t height,
					uint64_t & gas,
                    uint64_t& cost,
                    CTransaction &outTx,
					const std::vector<std::pair<std::string, uint64_t>>& transferrings,
					const std::vector<std::pair<std::string, uint64_t>>& payment,
					TxHelper::vrfAgentType &type,
                    Vrf & info_)
{
    std::vector<std::string> vecfromAddr;
	vecfromAddr.push_back(fromAddr);
	int ret = TxHelper::Check(vecfromAddr, height);
	if(ret != 0)
	{
		ERRORLOG("Check parameters failed! The error code is {}.", ret);
		ret -= 100;
		return ret;
	}

	if(toAddr.empty())
	{
		return -1;
	}


	std::map<std::string, uint64_t> callPayments;
	std::map<std::string, uint64_t> contractToAddr;
	uint64_t contractOutAmount = 0;//Transaction fee
	for (auto& i : transferrings)
	{
		string addr = i.first;
		if (!CheckBase58Addr(addr))
		{
			ERRORLOG(RED "To address is not base58 address!" RESET);
			return -2;
		}

		for (auto& from : contractToAddr)
		{
			if (addr == fromAddr)
			{
				ERRORLOG(RED "From address and to address is equal!" RESET);
				return -3;
			}
		}
		
		if (i.second <= 0)
		{
			ERRORLOG(RED "Value is zero!" RESET);
			return -4;
		}
		auto found = contractToAddr.find(addr);
		if (found == contractToAddr.end())
		{
			contractToAddr[addr] =  i.second;
		}
		else
		{
			contractToAddr[addr] = found->second + i.second;
		}
		contractOutAmount += i.second;    
	}

	if(fromAddr != toAddr)
	{
		for (auto& payment_item : payment)
		{
			std::string addr = payment_item.first;
			uint64_t call_payment = payment_item.second;
			if (call_payment < 0)
			{
				ERRORLOG(RED "Value is zero!" RESET);
				return -5;
			}

			auto found = callPayments.find(addr);
			if (found == callPayments.end())
			{
				callPayments[addr] =  call_payment;
			}
			else
			{
				callPayments[addr] = found->second + call_payment;
			}
			contractOutAmount += call_payment;
		}
	}



	uint64_t expend =  amount + contractOutAmount;

	// Find utxo
	uint64_t total = 0;
	std::multiset<TxHelper::Utxo, TxHelper::UtxoCompare> setOutUtxos;
	ret = TxHelper::FindUtxo(vecfromAddr, TxHelper::kMaxVinSize, total, setOutUtxos);
	if (ret != 0)
	{
		ERRORLOG(RED "FindUtxo failed! The error code is {}." RESET, ret);
		ret -= 200;
		return ret;
	}
	if (setOutUtxos.empty())
	{
		ERRORLOG(RED "Utxo is empty!" RESET);
		return -6;
	}

	outTx.Clear();

	CTxUtxo * txUtxo = outTx.mutable_utxo();
	
	// Fill Vin
	std::set<string> setTxowners;
	for (auto & utxo : setOutUtxos)
	{
		setTxowners.insert(utxo.addr);
	}
	if (setTxowners.empty())
	{
		ERRORLOG(RED "Tx owner is empty!" RESET);
		return -7;
	}

	for (auto & owner : setTxowners)
	{
		txUtxo->add_owner(owner);
		uint32_t n = 0;
		CTxInput * vin = txUtxo->add_vin();
		for (auto & utxo : setOutUtxos)
		{
			if (owner == utxo.addr)
			{
				CTxPrevOutput * prevOutput = vin->add_prevout();
				prevOutput->set_hash(utxo.hash);
				prevOutput->set_n(utxo.n);
			}
		}
		vin->set_sequence(n++);

		std::string serVinHash = getsha256hash(vin->SerializeAsString());
		std::string signature;
		std::string pub;
		if (TxHelper::Sign(owner, serVinHash, signature, pub) != 0)
		{
			return -8;
		}

		CSign * vinSign = vin->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
	}

	nlohmann::json data;
    data["TxInfo"] = jTxInfo;
	data.dump();
	std::string s = data.dump();
	outTx.set_data(s);
	outTx.set_type(global::ca::kTxSign);

	uint64_t gasNew = 0;
	std::map<std::string, int64_t> targetAddrs ;
	if(toAddr == fromAddr && amount == 0)
	{
		targetAddrs.insert(make_pair(global::ca::kVirtualDeployContractAddr, amount));
	}
	else
	{
		targetAddrs.insert(make_pair(toAddr, amount));
	}
	targetAddrs.insert(make_pair(fromAddr, total - expend));
	for(auto & to : contractToAddr)
	{
		if (to.second == 0)
		{
			continue;
		}
		
		targetAddrs.insert(make_pair(to.first, to.second));
	}
	for(auto & to : callPayments)
	{
		targetAddrs.insert(make_pair(to.first, to.second));
	}
	
	if(GenerateGas(outTx, targetAddrs, gasNew) != 0)
	{
		ERRORLOG(" gas = 0 !");
		return -9;
	}

	gas = gasNew;

	// Calculate total expenditure
	uint64_t gasTotal = (global::ca::kConsensus - 1) * gasNew;

	auto current_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	TxHelper::GetTxStartIdentity(vecfromAddr,height,current_time,type);
	if(type == TxHelper::vrfAgentType_unknow)
	{//At this time, it means that within 30 seconds beyond the height of 50, the current node has not satisfied the staking and the node that has invested can initiate an investment operation
		type = TxHelper::vrfAgentType_defalut;
	}

	if (type == TxHelper::vrfAgentType_local || type == TxHelper::vrfAgentType_vrf)
	{
		cost = gasNew;
	}

	expend += gasTotal +cost;

	//Determine whether UTXO's is costly
	if(total < expend)
	{
		ERRORLOG("The total cost = {} is less than the cost = {}", total, expend);
		return -10;
	}

	CTxOutput * vout = txUtxo->add_vout(); //vout[0]
	if(toAddr == fromAddr && amount == 0)
	{
		vout->set_addr(global::ca::kVirtualDeployContractAddr);
		vout->set_value(amount);
	}
	else
	{
		vout->set_addr(toAddr);
		vout->set_value(amount);
	}

	CTxOutput * voutFromAddr = txUtxo->add_vout();//vout[1]
	voutFromAddr->set_addr(fromAddr);
	voutFromAddr->set_value(total - expend);

	for(auto & to : contractToAddr)
	{
		if (to.second == 0)
		{
			continue;
		}
		
		CTxOutput * vout = txUtxo->add_vout();
		vout->set_addr(to.first);
		vout->set_value(to.second);
	}
	
	for(auto & to : callPayments)
	{
		CTxOutput * vout = txUtxo->add_vout();
		vout->set_addr(to.first);
		vout->set_value(to.second);
	}

	std::string serUtxoHash = getsha256hash(txUtxo->SerializeAsString());
	for (auto & owner : setTxowners)
	{		
		if (TxHelper::AddMutilSign(owner, outTx) != 0)
		{
			return -11;
		}
	}
	outTx.set_time(current_time);

	
	//Determine whether dropshipping is default or local dropshipping
	if(type == TxHelper::vrfAgentType_defalut || type == TxHelper::vrfAgentType_local)
	{
		outTx.set_identity(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
	}
	else{
		
		
		//Select dropshippers
		std::string allUtxos;
		for(auto & utxo:setOutUtxos){
			allUtxos+=utxo.hash;
		}
		allUtxos += std::to_string(current_time);
		
		std::string id;
    	int ret= GetBlockPackager(id,allUtxos,info_);
    	if(ret!=0){
        	return ret;
    	}
		outTx.set_identity(id);
		
	}

    outTx.set_version(0);
    return 0;
}

int VmInterface::FillOutTxDataAndHashField(
                            uint64_t height,
                            const uint64_t &gas,
                            uint64_t cost,
							global::ca::TxType tx_type,
                            CTransaction &outTx)
{

	
	outTx.set_gas(gas);
	outTx.set_cost(cost);
	outTx.set_txtype((uint32_t)tx_type);
	outTx.set_consensus(global::ca::kConsensus);

	std::string txHash = getsha256hash(outTx.SerializeAsString());
	outTx.set_hash(txHash);

	if (MagicSingleton<TranMonitor>::GetInstance()->IsConflict(outTx))
	{
		ERRORLOG("outTx is in pending cache!");
		std::cout << "outTx is in pending cache!" << std::endl;
		return -1;
	}
    return 0;
}

int VmInterface::FillExecuteOutTx(const std::string & fromAddr,
				const std::string & toAddr,
				nlohmann::json& jTxInfo,
					uint64_t amount,
					uint64_t height,
					uint64_t &gas,
					uint64_t& cost,
					CTransaction &outTx,
					const std::vector<std::pair<std::string, uint64_t>>& transferrings,
					const std::vector<std::pair<std::string, uint64_t>>& call_amounts,
					TxHelper::vrfAgentType &type,
                    Vrf & info_)
{
	if (!CheckBase58Addr(toAddr))
	{
		ERRORLOG("Fromaddr is a non base58 address!");
		return -1;
	}
                    
	return FillOutTx(fromAddr, toAddr, jTxInfo, amount, height, gas, cost, outTx, transferrings, call_amounts, type, info_);
}

int VmInterface::FillExecuteOutTxDataAndHashField(
											uint64_t height,
											const uint64_t &gas,
											uint64_t cost,
											CTransaction &outTx)
{
	return FillOutTxDataAndHashField( height, gas, cost, global::ca::TxType::kTxTypeCallContract, outTx);
}