#include "ca_transaction.h"

#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>

#include <iostream>
#include <set>
#include <algorithm>
#include <shared_mutex>
#include <mutex>


#include "interface.pb.h"
#include "proto/ca_protomsg.pb.h"

#include "db/db_api.h"
#include "db/cache.h"
#include "common/config.h"
#include "utils/time_util.h"
#include "utils/base64.h"
#include "utils/string_util.h"
#include "utils/MagicSingleton.h"
#include "utils/util2.h"
#include "utils/hexcode.h"
#include "include/logging.h"
#include "include/net_interface.h"
#include "common/global.h"
#include "ca.h"
#include "ca_global.h"
#include "utils/console.h"
#include "utils/base64_2.h"

#include "ca_txconfirmtimer.h"
#include "ca_block_http_callback.h"
#include "ca/ca_algorithm.h"
#include "ca/ca_blockcache.h"
#include "ca/ca_transaction_cache.h"

#include "ca/ca_txhelper.h"
#include "utils/time_util.h"
#include "ca/ca_CCalBlockGas.h"
#include "utils/ReturnAckCode.h"
#include "include/ScopeGuard.h"
#include "ca/ca_tranmonitor.h"
#include "ca_blockhelper.h"
#include "utils/AccountManager.h"
#include "utils/AccountManager.h"
#include "utils/Cycliclist.hpp"
#include "net/peer_node_cache.h"
#include "utils/VRF.hpp"
#include "utils/TFSbenchmark.h"

int GetBalanceByUtxo(const std::string &address, uint64_t &balance)
{
	if (address.size() == 0)
	{
		return -1;
	}

	DBReader db_reader;
	std::vector<std::string> addr_utxo_hashs;
	db_reader.GetUtxoHashsByAddress(address, addr_utxo_hashs);

	uint64_t total = 0;
	std::string txRaw;
	CTransaction tx;
	for (auto utxo_hash : addr_utxo_hashs)
	{
		if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(utxo_hash, txRaw))
		{
			return -2;
		}
		if (!tx.ParseFromString(txRaw))
		{
			return -3;
		}
		for (auto &vout : tx.utxo().vout())
		{
			if (vout.addr() == address)
			{
				total += vout.value();
			}
		}
	}
	balance = total;
	return 0;
}

void setVrf(Vrf &dest, const std::string &proof, const std::string &pub, const std::string &data)
{
	CSign *sign = dest.mutable_vrfsign();
	sign->set_pub(pub);
	sign->set_sign(proof);
	dest.set_data(data);
}

int getVrfdata(const Vrf &vrf, std::string &hash, int &range , double &percentage)
{
	try
	{
		auto json = nlohmann::json::parse(vrf.data());
		hash = json["hash"];
		range = json["range"];
		percentage = json["percentage"];
	}
	catch (...)
	{
		ERRORLOG("getVrfdata json parse fail !");
		return -1;
	}

	return 0;
}

int getVrfdata(const Vrf &vrf, std::string &hash, int &range)
{
	try
	{
		auto json = nlohmann::json::parse(vrf.data());
		hash = json["hash"];
		range = json["range"];
	}
	catch (...)
	{
		ERRORLOG("getVrfdata json parse fail !");
		return -1;
	}

	return 0;
}

TransactionType GetTransactionType(const CTransaction &tx)
{
	if (tx.type() == global::ca::kGenesisSign)
	{
		return kTransactionType_Genesis;
	}
	if (tx.type() == global::ca::kTxSign)
	{
		return kTransactionType_Tx;
	}
	if (tx.type() == global::ca::kGasSign)
	{
		return kTransactionType_Gas;
	}
	else if (tx.type() == global::ca::kBurnSign)
	{
		return kTransactionType_Burn;
	}

	return kTransactionType_Unknown;
}

bool checkTop(int top)
{
	uint64_t mytop = 0;
	DBReader db_reader;
	db_reader.GetBlockTop(mytop);

	if (top < (int)mytop - 4)
	{
		ERRORLOG("checkTop fail other top:{} my top:{}", top, (int)mytop);
		return false;
	}
	else if (top > (int)mytop + 1)
	{
		ERRORLOG("checkTop fail other top:{} my top:{}", top, (int)mytop);
		return false;
	}
	else
	{
		return true;
	}
}

bool ContainSelfVerifySign(const CTransaction &tx)
{
	bool isContainSelfVerifySign = false;

	if (tx.verifysign_size() == 0)
	{
		return isContainSelfVerifySign;
	}

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	int index = defaultBase58Addr != tx.identity() ? 0 : 1;

	for (; index != tx.verifysign_size(); index++)
	{
		const CSign &sign = tx.verifysign(index);
		if (defaultBase58Addr == GetBase58Addr(sign.pub()))
		{
			isContainSelfVerifySign = true;
			break;
		}
	}
	return isContainSelfVerifySign;
}

int CreateSignTransaction(const CTransaction &tx, CTransaction &retTx)
{
	if (tx.hash().empty())
	{
		return -1;
	}

	if (tx.verifysign().empty())
	{
		return -2;
	}

	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		return -3;
	}

	if (tx.identity() != defaultAccount.base58Addr)
	{
		return -4;
	}

	CTxUtxo *utxo = retTx.mutable_utxo();
	utxo->add_owner(tx.utxo().owner(0));

	// Fill Vin
	CTxInput *txin = utxo->add_vin();
	txin->set_sequence(0x00);
	CTxPrevOutput *prevout = txin->add_prevout();
	prevout->set_n(0x00);
	prevout->set_hash(tx.hash());

	std::string signature;
	if (defaultAccount.Sign(getsha256hash(txin->SerializeAsString()), signature) == false)
	{
		return -5;
	}
	CSign *vinSign = txin->mutable_vinsign();
	vinSign->set_sign(signature);
	vinSign->set_pub(defaultAccount.pubStr);

	retTx.set_type(global::ca::kGasSign);

	// Fill Vout
	int gas = tx.gas();
	int cost = tx.cost();

    bool isAgent = TxHelper::IsNeedAgent(tx);


	for (int i = 0; i < tx.verifysign_size(); i++)
	{
		// Person to transfer
		CSign sign = tx.verifysign(i);
		std::string account = GetBase58Addr(sign.pub());

		// Amount to transfer
		uint64_t amount = (i == 0 ? cost : gas / 2);
		if (i == 0 && !isAgent)
		{
			amount = 0;
		}

		CTxOutput *txout = utxo->add_vout();
		txout->set_addr(account);
		txout->set_value(amount);
	}

	{
		std::string signature;
		if (defaultAccount.Sign(getsha256hash(utxo->SerializeAsString()), signature) == false)
		{
			return -6;
		}
		CSign *multiSign = utxo->add_multisign();
		multiSign->set_sign(signature);
		multiSign->set_pub(defaultAccount.pubStr);
	}

	// Fill data
	retTx.set_data("");

	// Fill identity
	retTx.set_identity(defaultAccount.base58Addr);

	// Fill time
	retTx.set_time(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());

	{
		std::string signature;
		if (defaultAccount.Sign(getsha256hash(retTx.SerializeAsString()), signature) == false)
		{
			return -7;
		}
		CSign *verifySign = retTx.add_verifysign();
		verifySign->set_sign(signature);
		verifySign->set_pub(defaultAccount.pubStr);
	}

	// Fill hash
	retTx.set_hash(ca_algorithm::CalcTransactionHash(retTx));

	return 0;
}

int CreateBurnTransaction(const CTransaction &tx, CTransaction &retTx)
{
	if (tx.hash().empty())
	{
		return -1;
	}

	if (tx.verifysign().empty())
	{
		return -2;
	}

	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		return -3;
	}

	if (tx.identity() != defaultAccount.base58Addr)
	{
		return -4;
	}

	CTxUtxo *utxo = retTx.mutable_utxo();
	utxo->add_owner(tx.utxo().owner(0));

	// Fill Vin
	CTxInput *txin = utxo->add_vin();
	txin->set_sequence(0x00);
	CTxPrevOutput *prevout = txin->add_prevout();
	prevout->set_n(0x00);
	prevout->set_hash(tx.hash());

	std::string signature;
	if (defaultAccount.Sign(getsha256hash(txin->SerializeAsString()), signature) == false)
	{
		return -5;
	}
	CSign *vinSign = txin->mutable_vinsign();
	vinSign->set_sign(signature);
	vinSign->set_pub(defaultAccount.pubStr);

	retTx.set_type(global::ca::kBurnSign);

	// Fill Vout
	int gas = tx.gas();
	int cost = tx.cost();



	uint64_t burn_amount = 0;
	for (int i = 0; i < tx.verifysign_size(); i++)
	{
		// Amount to transfer
		uint64_t amount = gas / 2;
		if (i == 0)
		{
			amount = 0;
		}
		burn_amount += amount;
	}

	for (int i = 0; i < 2; i++) // i < tx.owner().size()
	{
		CTxOutput *txout = utxo->add_vout();
		if (i == 0)
		{
			txout->set_addr(global::ca::kVirtualBurnGasAddr);
			txout->set_value(burn_amount);
		}
		else
		{
			txout->set_addr(tx.utxo().owner(0));
			txout->set_value(0);
		}
	}

	{
		std::string signature;
		if (defaultAccount.Sign(getsha256hash(utxo->SerializeAsString()), signature) == false)
		{
			return -6;
		}
		CSign *multiSign = utxo->add_multisign();
		multiSign->set_sign(signature);
		multiSign->set_pub(defaultAccount.pubStr);
	}

	// Fill data
	retTx.set_data("");

	// Fill identity
	retTx.set_identity(defaultAccount.base58Addr);

	// Fill time
	retTx.set_time(MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp());

	{
		std::string signature;
		if (defaultAccount.Sign(getsha256hash(retTx.SerializeAsString()), signature) == false)
		{
			return -7;
		}
		CSign *verifySign = retTx.add_verifysign();
		verifySign->set_sign(signature);
		verifySign->set_pub(defaultAccount.pubStr);
	}

	// Fill hash
	retTx.set_hash(ca_algorithm::CalcTransactionHash(retTx));

	return 0;
}

int HandleBuildBlockBroadcastMsg(const std::shared_ptr<BuildBlockBroadcastMsg> &msg, const MsgData &msgdata)
{


	DEBUGLOG("HandleBuildBlockBroadcastMsg begin");
	//  Determine if the version is compatible
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg IsVersionCompatible");
		return -1;
	}

	std::string serBlock = msg->blockraw();
	CBlock block;
	if (!block.ParseFromString(serBlock))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg block ParseFromString failed");
		return -2;
	}

	DBReader reader;
	uint64_t newTop = 0;
	static const uint64_t block_pool_cache_height = 10000;
	if (reader.GetBlockTop(newTop) == DBStatus::DB_SUCCESS)
	{
		if (block.height() >= newTop && block.height() - newTop > block_pool_cache_height)
		{
			return -3;
		}
	}

	{
		DBReader db_reader;
		uint64_t node_height = 0;
		if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(node_height))
		{
			ERRORLOG("GetBlockTop error!");
			return -4;
		}
		if(block.height() > node_height + 100)
		{
			return -5;
		}
	}

	Vrf vrf = msg->vrfinfo();

	int range_ = 0;

	std::string hash;
	if(getVrfdata(vrf, hash, range_) != 0)
	{
		return -6;
	}

	EVP_PKEY *pkey = nullptr;
	if (!GetEDPubKeyByBytes(vrf.vrfsign().pub(), pkey))
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Get public key from bytes failed!" RESET);
		return -7;
	}

	std::string result = hash;
	std::string proof = vrf.vrfsign().sign();
	if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, block.hash(), result, proof) != 0)
	{
		ERRORLOG(RED "HandleBuildBlockBroadcastMsg Verify VRF Info fail" RESET);
		return -8;
	}

	double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(result);

	// Circular linked list
	Cycliclist<std::string> list;
	for (auto &iter : block.txs())
	{
		for (auto &sign_node : iter.verifysign())
		{
			list.push_back(GetBase58Addr(sign_node.pub()));
		}
	} // The signing nodes for all transactions in the block are added to the loop list

	std::vector<std::string> verify_sign;
	for (auto &signNodeMsg : block.sign())
	{
		verify_sign.push_back(GetBase58Addr(signNodeMsg.pub()));
	} // The signature node for block flow

	int rand_pos = list.size() * rand_num;
	const int sign_threshold = global::ca::KSign_node_threshold / 2;

	auto end_pos = rand_pos - sign_threshold;
	std::vector<std::string> target_addr;
	for (; target_addr.size() < global::ca::KSign_node_threshold; end_pos++)
	{
		target_addr.push_back(list[end_pos]);
	}

	std::vector<std::string> sign_addr;
	for (auto iter = list.begin(); iter != list.end(); iter++)
	{
		sign_addr.push_back(iter->data);
	}
	sign_addr.push_back(list.end()->data);

	// Determine whether the random signature node of VRF is consistent with the circulation signature node
	for (auto &item : target_addr)
	{
		if (std::find(sign_addr.begin(), sign_addr.end(), item) == sign_addr.end())
		{
			DEBUGLOG("HandleBuildBlockBroadcastMsg sign addr error !");
			return -9;
		}
	}

	MagicSingleton<BlockMonitor>::GetInstance()->AddBlockMonitor(block.hash(), msg->id(), msg->flag());
	MagicSingleton<BlockHelper>::GetInstance()->AddBroadcastBlock(block);

	std::cout << "block Add succeed" << std::endl;
	return 0;
}
// Create: receive pending transaction from network and add to cache
int HandleTxPendingBroadcastMsg(const std::shared_ptr<TxPendingBroadcastMsg> &msg, const MsgData &msgdata)
{
	//  Determine if the version is compatible
	if (Util::IsVersionCompatible(msg->version()) != 0)
	{
		ERRORLOG("HandleTxPendingBroadcastMsg IsVersionCompatible");
		return -1;
	}

	std::string transactionRaw = msg->txraw();
	CTransaction tx;
	tx.ParseFromString(transactionRaw);

	CTransaction copyTx = tx;
	copyTx.clear_hash();
	copyTx.clear_verifysign();
	tx.set_hash(getsha256hash(copyTx.SerializeAsString()));

	// int result = MagicSingleton<TxVinCache>::GetInstance()->Add(tx, msg->prevblkheight(), false);
	int result = MagicSingleton<TranMonitor>::GetInstance()->Add(tx, msg->prevblkheight());

	DEBUGLOG("Receive pending transaction broadcast message result:{} ", result);
	return 0;
}

int SendTxMsg(const CTransaction &tx, const std::shared_ptr<TxMsgReq> &msg)
{
	std::set<std::string> sendid;
	const int signNodeNumber = global::ca::KSign_node_threshold;
	int ret = FindSignNode(tx, msg, signNodeNumber, sendid);
	if (ret < 0)
	{
		ret -= 1038;
		ERRORLOG("SendTxMsg failed, ret:{} sendid size: {}", ret, sendid.size());
		return ret;
	}
	if (sendid.empty())
	{
		ERRORLOG("SendTxMsg failed, sendid size is empty");
		return -1;
	}

	uint64_t handleTxHeight = msg->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);

	for (auto id : sendid)
	{
		DEBUGLOG("sendid id = {} tx time = {} , type = {}", id, tx.time(), type);
		if (type == TxHelper::vrfAgentType_vrf)
		{
			if (msg->vrfinfo().vrfsign().pub().empty())
			{
				ERRORLOG("----------------------------dohandle vrf pub is empty!!!");
			}
		}
		net_send_message<TxMsgReq>(id.c_str(), *msg, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
	}

	return 0;
}

int CheckTxMsg(const std::shared_ptr<TxMsgReq> &msg)
{
	//  Take the trading body
	CTransaction tx;
	if (!tx.ParseFromString(msg->txmsginfo().tx()))
	{
		return -1;
	}

	//  Take the signer in the circulation transaction body
	std::set<std::string> vMsgSigners;
	for (const auto &signer : msg->signnodemsg())
	{
		if (signer.pub().size() != 0)
		{
			vMsgSigners.insert(GetBase58Addr(signer.pub()));
		}
	}

	//  Take the signer in the transaction body
	std::set<std::string> vTxSigners;
	for (const auto &verifySign : tx.verifysign())
	{
		if (verifySign.pub().size() != 0)
		{
			vTxSigners.insert(GetBase58Addr(verifySign.pub()));
		}
	}

	//  Compare the differences
	if (vMsgSigners != vTxSigners)
	{
		return -2;
	}

	bool bIsStakeTx = false;
	bool bIsInvestTx = false;
	try
	{
		//  Take the transaction type
		global::ca::TxType txType = (global::ca::TxType)tx.txtype();

		if (txType == global::ca::TxType::kTxTypeStake)
		{
			bIsStakeTx = true;
		}
		if (txType == global::ca::TxType::kTxTypeInvest)
		{
			bIsInvestTx = true;
		}
	}
	catch (...)
	{
		return -3;
	}

	//  Take the entire network staking account
	DBReader db_reader;
	std::vector<string> pledgeAddrs;
	auto status = db_reader.GetStakeAddress(pledgeAddrs);
	if (DBStatus::DB_SUCCESS != status && DBStatus::DB_NOT_FOUND != status)
	{
		return -4;
	}

	//  Determine whether it is an initial account transaction
	//  Take the transaction initiator
	std::vector<std::string> vTxOwners = TxHelper::GetTxOwner(tx);
	bool bIsInitAccount = false;
	if (vTxOwners.end() != std::find(vTxOwners.begin(), vTxOwners.end(), global::ca::kInitAccountBase58Addr))
	{
		bIsInitAccount = true;
	}

	//  Staking and initial accounts up to 50 do not need to be verified
	if ((bIsStakeTx || bIsInvestTx || bIsInitAccount) && msg->txmsginfo().height() < global::ca::kMinUnstakeHeight)
	{
		return 0;
	}

	bool flag = TxHelper::IsNeedAgent(tx);

	for (int i = (flag ? 0 : 1); i < tx.verifysign_size(); ++i)
	{
		std::string sign_addr = GetBase58Addr(tx.verifysign(i).pub());
		auto ret = VerifyBonusAddr(sign_addr);
		if (ret < 0)
		{
			return ret;
		}

		int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(sign_addr, global::ca::StakeType::kStakeType_Node);
		if (stake_time <= 0)
		{
			return -5;
		}
	}

	for (auto &signNodeMsg : msg->signnodemsg())
	{
		std::string pub = signNodeMsg.pub();
		std::string sign = signNodeMsg.sign();

		TxMsgInfo cpTxMsgInfo = msg->txmsginfo();
		CTransaction cpTx;
		cpTx.ParseFromString(cpTxMsgInfo.tx());

		cpTx.clear_hash();
		cpTx.clear_verifysign();
		cpTx.set_hash(getsha256hash(cpTx.SerializeAsString()));
		cpTxMsgInfo.set_tx(cpTx.SerializeAsString());

		std::string serTxMsgInfo = getsha256hash(cpTxMsgInfo.SerializeAsString());
		if (pub.size() == 0 ||
			sign.size() == 0 ||
			serTxMsgInfo.size() == 0)
		{
			return -6;
		}

		EVP_PKEY *eckey = nullptr;
		if (GetEDPubKeyByBytes(pub, eckey) == false)
		{
			EVP_PKEY_free(eckey);
			ERRORLOG(RED "Get public key from bytes failed!" RESET);
			return -7;
		}

		if (ED25519VerifyMessage(serTxMsgInfo, eckey, sign) == false)
		{
			EVP_PKEY_free(eckey);
			ERRORLOG(RED "Public key verify sign failed!" RESET);
			return -8;
		}
		EVP_PKEY_free(eckey);
	}

	return 0;
}

int AddSignNodeMsg(const std::shared_ptr<TxMsgReq> &msg, CTransaction &tx)
{
	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		ERRORLOG("get default account fail");
		return -1;
	}

	CTransaction cpTx = tx;
	cpTx.clear_hash();
	cpTx.clear_verifysign();
	cpTx.set_hash(getsha256hash(cpTx.SerializeAsString()));

	TxMsgInfo *txMsgInfo = msg->mutable_txmsginfo();
	TxMsgInfo cpTxMsgInfo = *txMsgInfo;

	cpTxMsgInfo.set_tx(cpTx.SerializeAsString());

	std::string serTxMsgInfo = getsha256hash(cpTxMsgInfo.SerializeAsString());
	std::string signature;
	if (defaultAccount.Sign(serTxMsgInfo, signature) == false)
	{
		ERRORLOG("sign info fail");
		return -2;
	}

	SignNodeMsg *signNodeMsg = msg->add_signnodemsg();
	signNodeMsg->set_id(defaultAccount.base58Addr);
	signNodeMsg->set_sign(signature);
	signNodeMsg->set_pub(defaultAccount.pubStr);

	DBReader db_reader;
	std::vector<std::string> pre_block_hashs;
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(msg->txmsginfo().height(), pre_block_hashs))
	{
		return -3;
	}

	std::string ownBaseaddr = defaultAccount.base58Addr;
	for (int i = 0; i < pre_block_hashs.size(); ++i)
	{
		if (ownBaseaddr != msg->signnodemsg(0).id())
		{
			msg->add_prevblkhashs(pre_block_hashs[i]);
		}
	}

	tx.clear_hash();
	tx.set_hash(getsha256hash(tx.SerializeAsString()));

	txMsgInfo->set_tx(tx.SerializeAsString());
	return 0;
}

int HandleDoHandleTxAck(const std::shared_ptr<TxMsgAck> &msg, const MsgData &msgdata)
{
	//  Determine if the version is compatible
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg IsVersionCompatible");
		return -1;
	}

	MagicSingleton<TranMonitor>::GetInstance()->ReviceDoHandleAck(*msg);

	return 0;
}

std::map<int32_t, std::string> TxMsgReqCode()
{
	std::map<int32_t, std::string> errInfo = {};

	return errInfo;
}
int HandleTx(const std::shared_ptr<TxMsgReq> &msg, const MsgData &msgdata)
{
	MagicSingleton<TFSBenchmark>::GetInstance()->AddAgentTransactionReceiveMap(msg);

	auto errInfo = TxMsgReqCode();
	TxMsgAck ack;

	int ret = 0;
	ON_SCOPE_EXIT
	{
		ReturnAckCode<TxMsgAck>(msgdata, errInfo, ack, ret);
	};

	CTransaction tx;

	ret = DoHandleTx(msg, tx);
	if (ret != 0)
	{
		ERRORLOG("trasaction {} turnover fail {}", tx.hash(), ret);
	}
	

	ack.set_tx(tx.SerializeAsString());

	if (tx.identity() == MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr())
	{
		MagicSingleton<TranMonitor>::GetInstance()->SetSelfAckDoHandle(tx, ret);
	}

	return ret;
}

int DoHandleTx(const std::shared_ptr<TxMsgReq> &msg, CTransaction &outTx)
{
	// Judge whether the version is compatible
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("Incompatible version!");
		return -1;
	}

	// Judge whether the height is reasonable
	uint64_t txheight = msg->txmsginfo().height();
	if (!checkTop(txheight))
	{
		ERRORLOG("Unreasonable height!");
		return -2;
	}

	CTransaction tx;
	if (!tx.ParseFromString(msg->txmsginfo().tx()))
	{
		ERRORLOG("Failed to deserialize transaction body!");
		return -3;
	}

	ON_SCOPE_EXIT
	{
		outTx = tx;
	};

    DBReader db_reader;
    uint64_t top = 0;
    if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
    {
        ERRORLOG("db get top failed!!");
        return -4;
    }

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	if (msg->txmsginfo().type() != 0)
	{
		ERRORLOG("type Error!");
		return -5;
	}

	int verifyCount = tx.verifysign_size();
	std::vector<std::string> owners(tx.utxo().owner().begin(), tx.utxo().owner().end());
	if (verifyCount == 2 && defaultBase58Addr == tx.identity())
	{
		//Determine what type of transaction initiator is local or local or VRF
		TxHelper::vrfAgentType type;
		TxHelper::GetTxStartIdentity(owners, txheight + 1, tx.time(), type);
		if (type == TxHelper::vrfAgentType::vrfAgentType_vrf)
		{
			std::pair<std::string, std::vector<std::string>> nodes_pair;
			MagicSingleton<VRF>::GetInstance()->getVerifyNodes(tx.hash(), nodes_pair);

			std::vector<std::string> nodes = nodes_pair.second;
			auto id_ = msg->signnodemsg(1).id();
			auto iter = std::find(nodes.begin(), nodes.end(), id_);
			if (iter == nodes.end())
			{
				ERRORLOG("vrf sign node = {} info fail", id_);
				return -6;
			}
		}

		if (MagicSingleton<TranStroage>::GetInstance()->Update(*msg) != 0)
		{
			ERRORLOG("Update fail");
			return -7;
		}
	}
	else
	{

		int ret = VerifyTxMsgReq(*msg);
		if (ret != 0)
		{
			ERRORLOG("Verify fail");
			return ret -1238;
		}

		if (TxHelper::AddVerifySign(defaultBase58Addr, tx) != 0)
		{
			ERRORLOG("Add verify sign fail");
			return -8;
		}

		if (AddSignNodeMsg(msg, tx) != 0)
		{
			ERRORLOG("Add node sign fail");
			return -9;
		}

		if (verifyCount == 0)
		{
			TxHelper::vrfAgentType type;
			TxHelper::GetTxStartIdentity(owners, txheight + 1, tx.time(), type);
			if (type == TxHelper::vrfAgentType::vrfAgentType_vrf)
			{
				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				tx.set_hash(getsha256hash(copyTx.SerializeAsString()));

				if (IsVrfVerifyNode(defaultBase58Addr, msg) != 0)
				{
					ERRORLOG("I am not a transaction issuing node = {} , tx hash = {}", defaultBase58Addr, tx.hash());
					return -10;
				}
			}
			ret = (MagicSingleton<TranStroage>::GetInstance()->Add(*msg));
			if (ret != 0)
			{
				ERRORLOG("add to TranStroage fail");
				return -2207;
			}
			// send to other node
			ret = SendTxMsg(tx, msg);
			if (0 != ret)
			{
				ERRORLOG("Send TxMsgReq failed");
				return ret -3410;
			}

			if (GetBase58Addr(tx.verifysign(0).pub()) == defaultBase58Addr)
			{
				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				tx.set_hash(getsha256hash(copyTx.SerializeAsString()));

				int result = MagicSingleton<TranMonitor>::GetInstance()->Add(tx, msg->txmsginfo().height());
				TRACELOG("Transaction add to Cache ({}) ({})", result, TranMonitor::t_VinSt::TxToString(tx));
			}
		}
		else if (verifyCount == 1)
		{
			uint64_t handleTxHeight = msg->txmsginfo().height();

			//Check whether it is the signature node specified by the VRF

			auto CheckVrfVerify = [](const std::shared_ptr<TxMsgReq> &msg) -> int
			{
				//###
				//TODO
				return -1;
			};

			TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
			if (type == TxHelper::vrfAgentType::vrfAgentType_vrf)
			{
				//  Check whether the dropshipping node is a VP-specified node
				ret = IsVrfVerifyNode(tx.identity(), msg);
				if (ret != 0)
				{
					ERRORLOG("The issuing node = {} is not the specified node, ret: {}", tx.identity(), ret);
					return ret -4021;
				}
				int _ret = CheckVrfVerify(msg);
				if (_ret != 0)
				{
					ERRORLOG("The signature node is not selected by vrf : {}", _ret);
					return _ret -1908;
				}
			}

			TxMsgInfo *txmsginfo_ = msg->mutable_txmsginfo();
			CTransaction copyTx = tx;
			copyTx.clear_hash();
			copyTx.clear_verifysign();
			tx.set_hash(getsha256hash(copyTx.SerializeAsString()));

			txmsginfo_->set_tx(tx.SerializeAsString());
			// send to origin node
			if (defaultBase58Addr != tx.identity() && tx.verifysign_size() == 2)
			{
				net_send_message<TxMsgReq>(tx.identity(), *msg, net_com::Priority::kPriority_High_1);
				DEBUGLOG("TX Send to ip[{}] to Create Block ...", tx.identity().c_str());
			}
		}
		else
		{
			// error
			ERRORLOG("unknow type!");
			return -1499;
		}
	}

	return 0;
}

int IsVrfVerifyNode(const std::string identity, const std::shared_ptr<TxMsgReq> &msg)
{

 //###
 //TODO

	return -1;
}

int SearchNodeToSendMsg(BlockMsg &msg)
{
	//###
	//TODO
	return -1;
}

int SearchStake(const std::string &address, uint64_t &stakeamount, global::ca::StakeType stakeType)
{
	DBReader db_reader;
	std::vector<string> utxos;
	auto status = db_reader.GetStakeAddressUtxo(address, utxos);
	if (DBStatus::DB_SUCCESS != status)
	{
		ERRORLOG("GetStakeAddressUtxo fail db_status:{}", status);
		return -1;
	}
	uint64_t total = 0;
	for (auto &item : utxos)
	{
		std::string strTxRaw;
		if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(item, strTxRaw))
		{
			continue;
		}
		CTransaction utxoTx;
		utxoTx.ParseFromString(strTxRaw);

		nlohmann::json data = nlohmann::json::parse(utxoTx.data());
		nlohmann::json txInfo = data["TxInfo"].get<nlohmann::json>();
		std::string txStakeTypeNet = txInfo["StakeType"].get<std::string>();

		if (stakeType == global::ca::StakeType::kStakeType_Node && txStakeTypeNet != global::ca::kStakeTypeNet)
		{
			continue;
		}

		for (int i = 0; i < utxoTx.utxo().vout_size(); i++)
		{
			CTxOutput txout = utxoTx.utxo().vout(i);
			if (txout.addr() == global::ca::kVirtualStakeAddr)
			{
				total += txout.value();
			}
		}
	}
	stakeamount = total;
	return 0;
}

// Random select node from list, 20211207  Liu
static void RandomSelectNode(const vector<Node> &nodes, size_t selectNumber, std::set<std::string> &outNodes)
{
	if (nodes.empty())
		return;

	vector<Node> tmp_nodes = nodes;

	std::random_device device;
	std::mt19937 engine(device());
	std::uniform_int_distribution<size_t> dist(0, tmp_nodes.size() - 1);

	const size_t randomCount = std::min(tmp_nodes.size(), selectNumber);
	std::unordered_set<size_t> randomIndexs;
	while (randomIndexs.size() < randomCount)
	{
		size_t random = dist(engine);
		randomIndexs.insert(random);
	}

	for (const auto &i : randomIndexs)
	{
		outNodes.insert(tmp_nodes[i].base58address);
	}
}

static void SignNodeFilter(Cycliclist<Node>::iterator &start, Cycliclist<Node>::iterator &end, const std::vector<Node> &filter_addrs, const int &sign_node_threshold, std::set<std::string> &target_nodes, uint64_t &top)
{
	for (; start != end; start++)
	{
		auto node = start->data;
		auto find_result = std::find_if(filter_addrs.begin(), filter_addrs.end(), [node](const Node &findNode)
										{ return node.base58address == findNode.base58address; });

		if (find_result != filter_addrs.end())
		{
			if (sign_node_threshold > target_nodes.size() && node.height >= top)
			{
				target_nodes.insert(node.base58address);
				DEBUGLOG("node {} meets the requirements of sign node", node.base58address);
			}
		}
		else
		{
			DEBUGLOG("node {} doesn't meet the requirements of sign node", node.base58address);
		}
	}
}

static void RandomSelectNode(const std::vector<Node> &nodes, const double &rand_num, const int &sign_node_threshold, const bool &flag, std::set<std::string> &out_nodes, int &range , uint64_t & top)
{

	
	// Select the range of nodes from the node cache
	int target_pos = nodes.size() * rand_num;

	Cycliclist<Node> list;

	for (auto &node : nodes)
	{
		list.push_back(node);
	}

	auto begin = list.begin();
	auto target = begin + target_pos;
	auto start_pos = target - range;
	auto end_pos = target + range;

	DEBUGLOG("range ->>>>> {}", range);
	int iter_count = range * 2;
	if (nodes.size() < iter_count)
	{
		DEBUGLOG("peer node cache size = {} less than target num = {}", nodes.size(), iter_count);
		return;
	}

	std::string ownerID = net_get_self_node_id();
	//Find the nodes in the scope of the circular linked list that match the node height and filter their own nodes to add to the collection
	for (; start_pos != end_pos; start_pos++)
	{
		DEBUGLOG("start_pos base58 = {}", start_pos->data.base58address);
		if(start_pos->data.height >= top)
		{
			if(out_nodes.size() > sign_node_threshold)
			{
				return;
			}

			if(start_pos->data.base58address == ownerID)
			{
				continue;
			}
			out_nodes.insert(start_pos->data.base58address);
			DEBUGLOG("out_nodes -> {}", start_pos->data.base58address);
		}
	}

	return;
}

static void filterNodeList(const CTransaction & tx, std::vector<Node> &outAddrs)
{
	std::vector<Node> nodelist = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	
	//Recipient address
	std::vector<std::string> txAddrs;
	global::ca::TxType txType = (global::ca::TxType)tx.txtype();
	if(txType == global::ca::TxType::kTxTypeBonus)
	{
		CTxOutput txout = tx.utxo().vout(tx.utxo().vout_size() - 1);
		txAddrs.push_back(txout.addr());
	}
	else
	{
		for (int i = 0; i < tx.utxo().vout_size(); ++i)
		{
			CTxOutput txout = tx.utxo().vout(i);
			txAddrs.push_back(txout.addr());
		}
	}	

	std::vector<std::string> txOwners(tx.utxo().owner().begin(), tx.utxo().owner().end());


	for (auto iter = nodelist.begin(); iter != nodelist.end(); ++iter)
	{
		//Delete the initiator node
		if (txOwners.end() != find(txOwners.begin(), txOwners.end(), iter->base58address))
		{
			DEBUGLOG("filterNodeList filter: from addr {}", iter->base58address);
			continue;
		}

		// Delete the receiver node
		if (txAddrs.end() != find(txAddrs.begin(), txAddrs.end(), iter->base58address))
		{
			DEBUGLOG("filterNodeList filter: to addr {}", iter->base58address);
			continue;
		}

		//Delete the identity of the transaction
		if (tx.identity() == iter->base58address)
		{
			DEBUGLOG("filterNodeList filter: identity addr {}", iter->base58address);
			continue;
		}

		outAddrs.push_back(*iter);

	}

	outAddrs.push_back(MagicSingleton<PeerNode>::GetInstance()->get_self_node());
}


int FindSignNode(const CTransaction & tx, const std::shared_ptr<TxMsgReq> &msg,  const int nodeNumber, std::set<std::string> & nextNodes)
{
	//###
	
	//TODO
	return -1;
}




int GetBlockPackager(std::string &packager, const std::string &hash_utxo, Vrf &info)
{
	DBReader db_reader;
	uint64_t top;
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
	{
		return -1;
	}
	std::vector<std::string> hashes;

	//Take the current height within 50 height and take the current height -10 height outside 50 height
	uint64_t block_height = top;
	if (top >= 50)
	{
		block_height = top - 10;
	}

	if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(block_height, hashes))
	{
		return -2;
	}

	std::vector<CBlock> blocks;
	for (auto &hash : hashes)
	{
		std::string blockStr;
		db_reader.GetBlockByBlockHash(hash, blockStr);
		CBlock block;
		block.ParseFromString(blockStr);
		blocks.push_back(block);
	}
	std::sort(blocks.begin(), blocks.end(), [](const CBlock &x, const CBlock &y)
			  { return x.time() < y.time(); });

	CBlock RandomBlock = blocks[0];
	std::string output, proof;
	Account defaultAccount;
	EVP_PKEY_free(defaultAccount.pkey);
	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultAccount(defaultAccount) != 0)
	{
		return -3;
	}
	int ret = MagicSingleton<VRF>::GetInstance()->CreateVRF(defaultAccount.pkey, hash_utxo, output, proof);
	if (ret != 0)
	{
		std::cout << "error create:" << ret << std::endl;
		return -4;
	}


	//Take 3, 4, 5 in the signature array of the block In this 3 addresses, use vrf to randomly find an address as a packaging node
	std::vector<std::string> BlockSignInfo;
	for (int i = 2; i < 5; ++i)
	{
		BlockSignInfo.push_back(GetBase58Addr(RandomBlock.sign(i).pub()));
	}

	if (BlockSignInfo.size() < 3)
	{
		return -5;
	}

	uint32_t rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(output, 3);
	packager = BlockSignInfo[rand_num]; //Packer
	if (packager == MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr())
	{
		ERRORLOG("Packager = {} cannot be the transaction initiator", packager);
		std::cout << "Packager cannot be the transaction initiator " << std::endl;
		return -6;
	}

	std::cout << "block rand_num: " << rand_num << std::endl;

	std::cout << "packager: " << packager << std::endl;
	nlohmann::json data_string;
	data_string["hash"] = RandomBlock.hash();
	data_string["range"] = 0;
	data_string["percentage"] = 0;
	setVrf(info, proof, defaultAccount.pubStr, data_string.dump());
	std::cout << "**********VRF Generated the number end**********************" << std::endl;

	return 0;
}

int VerifyTxMsgReq(const TxMsgReq &msg)
{
	//###
	//TODO
	return -1;
}

int IsQualifiedToUnstake(const std::string &fromAddr,
						 const std::string &utxo_hash,
						 uint64_t &staked_amount)
{
	// Query whether the account number has stake assets
	DBReader db_reader;
	std::vector<string> addresses;
	if (db_reader.GetStakeAddress(addresses) != DBStatus::DB_SUCCESS)
	{
		ERRORLOG(RED "Get all stake address failed!" RESET);
		return -1;
	}
	if (std::find(addresses.begin(), addresses.end(), fromAddr) == addresses.end())
	{
		ERRORLOG(RED "The account number has not staked assets!" RESET);
		return -2;
	}

	// Query whether the utxo to be de stake is in the staked utxo
	std::vector<string> utxos;
	if (db_reader.GetStakeAddressUtxo(fromAddr, utxos) != DBStatus::DB_SUCCESS)
	{
		ERRORLOG(RED "Get stake utxo from address failed!" RESET);
		return -3;
	}
	if (std::find(utxos.begin(), utxos.end(), utxo_hash) == utxos.end())
	{
		ERRORLOG(RED "The utxo to be de staked is not in the staked utxo!" RESET);
		return -4;
	}

	// Check whether the stake exceeds 30 days
	if (IsMoreThan30DaysForUnstake(utxo_hash) != true)
	{
		ERRORLOG(RED "The staked utxo is not more than 30 days" RESET);
		return -5;
	}

	std::string strStakeTx;
	if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(utxo_hash, strStakeTx))
	{
		ERRORLOG(RED "Stake tx not found!" RESET);
		return -6;
	}

	CTransaction StakeTx;
	if (!StakeTx.ParseFromString(strStakeTx))
	{
		ERRORLOG(RED "Failed to parse transaction body!" RESET);
		return -7;
	}
	for (int i = 0; i < StakeTx.utxo().vout_size(); i++)
	{
		if (StakeTx.utxo().vout(i).addr() == global::ca::kVirtualStakeAddr)
		{
			staked_amount = StakeTx.utxo().vout(i).value();
			break;
		}
	}
	if (staked_amount == 0)
	{
		ERRORLOG(RED "Stake value is zero!" RESET);
		return -8;
	}

	return 0;
}

int CheckInvestQualification(const std::string &fromAddr,
							 const std::string &toAddr,
							 uint64_t invest_amount)
{
	// Each investor can only invest once
	DBReader db_reader;
	std::vector<string> nodes;
	auto status = db_reader.GetBonusAddrByInvestAddr(fromAddr, nodes);
	if (status == DBStatus::DB_SUCCESS && !nodes.empty())
	{
		ERRORLOG(RED "The investor have already invested in a node!" RESET);
		return -1;
	}

	// Each investor shall not invest less than 99 yuan
	if (invest_amount < (uint64_t)99 * global::ca::kDecimalNum)
	{
		ERRORLOG(RED "The investment amount is less than 99" RESET);
		return -2;
	}

	// The node to be invested must have spent 999 to access the Internet
	int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(toAddr, global::ca::StakeType::kStakeType_Node);
	if (stake_time <= 0)
	{
		ERRORLOG(RED "The account to be invested has not spent 500 to access the Internet!" RESET);
		return -3;
	}

	// The node to be invested can only be invested by 999 people at most
	std::vector<string> addresses;
	status = db_reader.GetInvestAddrsByBonusAddr(toAddr, addresses);
	if (status != DBStatus::DB_SUCCESS && status != DBStatus::DB_NOT_FOUND)
	{
		ERRORLOG(RED "Get invest addrs by node failed!" RESET);
		return -4;
	}
	if (addresses.size() + 1 > 999)
	{
		ERRORLOG(RED "The account number to be invested have been invested by 999 people!" RESET);
		return -5;
	}

	// The node to be invested can only be be invested 100000 TFS at most
	uint64_t sum_invest_amount = 0;
	for (auto &address : addresses)
	{
		std::vector<string> utxos;
		if (db_reader.GetBonusAddrInvestUtxosByBonusAddr(toAddr, address, utxos) != DBStatus::DB_SUCCESS)
		{
			ERRORLOG("GetBonusAddrInvestUtxosByBonusAddr failed!");
			return -6;
		}

		for (const auto &utxo : utxos)
		{
			std::string strTx;
			if (db_reader.GetTransactionByHash(utxo, strTx) != DBStatus::DB_SUCCESS)
			{
				ERRORLOG("GetTransactionByHash failed!");
				return -7;
			}

			CTransaction tx;
			if (!tx.ParseFromString(strTx))
			{
				ERRORLOG("Failed to parse transaction body!");
				return -8;
			}
			for (auto &vout : tx.utxo().vout())
			{
				if (vout.addr() == global::ca::kVirtualInvestAddr)
				{
					sum_invest_amount += vout.value();
					break;
				}
			}
		}
	}
	if (sum_invest_amount + invest_amount > 100000ull * global::ca::kDecimalNum)
	{
		ERRORLOG(RED "The total amount invested in a single node will be more than 100000!" RESET);
		return -9;
	}

	return 0;
}

int IsQualifiedToDisinvest(const std::string &fromAddr,
						   const std::string &toAddr,
						   const std::string &utxo_hash,
						   uint64_t &invested_amount)
{
	// Query whether the account has invested assets to node
	DBReader db_reader;
	std::vector<string> nodes;
	if (db_reader.GetBonusAddrByInvestAddr(fromAddr, nodes) != DBStatus::DB_SUCCESS)
	{
		ERRORLOG("GetBonusAddrByInvestAddr failed!");
		return -1;
	}
	if (std::find(nodes.begin(), nodes.end(), toAddr) == nodes.end())
	{
		ERRORLOG(RED "The account has not invested assets to node!" RESET);
		return -2;
	}

	// Query whether the utxo to divest is in the utxos that have been invested
	std::vector<std::string> utxos;
	if (db_reader.GetBonusAddrInvestUtxosByBonusAddr(toAddr, fromAddr, utxos) != DBStatus::DB_SUCCESS)
	{
		ERRORLOG("GetBonusAddrInvestUtxosByBonusAddr failed!");
		return -3;
	}
	if (std::find(utxos.begin(), utxos.end(), utxo_hash) == utxos.end())
	{
		ERRORLOG(RED "The utxo to divest is not in the utxos that have been invested!" RESET);
		return -4;
	}

	// Query whether the investment exceeds one day
	if (IsMoreThan1DayForDivest(utxo_hash) != true)
	{
		ERRORLOG(RED "The invested utxo is not more than 1 day!" RESET);
		return -5;
	}

	// The amount to be divested must be greater than 0
	std::string strInvestTx;
	if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(utxo_hash, strInvestTx))
	{
		ERRORLOG("Invest tx not found!");
		return -6;
	}
	CTransaction InvestedTx;
	if (!InvestedTx.ParseFromString(strInvestTx))
	{
		ERRORLOG("Failed to parse transaction body!");
		return -7;
	}

	nlohmann::json data_json = nlohmann::json::parse(InvestedTx.data());
	nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
	std::string invested_addr = tx_info["BonusAddr"].get<std::string>();
	if (toAddr != invested_addr)
	{
		ERRORLOG(RED "The node to be divested is not invested!" RESET);
		return -8;
	}

	for (int i = 0; i < InvestedTx.utxo().vout_size(); i++)
	{
		if (InvestedTx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
		{
			invested_amount = InvestedTx.utxo().vout(i).value();
			break;
		}
	}
	if (invested_amount == 0)
	{
		ERRORLOG(RED "The invested value is zero!" RESET);
		return -9;
	}

	return 0;
}

// Check time of the unstake, unstake time must be more than 30 days, add 20201208   LiuMingLiang
bool IsMoreThan30DaysForUnstake(const std::string &utxo)
{
	DBReader db_reader;

	std::string strTransaction;
	DBStatus status = db_reader.GetTransactionByHash(utxo, strTransaction);
	if (status != DBStatus::DB_SUCCESS)
	{
		return false;
	}

	CTransaction utxoStake;
	utxoStake.ParseFromString(strTransaction);
	uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	uint64_t DAYS30 = (uint64_t)1000000 * 60 * 60 * 24 * 30;
	if (global::kBuildType == global::BuildType::kBuildType_Dev)
	{
		DAYS30 = (uint64_t)1000000 * 60;
	}

	return (nowTime - utxoStake.time()) >= DAYS30;
}

// Check time of the redeem, redeem time must be more than 30 days, add 20201208   LiuMingLiang
bool IsMoreThan1DayForDivest(const std::string &utxo)
{
	DBReader db_reader;

	std::string strTransaction;
	DBStatus status = db_reader.GetTransactionByHash(utxo, strTransaction);
	if (status != DBStatus::DB_SUCCESS)
	{
		return -1;
	}
	CTransaction utxoStake;
	utxoStake.ParseFromString(strTransaction);
	uint64_t nowTime = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	uint64_t DAY = (uint64_t)1000000 * 60 * 60 * 24;
	if (global::kBuildType == global::BuildType::kBuildType_Dev)
	{
		DAY = (uint64_t)1000000 * 60;
	}

	return (nowTime - utxoStake.time()) >= DAY;
}

int VerifyBonusAddr(const std::string &BonusAddr)
{
	uint64_t invest_amount;
	auto ret = MagicSingleton<BounsAddrCache>::GetInstance()->get_amount(BonusAddr, invest_amount);
	if (ret < 0)
	{
		ERRORLOG("invest BonusAddr: {}, ret:{}", BonusAddr, ret);
		return -99;
	}
	DEBUGLOG("invest BonusAddr: {}, invest total: {}", BonusAddr, invest_amount);
	return invest_amount >= global::ca::kMinInvestAmt ? 0 : -99;
}

int GetInvestmentAmountAndDuration(const std::string &bonusAddr, const uint64_t &cur_time, const uint64_t &zero_time, std::map<std::string, std::pair<uint64_t, uint64_t>> &mpInvestAddr2Amount)
{
	DBReadWriter db_writer;
	std::string strTx;
	CTransaction tx;
	std::vector<string> addresses;

	time_t t = cur_time;
	t = t / 1000000;
	struct tm *tm = gmtime(&t);
	tm->tm_hour = 23;
	tm->tm_min = 59;
	tm->tm_sec = 59;
	uint64_t end_time = mktime(tm);
	end_time *= 1000000;

	uint64_t invest_amount = 0;
	uint64_t invest_amountDay = 0;
	if (db_writer.GetInvestAddrsByBonusAddr(bonusAddr, addresses) != DBStatus::DB_SUCCESS)
	{
		return -1;
	}
	for (auto &address : addresses)
	{
		std::vector<std::string> utxos;
		if (db_writer.GetBonusAddrInvestUtxosByBonusAddr(bonusAddr, address, utxos) != DBStatus::DB_SUCCESS)
		{
			return -2;
		}

		invest_amount = 0;
		invest_amountDay = 0;
		for (const auto &hash : utxos)
		{
			tx.Clear();
			if (db_writer.GetTransactionByHash(hash, strTx) != DBStatus::DB_SUCCESS)
			{
				return -3;
			}
			if (!tx.ParseFromString(strTx))
			{
				return -4;
			}
			if (tx.time() >= zero_time && tx.time() <= end_time)
			{
				for (int i = 0; i < tx.utxo().vout_size(); i++)
				{
					if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
					{
						invest_amountDay += tx.utxo().vout(i).value();
						invest_amount += tx.utxo().vout(i).value();
						break;
					}
				}
			}
			else
			{
				for (int i = 0; i < tx.utxo().vout_size(); i++)
				{
					if (tx.utxo().vout(i).addr() == global::ca::kVirtualInvestAddr)
					{
						invest_amount += tx.utxo().vout(i).value();
						break;
					}
				}
				break;
			}
		}
		invest_amount = (invest_amount - invest_amountDay);
		if (invest_amount == 0)
		{
			continue;
		}
		mpInvestAddr2Amount[address].first = invest_amount;

	}
	if (mpInvestAddr2Amount.empty())
	{
		return -9;
	}
	return 0;
}

int GetTotalCirculationYesterday(const uint64_t &cur_time, uint64_t &TotalCirculation)
{
	DBReadWriter db_writer;
	std::vector<std::string> utxos;
	std::string strTx;
	CTransaction tx;
	{
		std::lock_guard<std::mutex> lock(global::ca::kBonusMutex);
		if (DBStatus::DB_SUCCESS != db_writer.GetM2(TotalCirculation))
		{
			return -1;
		}
		uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
		auto ret = db_writer.GetBonusUtxoByPeriod(Period, utxos);
		if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
		{
			return -2;
		}
	}
	uint64_t Claim_Vout_amount = 0;
	uint64_t TotalClaimDay = 0;
	for (auto utxo = utxos.rbegin(); utxo != utxos.rend(); utxo++)
	{
		if (db_writer.GetTransactionByHash(*utxo, strTx) != DBStatus::DB_SUCCESS)
		{
			return -3;
		}
		if (!tx.ParseFromString(strTx))
		{
			return -4;
		}
		uint64_t claim_amount = 0;
		if ((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
		{
			nlohmann::json data_json = nlohmann::json::parse(tx.data());
			nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
			tx_info["BonusAmount"].get_to(claim_amount);
			TotalClaimDay += claim_amount;
		}
	}
	if (global::kBuildType == global::BuildType::kBuildType_Dev)
	{
		
	}
	TotalCirculation -= TotalClaimDay;
	return 0;
}

int GetTotalInvestmentYesterday(const uint64_t &cur_time, uint64_t &Totalinvest)
{
	DBReadWriter db_writer;
	std::vector<std::string> utxos;
	std::string strTx;
	CTransaction tx;
	{
		std::lock_guard<std::mutex> lock(global::ca::kInvestMutex);
		auto ret = db_writer.GetTotalInvestAmount(Totalinvest);
		if (DBStatus::DB_SUCCESS != ret)
		{
			if (DBStatus::DB_NOT_FOUND != ret)
			{
				return -1;
			}
			else
			{
				Totalinvest = 0;
			}
		}
		uint64_t Period = MagicSingleton<TimeUtil>::GetInstance()->getPeriod(cur_time);
		ret = db_writer.GetInvestUtxoByPeriod(Period, utxos);
		if (DBStatus::DB_SUCCESS != ret && DBStatus::DB_NOT_FOUND != ret)
		{
			return -2;
		}
	}
	uint64_t Invest_Vout_amount = 0;
	uint64_t TotalInvestmentDay = 0;
	for (auto utxo = utxos.rbegin(); utxo != utxos.rend(); utxo++)
	{
		Invest_Vout_amount = 0;
		if (db_writer.GetTransactionByHash(*utxo, strTx) != DBStatus::DB_SUCCESS)
		{
			return -3;
		}
		if (!tx.ParseFromString(strTx))
		{
			return -4;
		}
		for (auto &vout : tx.utxo().vout())
		{
			if (vout.addr() == global::ca::kVirtualInvestAddr)
			{
				Invest_Vout_amount += vout.value();
				break;
			}
		}
		TotalInvestmentDay += Invest_Vout_amount;
	}
	if (global::kBuildType == global::BuildType::kBuildType_Dev)
	{
		
	}
	Totalinvest -= TotalInvestmentDay;
	return 0;
}


// Notify node height to change, 20211129  Liu
void NotifyNodeHeightChange()
{
	net_send_node_height_changed();
}

std::map<int32_t, std::string> GetMultiSignTxReqCode()
{
	std::map<int32_t, std::string> errInfo = {
		std::make_pair(0, ""),
		std::make_pair(-1, ""),
		std::make_pair(-2, ""),
		std::make_pair(-3, ""),
		std::make_pair(-4, ""),
		std::make_pair(-5, ""),
		std::make_pair(-6, ""),
	};

	return errInfo;
}
int HandleMultiSignTxReq(const std::shared_ptr<MultiSignTxReq> &msg, const MsgData &msgdata)
{
	std::cout << "HandleMultiSignTxReq" << std::endl;

	auto errInfo = GetMultiSignTxReqCode();
	MultiSignTxAck ack;
	int ret = 0;

	ON_SCOPE_EXIT
	{
		ReturnAckCode<MultiSignTxAck>(msgdata, errInfo, ack, ret);
	};

	CTransaction tx;
	tx.ParseFromString(msg->txraw());

	ret = ca_algorithm::MemVerifyTransactionTx(tx);
	if (ret != 0)
	{
		return ret -= 1013;
	}

	ret = ca_algorithm::VerifyTransactionTx(tx, msg->height() + 1);
	if (ret != 0)
	{
		return ret -= 2015;
	}

	// 
	// Find all signable accounts that do not have signatures in the multi-signature list
	std::set<std::string> dataSignAddr;
	uint64_t threshold = 0;
	std::string multiSignPub;
	try
	{
		if (tx.utxo().owner_size() == 0)
		{
			return -1;
		}
		std::string owner = tx.utxo().owner(0);
		if (CheckBase58Addr(owner, Base58Ver::kBase58Ver_MultiSign) == false)
		{
			return -2;
		}

		DBReader db_reader;
		std::vector<std::string> multiSignAddrs;
		auto db_status = db_reader.GetMutliSignAddress(multiSignAddrs);
		if (DBStatus::DB_SUCCESS != db_status)
		{
			if (DBStatus::DB_NOT_FOUND != db_status)
			{
				return -3;
			}
		}

		if (std::find(multiSignAddrs.begin(), multiSignAddrs.end(), owner) == multiSignAddrs.end())
		{
			return -4;
		}

		std::vector<std::string> utxos;
		db_status = db_reader.GetMutliSignAddressUtxo(owner, utxos);
		if (DBStatus::DB_SUCCESS != db_status)
		{
			return -5;
		}
		if (utxos.size() != 1)
		{
			return -6;
		}

		std::string declareTxRaw;
		db_status = db_reader.GetTransactionByHash(utxos[0], declareTxRaw);
		if (DBStatus::DB_SUCCESS != db_status)
		{
			return -7;
		}
		CTransaction declareTx;
		if (!declareTx.ParseFromString(declareTxRaw))
		{
			ERRORLOG("TxHelper FindUtxo: GetTransactionByHash failed!");
			return -8;
		}
		nlohmann::json data_json = nlohmann::json::parse(declareTx.data());
		nlohmann::json tx_info = data_json["TxInfo"].get<nlohmann::json>();
		multiSignPub = tx_info["MultiSignPub"].get<std::string>();
		threshold = tx_info["SignThreshold"].get<uint64_t>();
		nlohmann::json signAddrList = tx_info["SignAddrList"].get<nlohmann::json>();

		for (auto &addr : signAddrList)
		{
			if (CheckBase58Addr(addr, Base58Ver::kBase58Ver_Normal) == false)
			{
				return -9;
			}
			dataSignAddr.insert(std::string(addr));
		}

		if (signAddrList.size() != dataSignAddr.size())
		{
			return -10;
		}

		if (threshold > signAddrList.size())
		{
			return -11;
		}
	}
	catch (const std::exception &e)
	{
		std::cerr << e.what() << '\n';
	}

	std::set<std::string> setMultiSign;
	const CTxUtxo &utxo = tx.utxo();
	for (int i = 1; i < utxo.multisign_size(); ++i)
	{
		const CSign &sign = utxo.multisign(i);

		setMultiSign.insert(GetBase58Addr(sign.pub()));
	}

	if ((utxo.multisign_size() - 1) != threshold)
	{
		return ret = -12;
	}

	uint64_t count = 0;
	for (auto &mSignAddr : setMultiSign)
	{
		for (auto &dSignAddr : dataSignAddr)
		{
			if (dSignAddr == mSignAddr)
			{
				count++;
			}
		}
	}

	if (count != setMultiSign.size())
	{
		return ret -= 13;
	}

	//  Send flow
	std::string identity = tx.identity();

	if (MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr() == identity)
	{
		uint64_t top = 0;
		{
			DBReader db_reader;
			if (DBStatus::DB_SUCCESS != db_reader.GetBlockTop(top))
			{
				ERRORLOG("db get top failed!!");
				return ret = -14;
			}
		}

		TxMsgReq txMsg;
		txMsg.set_version(global::kVersion);
		TxMsgInfo *txMsgInfo = txMsg.mutable_txmsginfo();
		txMsgInfo->set_type(0);
		txMsgInfo->set_tx(tx.SerializeAsString());
		txMsgInfo->set_height(top);

		auto msg = make_shared<TxMsgReq>(txMsg);

		CTransaction outTx;
		ret = DoHandleTx(msg, outTx);
		DEBUGLOG("Transaction result,ret:{}  txHash:{}", ret, outTx.hash());
		return ret;
	}
	else
	{
		MultiSignTxReq anotherReq;
		anotherReq.set_version(global::kVersion);
		anotherReq.set_txraw(tx.SerializeAsString());

		net_send_message<MultiSignTxReq>(identity, anotherReq, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
		return ret = 1;
	}

	return ret = 0;
}

bool IsMultiSign(const CTransaction &tx)
{
	global::ca::TxType tx_type = (global::ca::TxType)tx.txtype();

	return tx.utxo().owner_size() == 1 &&
		   (CheckBase58Addr(tx.utxo().owner(0), Base58Ver::kBase58Ver_MultiSign) &&
			(tx.utxo().vin_size() == 1) &&
			global::ca::TxType::kTxTypeTx == tx_type);
}


int HandleAddBlockAck(const std::shared_ptr<BuildBlockBroadcastMsgAck> &msg, const MsgData &msgdata)
{

	// Determine if the version is compatible
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("HandleBuildBlockBroadcastMsg IsVersionCompatible");
		return -1;
	}
	MagicSingleton<BlockMonitor>::GetInstance()->HandleBroadcastAddBlockAck(*msg);

	return 0;
}

int AddBlockSign(CBlock &block)
{

	std::string serblockHash = getsha256hash(block.SerializeAsString());
	std::string signature;
	std::string pub;
	std::string defalutaddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	if (TxHelper::Sign(defalutaddr, serblockHash, signature, pub) != 0)
	{
		ERRORLOG("Block flow signature failed");
		return -1;
	}

	CSign *cblocksign = block.add_sign();
	cblocksign->set_sign(signature);
	cblocksign->set_pub(pub);

	return 0;
}

int VerifyBlockSign(const CBlock &block)
{

	for (auto &blocksignmsg : block.sign())
	{
		std::string pub = blocksignmsg.pub();
		std::string sign = blocksignmsg.sign();

		CBlock cblock = block;
		cblock.clear_sign();
		std::string serblockHash = getsha256hash(cblock.SerializeAsString());
		if (pub.size() == 0 ||
			sign.size() == 0 ||
			serblockHash.size() == 0)
		{
			ERRORLOG("block flow info fail!");
			return -1;
		}

		EVP_PKEY *eckey = nullptr;
		if (GetEDPubKeyByBytes(pub, eckey) == false)
		{
			EVP_PKEY_free(eckey);
			ERRORLOG(RED "Get public key from bytes failed!" RESET);
			return -2;
		}

		if (ED25519VerifyMessage(serblockHash, eckey, sign) == false)
		{
			EVP_PKEY_free(eckey);
			ERRORLOG(RED "Public key verify sign failed!" RESET);
			return -3;
		}
		EVP_PKEY_free(eckey);
	}

	return 0;
}

int HandleBlock(const std::shared_ptr<BlockMsg> &msg, const MsgData &msgdata)
{
	auto errInfo = TxMsgReqCode();
	BlockMsg ack;

	int ret = 0;

	ret = DoHandleBlock(msg);
	if (ret != 0)
	{
		DEBUGLOG("DoHandleBlock failed The error code is {}", ret);
	}

	return ret;
}

int DoHandleBlock(const std::shared_ptr<BlockMsg> &msg)
{
	// Verify the version
	if (0 != Util::IsVersionCompatible(msg->version()))
	{
		ERRORLOG("Incompatible version!");
		return -1;
	}

	std::string defaultBase58Addr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
	CBlock cblock;
	if (!cblock.ParseFromString(msg->block()))
	{
		ERRORLOG("fail to serialization!!");
		return -2;
	}

	int verifyCount = cblock.sign_size();
	if (verifyCount == 2 && defaultBase58Addr == GetBase58Addr(cblock.sign(0).pub()))
	{
		std::pair<std::string, std::vector<std::string>> nodes_pair;
		MagicSingleton<VRF>::GetInstance()->getVerifyNodes(cblock.hash(), nodes_pair);

		std::vector<std::string> nodes = nodes_pair.second;
		auto id_ = GetBase58Addr(cblock.sign(1).pub());
		auto iter = std::find(nodes.begin(), nodes.end(), id_);
		if (iter == nodes.end())
		{
			ERRORLOG("Validation node not found = {} block hash = {}", id_, cblock.hash());
			return -3;
		}

		if (MagicSingleton<BlockStroage>::GetInstance()->UpdateBlock(*msg))
		{
			ERRORLOG("UpdataBlock fail");
			return -4;
		}
	}
	else
	{
		int ret = VerifyBlockSign(cblock);
		if (ret != 0)
		{
			ERRORLOG("VerifyBlockSign fail");
			return ret -= 1930;
		}
		ret = MagicSingleton<BlockHelper>::GetInstance()->VerifyFlowedBlock(cblock);
		if (ret != 0)
		{
			ERRORLOG("Verify Flowed Block fail");
			return ret -= 2240;
		}

		
		// Block flow plus signature
		ret = AddBlockSign(cblock);
		if (ret != 0)
		{
			ERRORLOG("Add Block Sign fail");
			return ret -= 3800;
		}

		msg->set_block(cblock.SerializeAsString());
		if (verifyCount == 0)
		{

			if (MagicSingleton<BlockStroage>::GetInstance()->AddBlock(*msg))
			{
				ERRORLOG("Add Block  fail)");
				return -5;
			}
			
			// VRF looks for nodes to send block flows
			ret = SearchNodeToSendMsg(*msg);
			if (ret != 0)
			{
				ERRORLOG("Search Node To SendMsg fail");
				return ret -= 1650;
			}
		}
		else if (verifyCount == 1)
		{
			std::vector<std::string> verify_sign;
			for (auto &tx : cblock.txs())
			{
			
				// Whether to find the vrf logo
				bool flag = true;
				if (GetTransactionType(tx) != kTransactionType_Tx)
				{
					continue;
				}
			
				// Not dropshipping

				CTransaction copyTx = tx;
				copyTx.clear_hash();
				copyTx.clear_verifysign();
				std::string tx_hash = getsha256hash(copyTx.SerializeAsString());
				uint64_t handleTxHeight = cblock.height() - 1;
				TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
				DEBUGLOG("block verify type = {}", type);
				if (type != TxHelper::vrfAgentType_vrf)
				{
					continue;
				}

				for (auto &vrf : msg->vrfinfo())
				{
					int range = 0;
					std::string hash;
					if(getVrfdata(vrf, hash, range) != 0)
					{
						return -6;
					}

					if (hash == tx_hash)
					{
						flag = false;
						
						// Check that the selected nodes for VRFs for all transactions in the block are correct
						EVP_PKEY *pkey = nullptr;
						std::string pub_str = vrf.vrfsign().pub();
						if (!GetEDPubKeyByBytes(pub_str, pkey))
						{
							ERRORLOG(RED "Get public key from bytes failed!" RESET);
							return -7;
						}

						std::string proof = vrf.vrfsign().sign();
						std::string result;
						if (MagicSingleton<VRF>::GetInstance()->VerifyVRF(pkey, tx_hash, result, proof) != 0)
						{
							ERRORLOG(RED "Verify VRF Info fail" RESET);
							return -8;
						}

						double rand_num = MagicSingleton<VRF>::GetInstance()->GetRandNum(result);

						if (VerifyTxFlowSignNode(tx, rand_num, range) != 0)
						{
							ERRORLOG(RED "vrf Failed to verify nodes in the interval" RESET);
							return -9;
						}
					}
				}

				if (flag)
				{
					ERRORLOG("flag is true Not have VrfInfo!");
					return -10;
				}
			}

			// send to origin node
			if (defaultBase58Addr != GetBase58Addr(cblock.sign(0).pub()) && cblock.sign_size() == 2)
			{
				DEBUGLOG("DoHandleBlock net_send_message<BlockMsg> {}", GetBase58Addr(cblock.sign(0).pub()));
				net_send_message<BlockMsg>(GetBase58Addr(cblock.sign(0).pub()), *msg, net_com::Priority::kPriority_High_1);
			}
		}
		else
		{
			// error
			ERRORLOG("unknow type !");
			return -11;
		}
	}
	return 0;
}

int DropshippingTx(const std::shared_ptr<TxMsgReq> &txMsg, const CTransaction &tx)
{

	uint64_t handleTxHeight = txMsg->txmsginfo().height();
	TxHelper::vrfAgentType type = TxHelper::GetVrfAgentType(tx, handleTxHeight);
	if (type == TxHelper::vrfAgentType_vrf)
	{
		if (txMsg->vrfinfo().vrfsign().pub().empty())
		{
			ERRORLOG("---------------------------net_send_message vrf pub is empty !!!!!");
		}
	}
	else
	{
		ERRORLOG("---------------------------DropshippingTx vrf pub is error !!!!!");
	}

	bool sRet = net_send_message<TxMsgReq>(tx.identity(), *txMsg, net_com::Compress::kCompress_True, net_com::Encrypt::kEncrypt_False, net_com::Priority::kPriority_High_1);
	if (sRet == false)
	{
		return -12000;
	}
	return 0;
}

int VerifyTxFlowSignNode(const CTransaction &tx, const double &rand_num, const int &range)
{

	
	std::vector<Node> outNodes;
	filterNodeList(tx, outNodes);
	outNodes.push_back(tx.identity());
	
	std::vector<std::string> stakeNodes;
	//When there are no 45 nodes staking investments, do not filter peernodes to satisfy 45 nodes staking investments, and then filter peernodes
	for (const auto &node : outNodes)
	{
		int ret = VerifyBonusAddr(node.base58address);
		int64_t stake_time = ca_algorithm::GetPledgeTimeByAddr(node.base58address, global::ca::StakeType::kStakeType_Node);
		if (stake_time > 0 && ret == 0)
		{
			stakeNodes.push_back(node.base58address);
		}
	}



	//	If there are 45 eligible nodes, take them from the set of qualified qualifications If they do not meet them, find them from the node list	
	std::vector<std::string> eligible_addrs;
	if(stakeNodes.size() < global::ca::kNeed_node_threshold)
	{
		for(const auto & node : outNodes)
		{
			eligible_addrs.push_back(node.base58address);
		}
	}
	else
	{
		eligible_addrs = stakeNodes;
	}

	//Sort by base58 address from smallest to largest
	std::sort(eligible_addrs.begin(), eligible_addrs.end(),[](const std::string & addr1, const std::string & addr2){
		return addr1 < addr2;
	});

	//Remove all nodes in the VRF range to the target_addrs
	int target_pos = eligible_addrs.size() * rand_num;

	Cycliclist<std::string> list;

	for (auto &addr : eligible_addrs)
	{
		list.push_back(addr);
	}

	auto begin = list.begin();
	auto target = begin + target_pos;
	auto start_pos = target - range;
	auto end_pos = target + range;

	DEBUGLOG("dohandleblock range = {} , random = {} ",range, rand_num);
	vector<std::string> target_addrs;
	for (; start_pos != end_pos; start_pos++)
	{
		DEBUGLOG("dohandleblock target_addrs = {} ", start_pos->data);
		target_addrs.push_back(start_pos->data);
	}

	//Take out the signature node in the transaction flow
	vector<std::string> verify_sign;
	for (int i = 1; i < tx.verifysign().size(); ++i)
	{
		DEBUGLOG("dohandleblock verify_sign addr = {} ", GetBase58Addr(tx.verifysign(i).pub()));
		verify_sign.push_back(GetBase58Addr(tx.verifysign(i).pub()));
	}

	//Verify that the signing node is in the selected range
	for (auto &item : verify_sign)
	{
		if (std::find(target_addrs.begin(), target_addrs.end(), item) == target_addrs.end())
		{
			DEBUGLOG("vrf verify sign addr = {} error !", item);
			return -1;
		}
	}

	return 0;
}

int PreCalcGas(CTransaction &tx)
{

	uint64_t gas = 0;
	CalculateGas(tx, gas);
	std::cout << "The gas for this transaction is:" << gas << std::endl;

	std::string strKey;
	std::cout << "Please input your choice [0](accept) or [1](Unacceptable) >: " << std::endl;
	std::cin >> strKey;
	std::regex pattern("^[0-1]$");
	if (!std::regex_match(strKey, pattern))
	{
		std::cout << "Invalid input." << std::endl;
		return -1;
	}
	int key = std::stoi(strKey);
	if (key == 1)
	{
		return -2;
	}

	auto current_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
	tx.set_time(current_time);
	tx.clear_hash();

	std::string txHash = getsha256hash(tx.SerializeAsString());
	tx.set_hash(txHash);

	return 0;
}

int CalculateGas(const CTransaction &tx, uint64_t &gas)
{

	TransactionType tx_type = GetTransactionType(tx);
	if (tx_type == kTransactionType_Genesis || tx_type == kTransactionType_Tx)
	{

		uint64_t utxo_size = 0;
		const CTxUtxo &utxo = tx.utxo();

		utxo_size += utxo.owner_size() * 34;

		for (auto &vin : utxo.vin())
		{
			utxo_size += vin.prevout().size() * 64;
		}
		utxo_size += utxo.vout_size() * 34;

		gas += utxo_size;
		gas += tx.type().size() + tx.data().size() + tx.info().size();
		gas += tx.reserve0().size() + tx.reserve1().size();
	}

	gas *= 2;

	if (gas == 0)
	{
		ERRORLOG(" gas = 0 !");
		return -1;
	}

	return 0;
}

//The interface used when creating transactions
int GenerateGas(const CTransaction &tx, const std::map<std::string, int64_t> &toAddr, uint64_t &gas)
{

	TransactionType tx_type = GetTransactionType(tx);
	if (tx_type == kTransactionType_Genesis || tx_type == kTransactionType_Tx)
	{

		uint64_t utxo_size = 0;
		const CTxUtxo &utxo = tx.utxo();

		utxo_size += utxo.owner_size() * 34;

		for (auto &vin : utxo.vin())
		{
			utxo_size += vin.prevout().size() * 64;
		}

		utxo_size += toAddr.size() * 34;

		gas += utxo_size;
		gas += tx.type().size() + tx.data().size() + tx.info().size();
		gas += tx.reserve0().size() + tx.reserve1().size();
	}

	gas *= 2;

	if (gas == 0)
	{
		ERRORLOG(" gas = 0 !");
		return -1;
	}

	return 0;
}
