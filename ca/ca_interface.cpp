#include "ca_interface.h"
#include "include/net_interface.h"
#include "include/ScopeGuard.h"
#include "utils/ReturnAckCode.h"
#include "utils/util.h"
#include "utils/MagicSingleton.h"
#include "ca/ca_global.h"
#include "db/db_api.h"

#include "ca/ca_txhelper.h"
#include "ca/ca_algorithm.h"
#include "utils/time_util.h"
#include "ca/ca_CCalBlockGas.h"
#include "utils/AccountManager.h"
#include "ca/ca_tranmonitor.h"
#include "utils/AccountManager.h"
//  Get the block

std::map<int32_t, std::string> GetBlockReqCode()
{
	std::map<int32_t, std::string> errInfo = {  
                                                std::make_pair(-1, "The version is wrong"),
												std::make_pair(-12, "By block height failure"), 
												};

	return errInfo;												
}
int GetBlockReqImpl(const std::shared_ptr<GetBlockReq>& req, GetBlockAck & ack)
{
	ack.set_version(global::kVersion);

    DBReader db_reader;
    std::vector<std::string> hashes;
	uint64_t top = req->height();
    uint64_t block_height = top;
	if(top >= global::ca::kMinUnstakeHeight)
	{
		block_height = top - 10;
	}
	
	if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashsByBlockHeight(block_height, hashes))
	{
        ack.set_code(-2);
        ack.set_message("Get block hash failed");
		return -2;
	}

	std::vector<CBlock> blocks;
	for (const auto &hash : hashes)
	{
		std::string blockStr;
		db_reader.GetBlockByBlockHash(hash, blockStr);
		CBlock block;
		block.ParseFromString(blockStr);
		blocks.push_back(block);
	}
	std::sort(blocks.begin(), blocks.end(), [](const CBlock &x, const CBlock &y)
			  { return x.time() < y.time(); });

    
    for(const auto &block:blocks)
    {
        BlockItem *blockitem = ack.add_list();
        blockitem->set_blockhash(block.hash());
        for(int i = 0; i<block.sign().size();  ++i)
        {
            blockitem->add_addr(GetBase58Addr(block.sign(i).pub())) ;
        }
    }
    


    {
        std::vector<std::string> block_hashes;
        if (DBStatus::DB_SUCCESS != db_reader.GetBlockHashesByBlockHeight(top, top, block_hashes))
        {
            ERRORLOG("can't GetBlockHashesByBlockHeight");
            return false;
        }

        std::vector<CBlock> blocks_time;
        for (auto &hash : block_hashes)
        {
            std::string blockStr;
            if(DBStatus::DB_SUCCESS != db_reader.GetBlockByBlockHash(hash, blockStr))
            {
                ERRORLOG("GetBlockByBlockHash error block hash = {} ", hash);
                return false;
            }

            CBlock block;
            if(!block.ParseFromString(blockStr))
            {
                ERRORLOG("block parse from string fail = {} ", blockStr);
                return false;
            }
            blocks_time.push_back(block);
        }

        std::sort(blocks_time.begin(), blocks_time.end(), [](const CBlock& x, const CBlock& y){ return x.time() < y.time(); });
        ack.set_timestamp(blocks_time.at(blocks_time.size()-1).time());
	
    }

    ack.set_code(0);
    ack.set_message("success");
    ack.set_height(block_height);
	return 0;
}
int HandleGetBlockReq(const std::shared_ptr<GetBlockReq>& req, const MsgData & msgdata)
{

    auto errInfo = GetBlockReqCode();
    GetBlockAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetBlockAck>(msgdata, errInfo, ack, ret); 
    };
    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}
    
	ret = GetBlockReqImpl(req, ack);
	if (ret != 0)
	{
		return ret -= 10;
	}

    return 0;
}


/*************************************Get the balance*************************************/

int GetBalanceReqImpl(const std::shared_ptr<GetBalanceReq>& req, GetBalanceAck & ack)
{
	ack.set_version(global::kVersion);

    std::string addr = req->address();
    if(addr.size() == 0)
    {
        return -1;
    } 

    if (!CheckBase58Addr(addr))
    {
        return -2;
    }

    DBReader db_reader;
	std::vector<std::string> addr_utxo_hashs;
    DBStatus db_status = db_reader.GetUtxoHashsByAddress(addr, addr_utxo_hashs);
    if (DBStatus::DB_SUCCESS != db_status)
    {
        if (db_status == DBStatus::DB_NOT_FOUND)
        {
            return -3;
        }
        else 
        {
            return -4;
        }
    }
	
	uint64_t balance = 0;
	std::string txRaw;
	CTransaction tx;
	for (auto utxo_hash : addr_utxo_hashs)
	{
		if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(utxo_hash, txRaw))
		{
			return -5;
		}
		if (!tx.ParseFromString(txRaw))
		{
            return -6;
		}
		for (auto &vout : tx.utxo().vout())
		{
			if (vout.addr() == addr)
			{
				balance += vout.value();
			}
		}
	}

    ack.set_address(addr);
    ack.set_balance(balance);

    ack.set_code(0);
    ack.set_message("success");

	return 0;
}

std::map<int32_t, std::string> GetBalanceReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get Amount Success"), 
												std::make_pair(-1, "addr is empty"), 
												std::make_pair(-2, "base58 addr invalid"), 
												std::make_pair(-3, "search balance not found"),
                                                std::make_pair(-4, "get tx failed"),
                                                std::make_pair(-5, "GetTransactionByHash failed!"),
                                                std::make_pair(-6, "parse tx failed"),
												};

	return errInfo;												
}
int HandleGetBalanceReq(const std::shared_ptr<GetBalanceReq>& req, const MsgData& msgdata)
{
    auto errInfo = GetBalanceReqCode();
    GetBalanceAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{

        ReturnAckCode<GetBalanceAck>(msgdata, errInfo, ack, ret);
        
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}
    
	ret = GetBalanceReqImpl(req, ack);
	if (ret != 0)
	{
		return ret -= 10;
	}

    return ret;    
}
/*************************************Get node information*************************************/


int GetNodeInfoReqImpl(const std::shared_ptr<GetNodeInfoReq>& req, GetNodeInfoAck & ack)
{
	ack.set_version(global::kVersion);

    ack.set_address(MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr());
    
    Node selfNode = MagicSingleton<PeerNode>::GetInstance()->get_self_node();
    ack.set_ip(IpPort::ipsz(selfNode.public_ip));

    DBReader db_reader;
	uint64_t height = 0;
    DBStatus db_status = db_reader.GetBlockTop(height);
    if (DBStatus::DB_SUCCESS != db_status)
    {
        return -1;
    }


    ack.set_height(height);
    ack.set_ver(global::kVersion);

    ack.set_code(0);
    ack.set_message("success");

	return 0;
}

std::map<int32_t, std::string> GetNodeInfoReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get Node Info Success"), 
												std::make_pair(-1, "Invalid Version"), 
												std::make_pair(-11, "Get Top Failed"),
												std::make_pair(-12, "Get Gas Failed"),
												};

	return errInfo;												
}
int HandleGetNodeInfoReqReq(const std::shared_ptr<GetNodeInfoReq>& req, const MsgData& msgdata)
{
    auto errInfo = GetNodeInfoReqCode();
    GetNodeInfoAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{

        ReturnAckCode<GetNodeInfoAck>(msgdata, errInfo, ack, ret);
        
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}
    
	ret = GetNodeInfoReqImpl(req, ack);
	if (ret != 0)
	{
		return ret -= 10;
	}

    return ret;
}



/*************************************Stake list*************************************/

int GetStakeListReqImpl(const std::shared_ptr<GetStakeListReq>& req, GetStakeListAck & ack)
{
	ack.set_version(global::kVersion);

	std::string addr = req->addr();
    if (addr.length() == 0)
    {
        return -1;
    }

	if (!CheckBase58Addr(addr))
    {
        return -2;
    }

    std::vector<string> utxoes;
    DBReader db_reader;
    auto db_status = db_reader.GetStakeAddressUtxo(addr, utxoes);
    if (DBStatus::DB_SUCCESS != db_status)
    {
        return -3;
    }

    if (utxoes.size() == 0)
    {
        return -4;
    }

    reverse(utxoes.begin(), utxoes.end());

    for (auto & strUtxo: utxoes)
    {
        std::string serTxRaw;
        db_status = db_reader.GetTransactionByHash(strUtxo, serTxRaw);
        if (DBStatus::DB_SUCCESS != db_status)
        {
            ERRORLOG("Get stake tx error");
            continue;
        }

        CTransaction tx;
        tx.ParseFromString(serTxRaw);
        if(tx.utxo().vout_size() != 2)
        {
            ERRORLOG("invalid tx");
            continue;
        }

        if (tx.hash().length() == 0)
        {
            ERRORLOG("Get stake tx error");
            continue;
        }

        std::string strBlockHash;
        db_status = db_reader.GetBlockHashByTransactionHash(tx.hash(), strBlockHash);
        if (DBStatus::DB_SUCCESS != db_status)
        {
            ERRORLOG("Get stake block hash error");
            continue;
        }

        std::string serBlock;
        db_status = db_reader.GetBlockByBlockHash(strBlockHash, serBlock);
        if (db_status != 0)
        {
            ERRORLOG("Get stake block error");
            continue;
        }

        CBlock block;
        block.ParseFromString(serBlock);

        if (block.hash().empty())
        {
            ERRORLOG("Block error");
            continue;
        }
        std::vector<std::string> txOwnerVec(tx.utxo().owner().begin(), tx.utxo().owner().end()); //TODO
		if (txOwnerVec.size() == 0)
        {
            continue;
        }

        StakeItem * pItem = ack.add_list();
        
        pItem->set_blockhash(block.hash());
        pItem->set_blockheight(block.height());
        pItem->set_utxo(strUtxo);
        pItem->set_time(tx.time());

        pItem->set_fromaddr(txOwnerVec[0]);

        for (int i = 0; i < tx.utxo().vout_size(); i++)
        {
            CTxOutput txout = tx.utxo().vout(i);
            if (txout.addr() == global::ca::kVirtualStakeAddr)
            {
                pItem->set_toaddr(txout.addr());
                pItem->set_amount(txout.value());
                break;
            }
        }

        if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
        {
            nlohmann::json data_json = nlohmann::json::parse(tx.data());
            pItem->set_detail(data_json["TxInfo"]["StakeType"].get<std::string>());
        }
    }

    ack.set_code(0);
    ack.set_message("success");

	return 0;
}

std::map<int32_t, std::string> GetStakeListReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get Stake List Success"), 
												std::make_pair(-1, "addr is empty !"), 
												std::make_pair(-2, "base58 addr invalid"), 
												std::make_pair(-3, "Get Stake utxo error"),
                                                std::make_pair(-4, "No stake"),
												};

	return errInfo;												
}
int HandleGetStakeListReq(const std::shared_ptr<GetStakeListReq>& req, const MsgData & msgdata)
{
	auto errInfo = GetStakeListReqCode();
    GetStakeListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetStakeListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

	ret = GetStakeListReqImpl(req, ack);
	if (ret != 0)
	{
		return ret -= 10;
	}
	return ret;
}


/*************************************List of investments*************************************/

int GetInvestListReqImpl(const std::shared_ptr<GetInvestListReq>& req, GetInvestListAck & ack)
{
	ack.set_version(global::kVersion);
        
    std::string addr = req->addr();
    if (addr.length() == 0)
    {
        return -1;
    }

	if (!CheckBase58Addr(addr))
    {
        return -2;
    }

    std::vector<std::string> utxoes;
    std::vector<std::string> bonusAddrs;

    DBReader db_reader;
    auto db_status = db_reader.GetBonusAddrByInvestAddr(addr, bonusAddrs);
    if (DBStatus::DB_SUCCESS != db_status)
    {
        return -3;
    }

    for (auto & bonusAddr : bonusAddrs)
    {
        db_status = db_reader.GetBonusAddrInvestUtxosByBonusAddr(bonusAddr, addr, utxoes);
        if (DBStatus::DB_SUCCESS != db_status)
        {
            return -4;
        }

        if (utxoes.size() == 0)
        {
            return -5;
        }

        reverse(utxoes.begin(), utxoes.end());

        for (auto & strUtxo: utxoes)
        {
            std::string serTxRaw;
            db_status = db_reader.GetTransactionByHash(strUtxo, serTxRaw);
            if (DBStatus::DB_SUCCESS != db_status)
            {
                ERRORLOG("Get invest tx error");
                continue;
            }

            CTransaction tx;
            tx.ParseFromString(serTxRaw);
            if(tx.utxo().vout_size() != 2)
            {
                ERRORLOG("invalid tx");
                continue;
            }

            if (tx.hash().length() == 0)
            {
                ERRORLOG("Get invest tx error");
                continue;
            }

            std::string strBlockHash;
            db_status = db_reader.GetBlockHashByTransactionHash(tx.hash(), strBlockHash);
            if (DBStatus::DB_SUCCESS != db_status)
            {
                ERRORLOG("Get pledge block hash error");
                continue;
            }

            std::string serBlock;
            db_status = db_reader.GetBlockByBlockHash(strBlockHash, serBlock);
            if (db_status != 0)
            {
                ERRORLOG("Get invest block error");
                continue;
            }

            CBlock block;
            block.ParseFromString(serBlock);

            if (block.hash().empty())
            {
                ERRORLOG("Block error");
                continue;
            }
            
            std::vector<std::string> txOwnerVec(tx.utxo().owner().begin(), tx.utxo().owner().end());
            if (txOwnerVec.size() == 0)
            {
                continue;
            }

            InvestItem * pItem = ack.add_list();
            
            pItem->set_blockhash(block.hash());
            pItem->set_blockheight(block.height());
            pItem->set_utxo(strUtxo);
            pItem->set_time(tx.time());

            pItem->set_fromaddr(txOwnerVec[0]);

            for (int i = 0; i < tx.utxo().vout_size(); i++)
            {
                CTxOutput txout = tx.utxo().vout(i);
                if (txout.addr() == global::ca::kVirtualInvestAddr)
                {
                    pItem->set_toaddr(txout.addr());
                    pItem->set_amount(txout.value());
                    break;
                }
            }

            if((global::ca::TxType)tx.txtype() != global::ca::TxType::kTxTypeTx)
            {
                nlohmann::json data_json = nlohmann::json::parse(tx.data());
                pItem->set_detail(data_json["TxInfo"].dump());
            }
        }
    }

    ack.set_code(0);
    ack.set_message("success");


    return 0;
}

std::map<int32_t, std::string> GetInvestListReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair( 0, "Get Invest List Success"), 
												std::make_pair(-1, "addr is empty !"), 
												std::make_pair(-2, "base58 addr invalid !"), 
												std::make_pair(-3, "GetBonusAddr failed !"),
												std::make_pair(-4, "GetBonusAddrInvestUtxos failed !"),
                                                std::make_pair(-5, "No Invest"),
												};

	return errInfo;												
}

int HandleGetInvestListReq(const std::shared_ptr<GetInvestListReq>& req, const MsgData & msgdata)
{
	auto errInfo = GetInvestListReqCode();
    GetInvestListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetInvestListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

	ret = GetInvestListReqImpl(req, ack); 
	if (ret != 0)
	{
		return ret -= 10;
	}
	return ret;
}



/*************************************Transactions in progress*************************************/

static void InsertTxPendingToAckList(std::vector<TranMonitor::VinSt>& TranMonitorTxs, GetTxPendingListAck& ack)
{

    std::vector<TranMonitor::t_VinSt> vectTxs;
    for (auto iter = TranMonitorTxs.begin(); iter != TranMonitorTxs.end(); ++iter)
    {
        TranMonitor::t_VinSt vectTx;
        TranMonitor::t_VinSt::ConvertTx(iter->tx, iter->prevBlkHeight, vectTx,iter->timestamp);
        vectTxs.push_back(vectTx);
    }


    for (auto iter = vectTxs.begin(); iter != vectTxs.end(); ++iter)
    {
        TxPendingItem* txItem = ack.add_list();
        txItem->set_txhash(iter->txHash);
        auto item = iter->identifies.begin();

        for( ; item != iter->identifies.end(); ++item)
        {
            txItem->add_fromaddr(item->first);
            auto start = item->second.begin();
            for( ; start != item->second.end(); ++start)
            {
                txItem->add_vins(*start);
            }
        }

        for (const auto& to : iter->to)
        {
            txItem->add_toaddr(to);
        }
        txItem->set_amount(iter->amount);
        txItem->set_time(iter->timestamp);
        txItem->set_detail("");
        txItem->set_gas(iter->gas);
        for (const auto& amount : iter->toAmount)
        {
            txItem->add_toamount(amount);
        }

        txItem->set_type(TxType(iter->type));
    }
}

int GetTxPendingListReqImpl(const std::shared_ptr<GetTxPendingListReq>& req, GetTxPendingListAck & ack)
{
    ack.set_version(global::kVersion);

    if (req->addr_size() == 0)
    {
        std::vector<TranMonitor::VinSt> vectTxs;
        MagicSingleton<TranMonitor>::GetInstance()->GetAllTx(vectTxs);
        
        InsertTxPendingToAckList(vectTxs, ack);
    }
    else
    {
        for (int i = 0; i < req->addr_size(); i++)
        {
            string fromAddr = req->addr(i);
            std::vector<TranMonitor::VinSt> vectTxs;
            MagicSingleton<TranMonitor>::GetInstance()->Find(fromAddr, vectTxs);
            InsertTxPendingToAckList(vectTxs, ack);

            ack.add_addr(fromAddr);
        }
    }

    ack.set_code(0);
    ack.set_message("success");

    return 0;
}

std::map<int32_t, std::string> GetTxPendingListReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair( 0, "GetTxPendingListReq Success"), 

											 };
	return errInfo;												
}
int HandleGetTxPendingListReq(const std::shared_ptr<GetTxPendingListReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetTxPendingListReqCode();
    GetTxPendingListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetTxPendingListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetTxPendingListReqImpl(req, ack);
    if (ret != 0)
	{
		return ret -= 10;
	}

    return ret;
}


/*************************************Failed transactions*************************************/

int GetTxFailureListReqImpl(const std::shared_ptr<GetTxFailureListReq>& req, GetTxFailureListAck & ack)
{
    ack.set_version(global::kVersion);

    std::string addr = req->addr();
    uint32 index = 0;
    std::string txhash = req->txhash();
    uint32 count = req->count();
    DEBUGLOG("In HandleGetTxFailureListReq addr:{}, txhash:{}, count:{}", addr, txhash, count);

    if (addr.empty())
    {
        return -1;
    }

    if(!CheckBase58Addr(addr))
    {
        return -2;
    }
    
    std::vector<TranMonitor::FailureList> txs;
    MagicSingleton<TranMonitor>::GetInstance()->FindFailureList(addr, txs);

    std::vector<TranMonitor::t_VinSt> vectTx;
    for(auto iter = txs.begin();iter != txs.end();++iter)
    {
        TranMonitor::t_VinSt vectTx1;
        TranMonitor::t_VinSt::ConvertTx(iter->tx, 0, vectTx1,iter->timestamp);
        vectTx.push_back(vectTx1);
    }

    ack.set_total(vectTx.size());
    size_t size = vectTx.size();
    if (size == 0)
    {
        return -3;
    }

    if (txhash.empty())
    {
        index = 0;
    }
    else
    {
        size_t i = 0;
        for (; i < vectTx.size(); i++)
        {
            if (vectTx[i].txHash == txhash)
            {
                break ;
            }
        }
        if (i == vectTx.size())
        {
            return -4;
        }
        index = i + 1;
    }
    
    std::string lasthash;    
    if (index > (size - 1))
    {
        return -5;
    }

    size_t end = index + count;
    if (end > size)
    {
        end = size;
    }

    for (size_t i = index; i < end; i++)
    {
        TranMonitor::t_VinSt& iter = vectTx[i];

        TxFailureItem* txItem = ack.add_list();
        txItem->set_txhash(iter.txHash);
        DEBUGLOG("In HandleGetTxFailureListReq {}", iter.txHash);

        auto item = iter.identifies.begin();

        for( ; item != iter.identifies.end(); ++item)
        {
            txItem->add_fromaddr(item->first);
            auto start = item->second.begin();
            for( ; start != item->second.end(); ++start)
            {
                txItem->add_vins(*start);
            }
        }

        for (const auto& to : iter.to)
        {
            txItem->add_toaddr(to);
        }
        txItem->set_amount(iter.amount);
        txItem->set_time(iter.timestamp);
        txItem->set_detail("");
        txItem->set_gas(iter.gas);
        for (const auto& amount : iter.toAmount)
        {
            txItem->add_toamount(amount);
        }

        txItem->set_type(TxType(iter.type));
        lasthash = iter.txHash;
    }

    ack.set_lasthash(lasthash);
    ack.set_code(0);
    ack.set_message("success");

    return 0;

}

std::map<int32_t, std::string> GetTxFailureListReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get TxFailure List Success"), 
												std::make_pair(-1, "The addr is empty"), 
												std::make_pair(-2, "Base58 addr invalid"), 
												std::make_pair(-3, "No failure of the transaction."),
                                                std::make_pair(-4, "Not found the txhash."),
                                                std::make_pair(-5, "Index out of range."),
												};

	return errInfo;												
}
int HandleGetTxFailureListReq(const std::shared_ptr<GetTxFailureListReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetTxFailureListReqCode();
    GetTxFailureListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetTxFailureListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetTxFailureListReqImpl(req, ack);
    if (ret != 0)
    {
        return ret -= 10;
    }

    return ret;
}


/*************************************Query UTXO*************************************/
int GetUtxoReqImpl(const std::shared_ptr<GetUtxoReq>& req, GetUtxoAck & ack)
{
    ack.set_version(global::kVersion);

    string address = req->address();
    if (address.empty() || !CheckBase58Addr(address))
    {
        return -1;
    }

    ack.set_address(address);

    std::vector<TxHelper::Utxo> utxos;
    int ret = TxHelper::GetUtxos(address, utxos);
    if (ret != 0)
    {
        return ret -= 10;
    }

    for (auto & item : utxos)
    {
        Utxo* utxo = ack.add_utxos();
        utxo->set_hash(item.hash);
        utxo->set_value(item.value);
        utxo->set_n(item.n);
    }
    
    ack.set_code(0);
    ack.set_message("success");

    return 0;
}


std::map<int32_t, std::string> GetUtxoReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair( 0,  "Get Utxo Success"), 
												std::make_pair(-1,  "The addr is empty / Base58 addr invalid"), 
												std::make_pair(-12, "GetUtxos : GetUtxoHashsByAddress failed !"),
												};

	return errInfo;												
}
int HandleGetUtxoReq(const std::shared_ptr<GetUtxoReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetUtxoReqCode();
    GetUtxoAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetUtxoAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetUtxoReqImpl(req, ack);
    if (ret != 0)
    {
        return ret -= 100;
    }

    return 0;
}



/*************************************Query all investment accounts and amounts on the investee node*************************************/

int GetAllInvestAddressReqImpl(const std::shared_ptr<GetAllInvestAddressReq>& req, GetAllInvestAddressAck & ack)
{
    ack.set_version(global::kVersion);
    
    string address = req->addr();
    if (address.empty() || !CheckBase58Addr(address))
    {
        return -1;
    }

    ack.set_addr(address);

    DBReader db_reader;
    std::vector<std::string> addresses;
    auto db_status = db_reader.GetInvestAddrsByBonusAddr(address,addresses);
    if (db_status != DBStatus::DB_SUCCESS)
    {
        return -2;
    }

    if(addresses.size() == 0)
    {
        return -3;
    }

    for(auto& addr : addresses)
    {
        std::vector<std::string> utxos;
	    uint64_t total = 0;
        db_status = db_reader.GetBonusAddrInvestUtxosByBonusAddr(address,addr,utxos);
        if (db_status != DBStatus::DB_SUCCESS)
        {
            return -4;
        }
        for (auto &item : utxos) 
        {
            std::string strTxRaw;
            if (DBStatus::DB_SUCCESS != db_reader.GetTransactionByHash(item, strTxRaw))
            {
                return -5;
            }
            CTransaction utxoTx;
            utxoTx.ParseFromString(strTxRaw);
            for (auto &vout : utxoTx.utxo().vout())
            {
                if (vout.addr() == global::ca::kVirtualInvestAddr)
                {
                    total += vout.value();
                }
            }
        }
        
        InvestAddressItem * item = ack.add_list();
        item->set_addr(addr);
        item->set_value(total);
    }
    ack.set_code(0);
    ack.set_message("success");
    return 0;
}

std::map<int32_t, std::string> GetAllInvestAddressReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get AllInvestAddress Success"), 
												std::make_pair(-1, "The addr is empty / Base58 addr invalid"), 
												std::make_pair(-2, "GetInvestAddrsByBonusAddr failed !"), 
												std::make_pair(-3, "No Invested addrs !"),
                                                std::make_pair(-4, "GetBonusAddrInvestUtxos failed !"),
                                                std::make_pair(-5, "GetTransactionByHash failed !"),
												};

	return errInfo;												
}
int HandleGetAllInvestAddressReq(const std::shared_ptr<GetAllInvestAddressReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetAllInvestAddressReqCode();
    GetAllInvestAddressAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetAllInvestAddressAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetAllInvestAddressReqImpl(req, ack);
    if (ret != 0)
    {
        return ret -= 10;
    }

    return 0;
}


/*************************************Get all investable nodes*************************************/

int GetAllStakeNodeListReqImpl(const std::shared_ptr<GetAllStakeNodeListReq>& req, GetAllStakeNodeListAck & ack)
{
    ack.set_version(global::kVersion);

	std::vector<Node> nodelist;
    
	Node selfNode = MagicSingleton<PeerNode>::GetInstance()->get_self_node();
	std::vector<Node> tmp = MagicSingleton<PeerNode>::GetInstance()->get_nodelist();
	nodelist.insert(nodelist.end(), tmp.begin(), tmp.end());
	nodelist.push_back(selfNode);

    for (auto &node : nodelist)
	{
        StakeNode* pStakeNode =  ack.add_list();
        pStakeNode->set_addr(node.base58address);
        pStakeNode->set_name(node.name);
        pStakeNode->set_height(node.height);
        pStakeNode->set_identity(node.identity);
        pStakeNode->set_logo(node.logo);
        pStakeNode->set_ip(string(IpPort::ipsz(node.public_ip)) );
	}
    ack.set_code(0);
    ack.set_message("success");

    return 0;
}

std::map<int32_t, std::string> GetAllStakeNodeListReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get GetAllStakeNode List Success"), 
												std::make_pair(-1, "GetStakeAddress failed !"), 
												std::make_pair(-12, "GetStakeAddressUtxo failed !"), 
												std::make_pair(-21, "No failure of the transaction."),
                                                std::make_pair(-24, "GetBonusAddrInvestUtxos failed !"),
                                                std::make_pair(-25, "GetTransactionByHash failed !"),
												};

	return errInfo;												
}
int HandleGetAllStakeNodeListReq(const std::shared_ptr<GetAllStakeNodeListReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetAllStakeNodeListReqCode();
    GetAllStakeNodeListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetAllStakeNodeListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetAllStakeNodeListReqImpl(req, ack);
    if (ret != 0)
    {
        return ret -= 100;
    }

    return 0;
}


/*************************************Get a list of signatures*************************************/

int GetSignCountListReqImpl(const std::shared_ptr<GetSignCountListReq>& req, GetSignCountListAck & ack)
{
    ack.set_version(global::kVersion);

    std::string defaultAddr = MagicSingleton<AccountManager>::GetInstance()->GetDefaultBase58Addr();
    if (!CheckBase58Addr(defaultAddr))
    {
        return -1;
    }

    std::vector<std::string> abnormal_addr_list;
    std::unordered_map<std::string, uint64_t> addr_sign_cnt;
    uint64_t cur_time = MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    ca_algorithm::GetAbnormalSignAddrListByPeriod(cur_time, abnormal_addr_list, addr_sign_cnt);
    if(std::find(abnormal_addr_list.begin(), abnormal_addr_list.end(), defaultAddr) != abnormal_addr_list.end())
    {
        return -2;
    }

    for (auto & item : addr_sign_cnt)
    {
        SignCount* Sign_list =  ack.add_list();
        Sign_list->set_addr(item.first);
        Sign_list->set_count(item.second);
    }

    ack.set_code(0);
    ack.set_message("success");
    return 0;
}

std::map<int32_t, std::string> GetSignCountListReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get SignCountList List Success"), 
												std::make_pair(-1, "defaultAddr is invalid !"), 
												std::make_pair(-2, "GetBonusaddr failed !"), 
												std::make_pair(-3, "GetInvestAddrsByBonusAddr failed !"),
                                                std::make_pair(-4, "BounsdAddrs < 1 || BounsdAddrs > 999"),
                                                std::make_pair(-5, "GetBonusAddrInvestUtxosByBonusAddr failed !"),
                                                std::make_pair(-6, "GetTransactionByHash failed !"),
                                                std::make_pair(-7, "Parse tx failed !"),
                                                std::make_pair(-8, "Total amount invested < 5000 !"),
                                                std::make_pair(-9, "GetSignUtxoByAddr failed !"),
												};

	return errInfo;												
}
int HandleGetSignCountListReq(const std::shared_ptr<GetSignCountListReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetSignCountListReqCode();
    GetSignCountListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetSignCountListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetSignCountListReqImpl(req, ack);
    if (ret != 0)
    {
        return ret -= 10;
    }

    return 0;
}


/*************************************Calculate the commission*************************************/

int CalcGasReqImpl(const std::shared_ptr<CalcGasReq>& req, CalcGasAck & ack)
{
    ack.set_version(global::kVersion);
    
    uint64_t height = req -> height();
    if(height == 0)
    {
        DBReader db_reader;
        db_reader.GetBlockTop(height);
    }
    ack.set_height(height);
    ack.set_code(0);
    ack.set_message("successful!");
    
    return 0;
}

std::map<int32_t, std::string> CalcGasReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(    0, " CalcGas Success "),
                                                std::make_pair(-1001, " blockheight < cachelow || blockheight > cachehigh "),
                                                std::make_pair(-1002, " not find _height in cache "),
                                                std::make_pair(-1003, " one_minute > start_time "),
                                                std::make_pair(-1004, " no tx in cache "),
                                                std::make_pair(-1999, " CacheInit failed !"),
												};

	return errInfo;												
}
int HandleCalcGasReq(const std::shared_ptr<CalcGasReq>& req, const MsgData & msgdata)
{
    auto errInfo = CalcGasReqCode();
    CalcGasAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<CalcGasAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = CalcGasReqImpl(req, ack);
    if (ret != 0)
    {
        return ret -= 10000;
    }

    return 0;
}


/*************************************Check the current claim amount*************************************/

int GetBonusListReqImpl(const std::shared_ptr<GetBonusListReq> & req, GetBonusListAck & ack)
{
    ack.set_version(global::kVersion);

    std::string addr = req->bonusaddr();
    if(addr.size() == 0)
    {
        return -1;
    } 

    if (!CheckBase58Addr(addr))
    {
        return -2;
    }

    ack.set_bonusaddr(addr);
    uint64_t cur_time=MagicSingleton<TimeUtil>::GetInstance()->getUTCTimestamp();
    std::map<std::string, uint64_t> values;
    int ret = ca_algorithm::CalcBonusValue(cur_time, addr, values);
    if (ret != 0)
    {
        return ret -= 10;
    }

    for (auto & bonus : values)
    {
        BonusItem * item = ack.add_list();
        item->set_addr(bonus.first);
        item->set_value(bonus.second);
    }

    ack.set_code(0);
    ack.set_message("success");

    return 0;
}

std::map<int32_t, std::string> GetBonusListReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get Stake List Success !"), 
                                                std::make_pair(-1, "addr is empty !"),
                                                std::make_pair(-2, "base58 is invalid !"),
                                                std::make_pair(-11, "addr is AbnormalSignAddr !"),
                                                std::make_pair(-111, "GetInvestAddrsByBonusAddr failed !"),
                                                std::make_pair(-112, "GetBonusAddrInvestUtxosByBonusAddr failed!"),
                                                std::make_pair(-113, "GetTransactionByHash failed !"),
                                                std::make_pair(-114, "Parse Transaction failed !"),
                                                std::make_pair(-115, "GetInvestAndDivestUtxoByAddr failed !"),
                                                std::make_pair(-116, "GetTransactionByHash failed !"),
                                                std::make_pair(-117, "Parse Transaction failed !"),
                                                std::make_pair(-118, "Unknown transaction type !"),
                                                std::make_pair(-119, "mpInvestAddr2Amount is empty !"),
                                                std::make_pair(-211, "GetM2 failed !"),
                                                std::make_pair(-212, "GetBonusUtxo failed !"),
                                                std::make_pair(-213, "GetTransactionByHash failed !"),
                                                std::make_pair(-214, "Parse Transaction failed !"),
                                                std::make_pair(-311, "GetTotalInvestAmount failed !"),
                                                std::make_pair(-312, "GetAllInvestUtxo failed !"),
                                                std::make_pair(-313, "GetTransactionByHash failed !"),
                                                std::make_pair(-314, "Parse Transaction failed !"),

											};

	return errInfo;												
}

int HandleGetBonusListReq(const std::shared_ptr<GetBonusListReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetBonusListReqCode();
    GetBonusListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetBonusListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetBonusListReqImpl(req, ack);
    if (ret != 0)
    {
        return ret -= 1000;
    }

    return 0;
}
int GetTransactionStatusReqImpl(const std::shared_ptr<GetTransactionStatusListReq> & req, GetTransactionStatusListAck & ack,std::map<int32_t, std::string> &errInfostatus)
{
    ack.set_version(global::kVersion);
    TransactionStatusItem * item  = ack.mutable_list();
    OtherStatusItem *otheritem = item->add_othernode();
    SelfVerifyStatusItem  * verifyothernode = item->add_verifyothernode();
    std::map<std::string,TranMonitor::TranMonSt> Status = MagicSingleton<TranMonitor>::GetInstance()->GetTranStatus();
    for (auto &tx: Status)
    { 
        if(tx.second.Tx.hash() == req->txhash())
        {
            for(auto &i : errInfostatus)
            {
                if(tx.second.LaunchTime.first == i.first)
                {
                    item->set_initiatortime(tx.second.LaunchTime.second);
                    item->set_selfcode(tx.second.LaunchTime.first);
                    item->set_initiatormessage(i.second);
                }
            }
     
            if(!tx.second._MonNodeDoHandleAck.empty())
            {
                for(auto &i : errInfostatus)
                {
                    for(auto &ack : tx.second._MonNodeDoHandleAck)
                    {
                        if(i.first == ack.first)
                        {
                            otheritem->set_othernodetime(ack.second);
                            otheritem->set_othernodecode(ack.first );
                            otheritem->set_othernodemessage(i.second);                  
                        }
                    }
                }

            }
            item->set_composetime(tx.second._ComposeStatusTime);
            if(!tx.second._SelfDohandleCount.empty())
            {
                for(auto &i : errInfostatus)
                {
                    for(auto &ack : tx.second._SelfDohandleCount)
                    {
                        if(i.first == ack.first)
                        {
                            verifyothernode->set_verifyothernodetime(ack.second);
                            verifyothernode->set_verifyothernodecode(ack.first );
                            verifyothernode->set_verifyothernodemessage(i.second);                  
                        }
                    }
                }
            }
            
            if(tx.second._BroadCastAck.second != 1)
            {
                item->set_selfeaddblockmessage("It is uncertain whether the block adding is successful");
            }
            else if(tx.second._BroadCastAck.second == 1)
            {
                item->set_selfaddblocktime(tx.second._BroadCastAck.first);
                item->set_selfeaddblockmessage("Add block success");
            }
            item->set_removependingtime(tx.second._VinRemoveTime);  
         }    
    }
    return 0;
}
std::map<int32_t, std::string> GetTransactionStatusReqCode()
{
	std::map<int32_t, std::string> errInfo = {  
												
};

return errInfo;												
}

std::map<int32_t, std::string> GetReqCode()
{
	std::map<int32_t, std::string> errInfo = {  std::make_pair(0, "Get  List Success"), 
												std::make_pair(-1, "version unCompatible"), 
												};
	return errInfo;												
}


int HandleTransactionStatusListReq(const std::shared_ptr<GetTransactionStatusListReq>& req, const MsgData & msgdata)
{
    auto errInfo = GetReqCode();
    auto errStatus = GetTransactionStatusReqCode();
    GetTransactionStatusListAck ack;
    int ret = 0;

    ON_SCOPE_EXIT{
        ReturnAckCode<GetTransactionStatusListAck>(msgdata, errInfo, ack, ret);
    };

    if( 0 != Util::IsVersionCompatible( req->version() ) )
	{
		return ret = -1;
	}

    ret = GetTransactionStatusReqImpl(req, ack,errStatus);
    return ret;
}

void RegisterInterface()
{
    net_register_callback<GetBlockReq>(HandleGetBlockReq);
    net_register_callback<GetBalanceReq>(HandleGetBalanceReq);
    net_register_callback<GetNodeInfoReq>(HandleGetNodeInfoReqReq);
	net_register_callback<GetStakeListReq>(HandleGetStakeListReq);
	net_register_callback<GetInvestListReq>(HandleGetInvestListReq);
    net_register_callback<GetTxPendingListReq>(HandleGetTxPendingListReq);
    net_register_callback<GetTxFailureListReq>(HandleGetTxFailureListReq);
    net_register_callback<GetUtxoReq>(HandleGetUtxoReq);
    net_register_callback<GetAllInvestAddressReq>(HandleGetAllInvestAddressReq);
    net_register_callback<GetAllStakeNodeListReq>(HandleGetAllStakeNodeListReq);
    net_register_callback<GetSignCountListReq>(HandleGetSignCountListReq);
    net_register_callback<CalcGasReq>(HandleCalcGasReq);
    net_register_callback<GetBonusListReq>(HandleGetBonusListReq);
    net_register_callback<GetTransactionStatusListReq>(HandleTransactionStatusListReq);
}

