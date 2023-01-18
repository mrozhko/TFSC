#ifndef _CA_CCALBLOCKGas_H_
#define _CA_CCALBLOCKGas_H_


#include "ca_blockcache.h"
#include "db/db_api.h"
#include "../include/logging.h"
#include "ca_transaction.h"
#include "ca_global.h"

class CCalBlockGas : public CCalBlockCacheInterface
{
public:
   explicit CCalBlockGas(uint64_t blockheight) : _height(blockheight), _gas(64)
   {

   }
    int Process(const std::map<uint64_t, std::set<CBlock, CBlockCompare>> & cache)
    {
        uint64_t cacheHigh = cache.rbegin()->first;
        uint64_t cacheLow = cache.begin()->first;
        if(_height > cacheHigh || _height < cacheLow)
        {
            return -1;
        }

        _height = _height > kPrevBlockHeight ? _height - kPrevBlockHeight : 0;
        

        auto heightIter = cache.find(_height);
        if (heightIter == cache.end())
        {
            return -2;
        }


        _gas = 0;
        for(auto it = cache.rbegin();it != cache.rend(); ++it)
        {
            if (it->first > _height)
            {
                continue;
            }

            for (auto sit = it->second.begin(); sit != it->second.end(); ++sit)
            {

                    for(auto & tx : sit->txs())
                    {
                        TransactionType tx_type = GetTransactionType(tx);
                        if(tx_type == kTransactionType_Genesis || tx_type == kTransactionType_Tx )
                        {
                            uint64_t utxo_size = 0;
                            const CTxUtxo & utxo = tx.utxo();
                            for (auto & owner : utxo.owner())
                            {
                                utxo_size += owner.size();
                            }

                            for (auto & vin : utxo.vin())
                            {
                                for (auto & prevout : vin.prevout())
                                {
                                    utxo_size += prevout.hash().size() + 4;
                                }

                                utxo_size += vin.vinsign().sign().size() + vin.vinsign().pub().size();
                                utxo_size += 4;
                            }

                            for (auto & vout : utxo.vout())
                            {
                                utxo_size += 8 + vout.addr().size();
                            }


                            _gas += utxo_size;
                            _gas += tx.type().size() + tx.data().size() + tx.info().size();


                            _gas += tx.reserve0().size() + tx.reserve1().size();
                        }
                    } 
                
            }
        }

        _gas *= 2;

        if (_gas == 0)
        {
            return -4;
        }
        
        return 0;
    }

    uint64_t Gas() const
    {
        return _gas;
    }

    static const uint32_t kPrevBlockHeight = 100;

private:
    uint64_t _gas;
    uint64_t _height;
};



#endif