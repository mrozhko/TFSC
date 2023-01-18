#ifndef CA_VM_INTERFACE_H
#define CA_VM_INTERFACE_H

#include <evmc/evmc.hpp>
#include "utils/json.hpp"
#include "ca_global.h"
#include "ca_txhelper.h"
class VmInterface
{
public:
    enum VmType
    {
        EVM,
        WASM
    };


    virtual int CreateDeployContractTransaction(const std::string & fromAddr,
											uint64_t deploy_amount,
                                            uint64_t height,
                                            CTransaction &outTx,
                                            TxHelper::vrfAgentType &type,
                                            Vrf & info_,
                                            const std::string& OwnerEvmAddr = "") = 0;
    virtual int CreateCallContractTransaction(const std::string & fromAddr,
											const std::string & toAddr,
											const std::string & txHash,											
											const std::string & strInput,
											uint64_t call_amount,
											uint64_t height,
											CTransaction & outTx,
                                            TxHelper::vrfAgentType &type,
                                            Vrf & info_,
                                            const std::string& OwnerEvmAddr = "") = 0;

protected:
    int FillExecuteOutTx(const std::string & fromAddr,
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
                        Vrf & info_);
    int FillOutTx(const std::string & fromAddr,
                    const std::string & toAddr,
                    nlohmann::json& jTxInfo,
                        uint64_t amount,
                        uint64_t height,
                        uint64_t &gas,
                        uint64_t& cost,
                        CTransaction &outTx,
					    const std::vector<std::pair<std::string, uint64_t>>& transferrings,
					    const std::vector<std::pair<std::string, uint64_t>>& payment,
                        TxHelper::vrfAgentType &type,
                        Vrf & info_);
    int FillOutTxDataAndHashField(
                                    uint64_t height,
                                    const uint64_t &gas,
                                    uint64_t cost,
                                    global::ca::TxType tx_type,
                                    CTransaction &outTx);
                                    
    int FillExecuteOutTxDataAndHashField(
                                        uint64_t height,
                                        const uint64_t &gas,
                                        uint64_t cost,
                                        CTransaction &outTx);

};

#endif