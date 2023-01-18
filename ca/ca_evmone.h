#ifndef __CA_EVMONE_H__
#define __CA_EVMONE_H__

#include <string>
#include <unordered_map>

#include <evmc/evmc.hpp>


#include <ca_DonHost.hpp>

#include "ca_vm_interface.h"

// class DonHost;
class Evmone : public VmInterface
{

private:
    std::string code_;
    VmType type_;

public:
    Evmone();
    Evmone(std::string code);

    int CreateDeployContractTransaction(const std::string & fromAddr,
											uint64_t deploy_amount,
                                            uint64_t height,
                                            CTransaction &outTx,
                                            TxHelper::vrfAgentType &type,
                                            Vrf & info_,
                                            const std::string& OwnerEvmAddr);

    int CreateCallContractTransaction(const std::string & fromAddr,
                                        const std::string & toAddr,
                                        const std::string & txHash,											
                                        const std::string & strInput,
                                        uint64_t call_amount,
                                        uint64_t height,
                                        CTransaction & outTx,
                                        TxHelper::vrfAgentType &type,
                                        Vrf & info_,
                                        const std::string& OwnerEvmAddr);
    // Contract related
    static int DeployContract(const std::string& OwnerEvmAddr,
                    const std::string& strInput,
                    std::string& strOutput,
                    DonHost& host);
    static int CallContract(const std::string& OwnerEvmAddr,
                    const std::string& strDeployer,
                    const std::string& strDeployHash,
                    const std::string& strInput,
                    std::string& strOutput,
                    DonHost& host);
    static void getStorage(const DonHost& host, nlohmann::json& jStorage);

private:
    int GenContractDeployOutput(const std::string& OwnerEvmAddr,
                                    uint64_t deploy_amount, 
                                    nlohmann::json& jTxInfo,
                                    std::vector<std::pair<std::string, uint64_t>>& transferrings,
                                    std::vector<std::pair<std::string, uint64_t>>& call_amount);
    int GenContractExecuteOutput(const std::string& OwnerEvmAddr,
                                    const std::string& fromAddr,
                                    const std::string& toAddr,
                                    const std::string& txHash,
                                    const std::string& strInput,
                                    nlohmann::json& jTxInfo, 
                                    std::vector<std::pair<std::string, uint64_t>>& transferrings,
                                    std::vector<std::pair<std::string, uint64_t>>& call_amount);
    static int ContractInfoAdd(const DonHost& host, nlohmann::json& jTxInfo, global::ca::TxType TxType);

};
// Test demos
void test_address_mapping();
#endif
