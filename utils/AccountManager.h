#ifndef _EDManager_
#define _EDManager_

#include <iostream>
#include <string>
#include <dirent.h>

#include "base58.h"
#include "hexcode.h"
#include "utils/time_util.h"
#include "MagicSingleton.h"
#include "../ca/ca_global.h"
#include "../include/logging.h"
#include "utils/sha3_256.h"
#include "utils/pbkdf2.h"
#include "utils/json.hpp"
#include "utils/bip39.h"
#include "utils/uuid4.h"

#include "../openssl/include/openssl/evp.h"
#include "../openssl/include/openssl/ec.h"
#include "../openssl/include/openssl/pem.h"
#include "../openssl/include/openssl/core_names.h"

class Account
{
    public:
        Account();
        Account(Base58Ver ver);
        Account(const std::string &bs58Addr);
        ~Account() = default;

        bool Sign(const std::string &message, std::string &signature);
        bool Verify(const std::string &message, std::string &signature);

    private:
        void _GetPubStr();
        void _GetPriStr();
        void _GetBase58Addr(Base58Ver ver);

    public:
        EVP_PKEY *pkey;
        std::string pubStr;
        std::string priStr;
        std::string base58Addr;
    
};

class AccountManager
{
    public:
        AccountManager();
        ~AccountManager() = default;

        int AddAccount(Account & ed);
        void PrintAllAccount() const;
        int DeleteAccount(const std::string& base58addr);
        void SetDefaultBase58Addr(const std::string & bs58Addr);
        std::string GetDefaultBase58Addr() const;
        int SetDefaultAccount(const std::string & bs58Addr);
        bool IsExist(const std::string & bs58Addr);
        int GetAccountListSize() const;
        int FindAccount(const std::string & bs58Addr, Account & ed);
        int GetDefaultAccount(Account & ed);
        void GetAccountList(std::vector<std::string> & base58_list);
        int SavePrivateKeyToFile(const std::string & base58Addr);

        int GetMnemonic(const std::string & bs58Addr, std::string & mnemonic);
        int ImportMnemonic(const std::string & mnemonic);
        
        int GetPrivateKeyHex(const std::string & bs58Addr, std::string & privateKeyHex);
        int ImportPrivateKeyHex(const std::string & privateKeyHex);

        int GetKeyStore(const std::string & bs58Addr, const std::string pwd, std::string & keyStore);
        int ImportKeyStore(const std::string & keyStore, const std::string pwd);


    private:
        std::string defaultBase58Addr;
        std::map<std::string /*base58addr*/,Account> _accountList;
        
        int _init();
};

int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
               unsigned char *iv, unsigned char *ciphertext);
int Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
               unsigned char *iv, unsigned char *plaintext);
std::string RandGenerateString(int len); 

std::string getsha256hash(const std::string & text);

bool ED25519SignMessage(const std::string &message, EVP_PKEY* pkey, std::string &signature);
bool ED25519VerifyMessage(const std::string &message, EVP_PKEY* pkey, const std::string &signature);

bool GetEDPubKeyByBytes(const std::string &pubStr, EVP_PKEY* &pKey);

#endif
