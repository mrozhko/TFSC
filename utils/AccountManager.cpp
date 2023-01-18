#include "AccountManager.h"


Account::Account()
{
    pkey = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if(ctx == nullptr)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    if(EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "keygen init fail" << std::endl;
    }

    if(EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "keygen fail\n" << std::endl;
    }

    _GetPubStr();
    _GetPriStr();
    _GetBase58Addr(Base58Ver::kBase58Ver_Normal);
    EVP_PKEY_CTX_free(ctx);
}

Account::Account(Base58Ver ver)
{
    pkey = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if(ctx == nullptr)
    {
        EVP_PKEY_CTX_free(ctx);
    }

    if(EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "keygen init fail" << std::endl;
    }

    if(EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        std::cout << "keygen fail\n" << std::endl;
    }

    _GetPubStr();
    _GetPriStr();
    _GetBase58Addr(ver);
    EVP_PKEY_CTX_free(ctx);
}

static const std::string EDCertPath = "./cert/";
Account::Account(const std::string &bs58Addr)
{
    std::string priFileFormat = EDCertPath + bs58Addr + ".private";
    const char * priPath = priFileFormat.c_str();

    //Read public key from PEM file
    BIO* priBioFile = BIO_new_file(priPath, "rb");

    pkey = PEM_read_bio_PrivateKey(priBioFile, NULL, 0, NULL);
    if (!pkey)  
    {
        printf("Error：PEM_write_bio_EC_PUBKEY err\n");
        return ;
    }
    if(priBioFile != NULL) BIO_free(priBioFile);

    base58Addr = bs58Addr;

    _GetPubStr();
    _GetPriStr();
}


bool Account::Sign(const std::string &message, std::string &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    const char * sig_name = message.c_str();

    unsigned char *sig_value = NULL;
    size_t sig_len = strlen(sig_name);

    // Create the Message Digest Context 
    if(!(mdctx = EVP_MD_CTX_new())) 
    {
        return false;
    }

    if(pkey == NULL)
    {
        return false;
    }
    
    // Initialise the DigestSign operation
    if(1 != EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey)) 
    {
        return false;
    }

    size_t tmpMLen = 0;
    if( 1 != EVP_DigestSign(mdctx, NULL, &tmpMLen, (const unsigned char *)sig_name, sig_len))
    {
        return false;
    }

    sig_value = (unsigned char *)OPENSSL_malloc(tmpMLen);

    if( 1 != EVP_DigestSign(mdctx, sig_value, &tmpMLen, (const unsigned char *)sig_name, sig_len))
    {
        return false;
    }

    std::string hashString((char*)sig_value, tmpMLen);
    signature = hashString;

    OPENSSL_free(sig_value);
    EVP_MD_CTX_free(mdctx);
    return true;
}

bool Account::Verify(const std::string &message, std::string &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    const char *msg = message.c_str();
    unsigned char *sig = (unsigned char *)signature.data();
    size_t slen = signature.size();
    size_t msg_len = strlen(msg);

    if(!(mdctx = EVP_MD_CTX_new())) 
    {
        return false;
    }

    /* Initialize `key` with a public key */
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey)) 
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (1 != EVP_DigestVerify(mdctx, sig, slen ,(const unsigned char *)msg, msg_len)) 
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);
    return true;
}

void Account::_GetPubStr()
{
    //     The binary of the resulting public key is stored in a string serialized
    unsigned char *pkey_der = NULL;
    int publen = i2d_PUBKEY(pkey ,&pkey_der);

    for(int i = 0; i < publen; ++i)
    {
        pubStr += pkey_der[i];
    }
}

void Account::_GetPriStr()
{

    size_t len = 80;
    char pkey_data[80] = {0};
    if( EVP_PKEY_get_raw_private_key(pkey, (unsigned char *)pkey_data, &len) == 0)
    {
        return;
    }

    std::string data(pkey_data);
    priStr = data;
}


void Account::_GetBase58Addr(Base58Ver ver)
{
    base58Addr = GetBase58Addr(pubStr, ver);
}

AccountManager::AccountManager()
{
    _init();
}

int AccountManager::AddAccount(Account & ed)
{
    auto iter = _accountList.find(ed.base58Addr);
    if(iter != _accountList.end())
    {
        std::cout << "bs58Addr repeat" << std::endl;
        return -1;
    }

    _accountList.insert(make_pair(ed.base58Addr, ed));
    return 0;
}

void AccountManager::PrintAllAccount() const
{
    auto iter = _accountList.begin();
    while(iter != _accountList.end())
    {
        if (iter->first == defaultBase58Addr)
        {
            std::cout << iter->first << " [default]" << std::endl;
        }
        else
        {
            std::cout << iter->first << std::endl;
        }
        ++iter;
    }
}

int AccountManager::DeleteAccount(const std::string& base58addr)
{
    auto iter = _accountList.find(base58addr);
    if (iter == _accountList.end()) 
    {
        std::cout << "Failed to get key from " << base58addr << "..." << std::endl;
        return -1;
    }

    EVP_PKEY_free(_accountList.at(base58addr).pkey);
    _accountList.erase(iter);
    std::cout << "Deleted " << base58addr << " from storage..." << std::endl;

    return 0;
}

void AccountManager::SetDefaultBase58Addr(const std::string & bs58Addr)
{
    defaultBase58Addr = bs58Addr;
}

std::string AccountManager::GetDefaultBase58Addr() const
{
    return defaultBase58Addr;
}

int AccountManager::SetDefaultAccount(const std::string & bs58Addr)
{
    if (_accountList.size() == 0)
    {
        return -1;
    }

    if (bs58Addr.size() == 0)
    {
        defaultBase58Addr = _accountList.begin()->first;
        return 0;
    }

    auto iter = _accountList.find(bs58Addr);
    if(iter == _accountList.end())
    {
        ERRORLOG("not found bs58Addr {} in the _accountList ",bs58Addr);
        return -2;
    }
    defaultBase58Addr = bs58Addr;
    
    return 0;
}

bool AccountManager::IsExist(const std::string & bs58Addr)
{
    auto iter = _accountList.find(bs58Addr);
    if(iter == _accountList.end())
    {
        ERRORLOG("not found bs58Addr {} in the _accountList ",bs58Addr);
        return false;
    }
    return true;
}

int AccountManager::GetAccountListSize() const
{
    return _accountList.size();
}

int AccountManager::FindAccount(const std::string & bs58Addr, Account & ed)
{
    auto iter = _accountList.find(bs58Addr);
    if(iter == _accountList.end())
    {
        ERRORLOG("not found bs58Addr {} in the _accountList ",bs58Addr);
        return -1;
    }
    ed = iter->second;

    return 0;
}

int AccountManager::GetDefaultAccount(Account & ed)
{
    auto iter = _accountList.find(defaultBase58Addr);
    if(iter == _accountList.end())
    {
        ERRORLOG("not found DefaultKeyBs58Addr {} in the _accountList ", defaultBase58Addr);
        return -1;
    }
    ed = iter->second;

    return 0;
}

void AccountManager::GetAccountList(std::vector<std::string> & base58_list)
{
    auto iter = _accountList.begin();
    while(iter != _accountList.end())
    {
        base58_list.push_back(iter->first);
        iter++;
    }
}

int AccountManager::SavePrivateKeyToFile(const std::string & base58Addr)
{
    std::string priFileFormat = EDCertPath + base58Addr +".private";
    const char * path =  priFileFormat.c_str();

    Account ed;
    EVP_PKEY_free(ed.pkey);
    if(FindAccount(base58Addr, ed) != 0)
    {
        ERRORLOG("SavePrivateKeyToFile find account fail: {}", base58Addr);
        return -1;
    }

    //Store the private key to the specified path
    BIO* priBioFile = BIO_new_file(path, "w");

    if (!priBioFile)
    {
        printf("Error：pBioFile err \n");
        return -2;
    }

    if (!PEM_write_bio_PrivateKey(priBioFile, ed.pkey, NULL, NULL, 0, NULL, NULL))  // Write to the private key
    {
        printf("Error：PEM_write_bio_ECPrivateKey err\n");
        return -3;
    }

    BIO_free(priBioFile);
    return 0;
}

int AccountManager::GetMnemonic(const std::string & bs58Addr, std::string & mnemonic)
{
    Account account;
    Account defaultAccount;
    if(!FindAccount(bs58Addr, account))
    {
        GetDefaultAccount(defaultAccount);
        account = defaultAccount;
    }
    
    if(account.priStr.size() <= 0)
    {
        return 0;
    }

    char out[1024]={0};

    int ret = mnemonic_from_data((const uint8_t*)account.priStr.c_str(), account.priStr.size(), out, 1024); 
    std::string data(out);
    mnemonic = data;
    return ret;
}

int AccountManager::ImportMnemonic(const std::string & mnemonic)
{
    char out[33] = {0};
    int outLen = 0;
	if(mnemonic_check((char *)mnemonic.c_str(), out, &outLen) == 0)
    {
        return -1;
    }

    char mnemonic_hex[65] = {0};
	encode_hex(mnemonic_hex, out, outLen);

	std::string mnemonic_key;
	mnemonic_key.append(mnemonic_hex, outLen * 2);

    ImportPrivateKeyHex(mnemonic_key);
    

    return 0;
}

int AccountManager::GetPrivateKeyHex(const std::string & bs58Addr, std::string & privateKeyHex)
{
    Account account;
    Account defaultAccount;

    if(!FindAccount(bs58Addr, account))
    {
        GetDefaultAccount(defaultAccount);
        account = defaultAccount;
    }

	if(account.priStr.size() <= 0)
    {
        return -1;
    }
	
    unsigned int privateKeyLen = sizeof(privateKeyHex);
	if(privateKeyHex.empty() || privateKeyLen < account.priStr.size() * 2)
    {
        privateKeyLen = account.priStr.size() * 2;
        return -2;
    }
	
    std::string strPriHex = Str2Hex(account.priStr);
    privateKeyHex = strPriHex;
    EVP_PKEY_free(account.pkey);
    EVP_PKEY_free(defaultAccount.pkey);
    
    return 0;
}

int AccountManager::ImportPrivateKeyHex(const std::string & privateKeyHex)
{
    std::string priStr_ = Hex2Str(privateKeyHex);
    std::string pubStr_;
    unsigned char* buf_ptr = (unsigned char *)priStr_.data();
    const unsigned char *pk_str = buf_ptr;

    EVP_PKEY * pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, pk_str, priStr_.size());
    if(pkey == nullptr)
    {
        return -1;
    }

    Account ed;
    GetDefaultAccount(ed);
    if(EVP_PKEY_eq(pkey,ed.pkey))
    {
        std::cout << "is equal" << std::endl;
    }

    unsigned char *pkey_der = NULL;
    int publen = i2d_PUBKEY(pkey ,&pkey_der);

    for(int i = 0; i < publen; ++i)
    {
        pubStr_ += pkey_der[i];
    }

    std::string base58Addr = GetBase58Addr(pubStr_, Base58Ver::kBase58Ver_Normal);
    Account acc;
    EVP_PKEY_free(acc.pkey);
    acc.pkey = pkey;
    acc.pubStr = pubStr_;
    acc.priStr = priStr_; 
    acc.base58Addr = base58Addr;

    std::cout << "final pubStr " << Str2Hex(acc.pubStr) << std::endl;
    std::cout << "final priStr" << Str2Hex(acc.priStr) << std::endl;

    MagicSingleton<AccountManager>::GetInstance()->AddAccount(acc);
    int ret =  MagicSingleton<AccountManager>::GetInstance()->SavePrivateKeyToFile(acc.base58Addr);
    if(ret != 0)
    {
        ERRORLOG("SavePrivateKey failed!");
        return -2;
    }

	return 0;
}

int AccountManager::GetKeyStore(const std::string & bs58Addr, const std::string pwd, std::string & keyStore)
{
    if(keyStore.empty())
    {
        return -1;
    }

    std::string _iv = RandGenerateString(16);
	unsigned char iv[17] = {0};
    memcpy(iv, _iv.c_str(), 32);
    
	int json_version = 1;
	int kdfparams_c = 10240;
	int kdfparams_dklen = 32;
	int kdfparams_salt_len = 32;
	const char *kdfparams_prf = "hmac-sha256";
	const char *cipher = "aes-128-ctr";
	const char *kdf = "pbkdf2";
	char key[33] = {0};

    unsigned char salt[33] = {0};
	std::string _salt = RandGenerateString(32);
    memcpy(salt, _salt.c_str(), 32);

	pbkdf2_hmac_sha256((const uint8_t *)pwd.c_str(), strlen(pwd.c_str()), (uint8_t*)salt, kdfparams_salt_len, kdfparams_c, (uint8_t*)key, kdfparams_dklen, NULL);	

	unsigned char encKey[17] = {0};
	int keysize = 16;
	memcpy(encKey, key, 16);


    Account acc;
    Account defaultAccount;
    if(!FindAccount(bs58Addr, acc))
    {
        GetDefaultAccount(defaultAccount);
        acc = defaultAccount;
    }

    EVP_PKEY_free(acc.pkey);
    EVP_PKEY_free(defaultAccount.pkey);

	std::string strEncTxt;
    std::string strDecTxt;
	std::string message = acc.priStr;
	
	if(message.size()<=0)	
		return -2;

    Encrypt((unsigned char *)message.data(), message.size(), encKey, iv, (unsigned char *)strEncTxt.data());
/**
    string  cipher;
	StringSource ss2( strEncTxt, true, new HexEncoder( new StringSink( cipher)));
    cout << "cipher text: " << cipher << endl;

**/
	
	std::string macstr;
	macstr.append(key, 32);
	macstr.append(strEncTxt.c_str(), strEncTxt.size());

	sha3_256_t sha3_256;
    sha3_256_t::sha3_256_item_t sha3_256_item;
    sha3_256.open(&sha3_256_item);
    sha3_256.update(macstr.c_str(), macstr.size());
    sha3_256.close();
	
	std::string json_address = acc.base58Addr;

    std::string str_iv;
    for(auto iter : iv)
    {
        str_iv.push_back(iter);
    }

    std::string json_iv = Str2Hex(str_iv);

	std::string json_ciphertext = Str2Hex(strEncTxt);	

    std::string str_salt;
    for(auto iter : salt)
    {
        str_salt.push_back(iter);
    }

	std::string  json_salt = Str2Hex(str_salt);	

    std::string str_sha3;
    for(auto iter : sha3_256_item)
    {
        str_sha3.push_back(iter);
    }

	std::string  json_mac = Str2Hex(str_sha3);	

	char json_uuid[UUID4_LEN] = {0};
	uuid4_init();
	uuid4_generate(json_uuid);
/** json **/
	nlohmann::json root;
	nlohmann::json crypto;
	nlohmann::json cipherparams;
	nlohmann::json kdfparams;

	//root
	root["address"] = json_address.c_str();
	root["version"] =json_version;
	root["id"] = json_uuid;

	//crypto
	crypto["cipher"] = cipher;
	crypto["ciphertext"] = json_ciphertext.c_str();
	crypto["kdf"] = kdf;
	crypto["mac"] = json_mac.c_str();

	//cipherparams
	cipherparams["iv"] = json_iv.c_str();

	//kdfparams
	kdfparams["salt"] = json_salt.c_str();
	kdfparams["prf"] = kdfparams_prf;
	kdfparams["c"] = kdfparams_c;
	kdfparams["dklen"] = kdfparams_dklen;
	
	crypto["cipherparams"] = cipherparams;
	crypto["kdfparams"] = kdfparams;
	root["crypto"] =  crypto;

    std::string json_keystore = root.dump(4);
    if(sizeof(keyStore) < json_keystore.size())
        return -3;
    keyStore = json_keystore;
    int iReturnLen = json_keystore.size();

    return iReturnLen;
}

int AccountManager::ImportKeyStore(const std::string & keyStore, const std::string pwd)
{

    int version = 1;
	int kdfparams_c = 0;
	int kdfparams_dklen = 0;
	const char *kdfparams_prf = "hmac-sha256";
	const char *cipher = "aes-128-ctr";
	const char *kdf = "pbkdf2";
	char key[33] = {0};

	unsigned char encKey[17] = {0};
	int keysize = 16;

	std::string macstr;
	sha3_256_t sha3_256;
    sha3_256_t::sha3_256_item_t sha3_256_item;

	std::string strEncTxt;
    std::string strDecTxt;

    std::string cipherparams_iv;
	std::string ciphertext;
	std::string kdfparams_salt;
	std::string mac;
	std::string address;

	nlohmann::json root = NULL;	
	nlohmann::json crypto =  NULL;
	nlohmann::json cipherparams =  NULL;
	nlohmann::json kdfparams =  NULL;
	nlohmann::json item = NULL;

	root = nlohmann::json::parse(keyStore);

	crypto = root["crypto"];
	cipherparams = crypto["cipherparams"];
	kdfparams = crypto["kdfparams"];

	item = root["version"];
	if(version != item.get<int>())
	{
		return false;
	}

	item = crypto["cipher"];
	if(memcmp(item.get<std::string>().c_str(), cipher, strlen(cipher)))
	{
		return false;
	}


	item = crypto["kdf"];
	if(memcmp(item.get<std::string>().c_str(), kdf, strlen(kdf)))
	{
		return false;
	}

	item = kdfparams["prf"];
	if(memcmp(item.get<std::string>().c_str(), kdfparams_prf, strlen(kdfparams_prf)))
	{
		return false;
	}

	item = kdfparams["c"];
	kdfparams_c = item.get<int>();

	item = kdfparams["dklen"];
	kdfparams_dklen = item.get<int>();

	item = cipherparams["iv"];
	cipherparams_iv = Hex2Str(item.get<std::string>());

	item = crypto["ciphertext"];
	ciphertext = Hex2Str(item.get<std::string>());

	item = crypto["mac"];
	mac = Hex2Str(item.get<std::string>());
	
	item = kdfparams["salt"];
	kdfparams_salt = Hex2Str(item.get<std::string>());

	item = root["address"];
	address = Hex2Str(item.get<std::string>());
	
	pbkdf2_hmac_sha256((const uint8_t *)pwd.c_str(), strlen(pwd.c_str()), (uint8_t*)kdfparams_salt.c_str(), 
                        sizeof(kdfparams_salt), kdfparams_c, (uint8_t*)key, kdfparams_dklen, NULL);	

//mac
	macstr.append(key, 32);
    macstr.append(ciphertext.c_str(), strlen(ciphertext.c_str()));

    sha3_256.open(&sha3_256_item);
    sha3_256.update(macstr.c_str(), macstr.size());
    sha3_256.close();
	
	if(sizeof(mac) != sizeof(sha3_256_item) || memcmp(mac.c_str(), &sha3_256_item, sizeof(sha3_256_item)))
	{
		return false;
	}

	memcpy(encKey, key, 16);

	strEncTxt.append(ciphertext.c_str(), sizeof(ciphertext));

    Decrypt((unsigned char *)strEncTxt.data(), strEncTxt.size(), encKey, (unsigned char *)cipherparams_iv.data(), (unsigned char *)strDecTxt.data());

	hex_print((unsigned char *)strDecTxt.c_str(), strDecTxt.size());

    //return KeyFromPrivate(strDecTxt.c_str(), strDecTxt.size());
    return 0;
}

std::string getsha256hash(const std::string & text)
{
	unsigned char mdStr[65] = {0};
	SHA256((const unsigned char *)text.c_str(), text.size(), mdStr);
 
	char buf[65] = {0};
	char tmp[3] = {0};
	for (int i = 0; i < 64; i++)
	{
		sprintf(tmp, "%02x", mdStr[i]);
		strcat(buf, tmp);
	}
	buf[64] = '\0'; 

    std::string encodedHexStr = std::string(buf);
    return encodedHexStr;
}

int AccountManager::_init()
{
    std::string path = EDCertPath;
    if(access(path.c_str(), F_OK))
    {
        if(mkdir(path.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH))
        {
            assert(false);
            return -1;
        }
    }

    DIR *dir;
    struct dirent *ptr;

    if ((dir = opendir(path.c_str())) == NULL)
    {
		ERRORLOG("OPEN DIR  ERROR ..." );
		return -2;
    }

    while ((ptr = readdir(dir)) != NULL)
    {
        if(strcmp(ptr->d_name,".") == 0 || strcmp(ptr->d_name, "..") ==0)
		{
            continue;
		}
        else
        {
            std::string filename(ptr->d_name);
            if (filename.size() == 0)
            {
                return -3;
            }

            Base58Ver ver;
            if (filename[0] == '1')
            {
                ver = Base58Ver::kBase58Ver_Normal;
            }
            else if (filename[0] == '3')
            {
                ver = Base58Ver::kBase58Ver_MultiSign;
            }
            else
            {
                return -4;
            }
            
            int index = filename.find('.');
            std::string bs58Addr = filename.substr(0, index);
            Account ed(bs58Addr);
            if(AddAccount(ed) != 0)
            {
                return -5;
            }

        }
    }
    closedir(dir);

    if(_accountList.size() == 0)
    {
        Account ed;
        if(AddAccount(ed) != 0)
        {
            return -6;
        }

        SetDefaultAccount(ed.base58Addr);

        if(SavePrivateKeyToFile(ed.base58Addr) != 0)
        {
            return -7;
        }
    }
    else
    {
        if (IsExist(global::ca::kInitAccountBase58Addr))
        {
            SetDefaultAccount(global::ca::kInitAccountBase58Addr);
        }
        else
        {
            SetDefaultBase58Addr(_accountList.begin()->first);
        }
    }

    return 0;
}

//AES encrypt
int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
               unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    ctx = EVP_CIPHER_CTX_new();
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        return -1;
    }
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

//AES decrypt
int Decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
               unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    int plaintext_len;
    
    ctx = EVP_CIPHER_CTX_new();
    
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}

std::string RandGenerateString(int len)
{
    srand((unsigned)time(NULL));                        //Generate randomized seeds                                   
	std::string str = "";
	for(int i = 1;i <= len;i++)
	{
		int flag = rand() % 2;                     //Randomly make flag 1 or 0, 1 is uppercase and 0 is lowercase 
		if(flag == 1)                        //If flag=1 
			str += rand()%('Z'-'A'+1)+'A';       //The ASCII code with capital letters appended 
		else 
			str += rand()%('z'-'a'+1)+'a';       //If flag=0, the ASCII code is appended to lowercase letters 
		
	}
	return str;
}

bool ED25519SignMessage(const std::string &message, EVP_PKEY* pkey, std::string &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    const char * sig_name = message.c_str();

    unsigned char *sig_value = NULL;
    size_t sig_len = strlen(sig_name);

    // Create the Message Digest Context 
    if(!(mdctx = EVP_MD_CTX_new())) 
    {
        return false;
    }

    if(pkey == NULL)
    {
        return false;
    }
    
    // Initialise the DigestSign operation
    if(1 != EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey)) 
    {
        return false;
    }

    size_t tmpMLen = 0;
    if( 1 != EVP_DigestSign(mdctx, NULL, &tmpMLen, (const unsigned char *)sig_name, sig_len))
    {
        return false;
    }

    sig_value = (unsigned char *)OPENSSL_malloc(tmpMLen);

    if( 1 != EVP_DigestSign(mdctx, sig_value, &tmpMLen, (const unsigned char *)sig_name, sig_len))
    {
        return false;
    }

    std::string hashString((char*)sig_value, tmpMLen);
    signature = hashString;

    OPENSSL_free(sig_value);
    EVP_MD_CTX_free(mdctx);
    return true;

}

bool ED25519VerifyMessage(const std::string &message, EVP_PKEY* pkey, const std::string &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    const char *msg = message.c_str();
    unsigned char *sig = (unsigned char *)signature.data();
    size_t slen = signature.size();
    size_t msg_len = strlen(msg);

    if(!(mdctx = EVP_MD_CTX_new())) 
    {
        return false;
    }

    /* Initialize `key` with a public key */
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey)) 
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (1 != EVP_DigestVerify(mdctx, sig, slen ,(const unsigned char *)msg, msg_len)) 
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);
    return true;

}

bool GetEDPubKeyByBytes(const std::string &pubStr, EVP_PKEY* &pKey)
{
    //Generate public key from binary string of public key  
    unsigned char* buf_ptr = (unsigned char *)pubStr.data();
    const unsigned char *pk_str = buf_ptr;
    int len_ptr = pubStr.size();
    
    if(len_ptr == 0)
    {
        ERRORLOG("public key Binary is empty");
        return false;
    }

    EVP_PKEY *peer_pub_key = d2i_PUBKEY(NULL, &pk_str, len_ptr);

    if(peer_pub_key == nullptr)
    {
        return false;
    }
    pKey = peer_pub_key;
    return true;
}
