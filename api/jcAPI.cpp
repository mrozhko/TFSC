#include "api/phoneAPI.h"
#include "utils/base64_2.h"
#include "../include/logging.h"

//g++ -fPIC -c jcAPI.cpp
//g++ -shared *.o -o libjcAPI.so libphone.a
extern "C" {


    static const char hexdigit[] = "0123456789abcdef";

    void encode_hex_local(char *hexstr, const void *p_, size_t len)
    {
        const unsigned char *p = (const unsigned char *)p_;
        unsigned int i;

        for (i = 0; i < len; i++) {
            unsigned char v, n1, n2;

            v = p[i];
            n1 = v >> 4;
            n2 = v & 0xf;

            *hexstr++ = hexdigit[n1];
            *hexstr++ = hexdigit[n2];
        }

        *hexstr = 0;
    }

    //Generate a wallet
    //The public and private keys are base 16
    //Private key + public key + BS58 address Stitched with spaces
    char* GenWallet(int ver) {
        string out_pri_key;
        string out_pub_key;
        const uint BUFF_SIZE = 128;
        ca_phoneAPI::CPPgenPairKey(out_pri_key, out_pub_key);

        //Private
        char* pri_hex = new char[BUFF_SIZE]{0};
        encode_hex_local(pri_hex, out_pri_key.c_str(), out_pri_key.size());

        //Public
        char* pub_hex = new char[BUFF_SIZE*2]{0};
        encode_hex_local(pub_hex, out_pub_key.c_str(), out_pub_key.size());

        //bs58
        const char *pub_key = out_pub_key.c_str();
        const int pub_len = out_pub_key.size();
        char *bs58_addr = new char[BUFF_SIZE]{0};
        int *bs58_len = new int;
        ca_phoneAPI::genBs58Addr(pub_key, pub_len, bs58_addr, bs58_len, ver);

        //splicing
        string wallet(pri_hex);
        wallet += " ";
        wallet += pub_hex;
        wallet += " ";
        wallet += bs58_addr;
        char* wallet_c = new char[BUFF_SIZE*4]{0};
        strcpy(wallet_c, wallet.c_str());

        return wallet_c;
    }

    int GenWallet_(char *out_private_key, int *out_private_key_len,
                  char *out_public_key, int *out_public_key_len, 
                  char *out_bs58addr, int *out_bs58addr_len)
    {   
        if (*out_private_key_len < 32 || *out_public_key_len < 66 || *out_bs58addr_len < 34)
        {
            return -1;
        }
        string out_pri_key;
        string out_pub_key;
        ca_phoneAPI::CPPgenPairKey(out_pri_key, out_pub_key);

        memcpy(out_private_key, out_pri_key.c_str(), out_pri_key.size());
        *out_private_key_len = out_pri_key.size();

        memcpy(out_public_key, out_pub_key.c_str(), out_pub_key.size());
        *out_public_key_len = out_pub_key.size();

        ca_phoneAPI::genBs58Addr(out_pub_key.c_str(), out_pub_key.size(), out_bs58addr, out_bs58addr_len, 0);

        return 0;
    }

    //Returns the signature after BS64
    //Returns the signature after BS64
    char* GenSign(char* pri, char* msg, int len) {
        string pri_str(pri);
        ECDSA<ECP, SHA1>::PrivateKey pri_key;
        ca_phoneAPI::SetPrivateKey(pri_key, pri_str);

        string message(msg, len);
        string signature;
        ca_phoneAPI::__SignMessage(pri_key, message, signature);

        uint encode_len = signature.size() * 2;
        unsigned char* encode = new unsigned char[encode_len];
        base64_encode((unsigned char *)signature.data(), signature.size(), encode);
        DEBUGLOG("encode:{} ", encode);

        return (char*)encode;
    }

    //Generate a signature
    //Returns the signature after BS64
    int GenSign_(const char* pri, int pri_len,
                 const char* msg, int msg_len,
                 char *signature_msg, int *out_len) 
    {   
        if (*out_len < 90)
        {
            return -1;
        }
        char pri_hex[128] = {0};
        encode_hex_local(pri_hex, pri, pri_len);

        string pri_str(pri_hex);
        ECDSA<ECP, SHA1>::PrivateKey pri_key;
        ca_phoneAPI::SetPrivateKey(pri_key, pri_str);

        string message(msg, msg_len);
        string signature;
        ca_phoneAPI::__SignMessage(pri_key, message, signature);
        
        base64_encode((unsigned char *)signature.data(), signature.size(), (unsigned char *)signature_msg);
        *out_len = strlen(signature_msg);

        return 0;
    }

}

