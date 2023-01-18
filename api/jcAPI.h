extern "C" {
    /**
         Illustrate:
            Generate public, private and wallet addresses
        Parameter:
            ver: Version number
                Pass 0 to generate base58 addresses starting with 1
                Pass 5 to generate base58 addresses starting with 3
        Return value:
            Private key, public key, base58 address A string of concatenated spaces is concatenated by spaces
            The private key, the public key is a hexadecimal string
    */
    char* GenWallet(int ver);

    /*
        Illustrate:
            Generate public, private and wallet addresses
        Parameter:
            out_private_key: outgoing parameters, outgoing private key (bytestream form), the caller is responsible for opening up memory, ensuring that it is greater than 33 bytes
            out_private_key_len: Pass in the outgoing parameter, which represents the size of the memory opened when passed in and returns the actual length of the private key when outgoing is returned 
            out_public_key: outgoing parameters, outgoing public key (in byte stream form), the caller is responsible for opening up memory, ensuring that it is greater than 67 bytes
            out_public_key_len: Pass in the outgoing parameter, which represents the size of the open memory when passed in, and returns the actual length of the public key when outgoing time
            out_bs58addr: outgoing parameters, outgoing address, the caller is responsible for opening up memory, ensuring that it is greater than 35 bytes
            out_bs58addr_len: Pass in the outgoing parameter, which represents the memory size when passed in and the actual length of the address returned when outgoing when it is out
        Return value:
            0 represents success
            -1 indicates insufficient memory space to open up
    */
    int GenWallet_(char *out_private_key, int *out_private_key_len,
                  char *out_public_key, int *out_public_key_len, 
                  char *out_bs58addr, int *out_bs58addr_len);


    /**
        Illustrate:
            Generate a signature after base64 encoding
        Parameter:
            pri: The hexadecimal private key
            msg: Information to be signed
            len: The length of the information to be signed
        Return value:
            Base64-encoded signature information
    */
    char* GenSign(char* pri, char* msg, int len);


    /*
    Illustrate:
        Generate base64-encoded signature information
    Parameter:
        PRI: Private Key (byte stream)
        pri_len: The length of the private key 
        MSG: Information to be signed
        msg_len: The length of the information to be signed
        signature_msg: Outgoing parameters, outgoing signature information after base64 encoding, the caller is responsible for opening up memory, ensuring that it is greater than 90 bytes
        out_len: Pass in the outgoing parameter, which represents the memory size when passed in, and returns the actual length of the signature information when passing out
    Return value:
        0 represents success
        -1 indicates insufficient memory space to open up
    */
    int GenSign_(const char* pri, int pri_len,
                const char* msg, int msg_len,
                char *signature_msg, int *out_len); 
}
