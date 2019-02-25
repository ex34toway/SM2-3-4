# SM4
SM4 is a symmetric encryption algorithm, seems to AES algorithm.
The key used by SM4 is just 128bit,and the size of input data is the multiple of 128bit, it need to pad if the size of input data is not the multiple of 128bit. 
The flow of encyrption/decryption is to encrypt/decrypt every 128bit, which is a block. 
The lastest version of openssl-1.1.1 have support the SM3/4, and here, I write a demo of how to encrypto/decrypto a file by SM4 within the openssl-1.1.1
The lastest of openssl can be loaded with https://www.openssl.org/source/openssl-1.1.1-pre5.tar.gz

