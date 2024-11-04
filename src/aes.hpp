/*
 * aes.hpp
 *
 *  Created on: Jan 19, 2012
 *      Author: Michael Fischer
 *      Derived from code by Ewa Syta
 */

#pragma once
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include "bytearray.hpp"
#include "prng.hpp"
#include "bytearray.hpp"
using namespace std;


/* Wrapper class for Botan's implementation of AES-128/CBC.
 * It encrypts and decrypts raw ByteArray data.
 * Must set the key and initialization vector before calling encrypt
 * or decrypt.
 */

class AES_128 {
public:
    static const unsigned int keyLength; // 128 bits 
    static const unsigned int blockSize; // 128 bits
private:
    ByteArray key;
    ByteArray iv;
    EVP_CIPHER_CTX *ctx;  // OpenSSL context


public:
    AES_128();
    ~AES_128();


    void encrypt( const ByteArray& plaintext, ByteArray& ciphertext );
    void decrypt( const ByteArray& ciphertext, ByteArray& plaintext );
    void zeroPad(ByteArray& plaintext);
    void zeroUnPad(ByteArray& plaintext);

    void setKey( const ByteArray& key );
    void setIV( const ByteArray& iv );
};
