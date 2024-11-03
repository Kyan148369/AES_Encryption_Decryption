/*
 * aes.hpp
 *
 *  Created on: Jan 19, 2012
 *      Author: Michael Fischer
 *      Derived from code by Ewa Syta
 */

#pragma once
#include <botan/botan.h>
#include "bytearray.hpp"
using namespace std;

#include "bytearray.hpp"
#include "prng.hpp"

/* Wrapper class for Botan's implementation of AES-128/CBC.
 * It encrypts and decrypts raw ByteArray data.
 * Must set the key and initialization vector before calling encrypt
 * or decrypt.
 */

class AES_128 {
public:
    static const unsigned int keyLength;
    static const unsigned int blockSize;
private:
    Botan::SymmetricKey bkey;
    Botan::InitializationVector biv;

public:
    AES_128() {
    }
    void encrypt( const ByteArray& plaintext, ByteArray& ciphertext );
    void decrypt( const ByteArray& ciphertext, ByteArray& plaintext );
    void zeroPad(ByteArray& plaintext);
    void zeroUnPad(ByteArray& plaintext);

    void setKey( const ByteArray& key ) {
        bkey.change(key.data(), key.size());
    }
    void setIV( const ByteArray& iv ) {
        biv.change(iv.data(), iv.size());
    }
};
