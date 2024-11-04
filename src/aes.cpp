/*
 * aes.cpp
 *
 *  Created on: Jan 19, 2012
 *      Author: Michael Fischer
 *      Derived from code by Ewa Syta
 */

#include <fstream>
#include "aes.hpp"
#include "exception.hpp"

//-----------------------------------------------------------------------
//Define static constants
const unsigned int AES_128::keyLength = 16;
const unsigned int AES_128::blockSize = 16;


// Constructor to initialise object
AES_128::AES_128() {
    OpenSSL_add_all_algorithms();
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create cipher context");
    }
}

// Destructor to delete an object 
AES_128::~AES_128() {
    if (ctx) {
        // ctx is openssls context structure that holds all encryption/decryption state
        EVP_CIPHER_CTX_free(ctx);
    }
    EVP_cleanup();
}



//-----------------------------------------------------------------------
// Encrypts an arbitrary size plaintext using AES-128/CBC/NoPadding.
// Precondition:  the key and iv must have been previously set.
void AES_128::encrypt(const ByteArray& plaintext, ByteArray& ciphertext) {
      // Initialize encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, 
                              reinterpret_cast<const unsigned char*>(key.data()),
                              reinterpret_cast<const unsigned char*>(iv.data()))) {
        throw CryptoException("Failed to initialize encryption");
    }

    // Disable OpenSSL's padding - we use our own
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Create padded copy of plaintext
    ByteArray padded(plaintext);
    zeroPad(padded);

    // Prepare output buffer
    ciphertext.resize(padded.size() + blockSize);
    int len = 0, ciphertext_len = 0;

    // Perform encryption
    if(1 != EVP_EncryptUpdate(ctx, 
                             reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                             reinterpret_cast<const unsigned char*>(padded.data()),
                             padded.size())) {
        throw CryptoException("Failed during encryption");
    }
    ciphertext_len = len;

    // Finalize encryption
    if(1 != EVP_EncryptFinal_ex(ctx, 
                               reinterpret_cast<unsigned char*>(&ciphertext[ciphertext_len]),
                               &len)) {
        throw CryptoException("Failed to finalize encryption");
    }
    ciphertext_len += len;

    // Resize to actual output size
    ciphertext.resize(ciphertext_len);
}
//-----------------------------------------------------------------------
// Decrypts an arbitrary size ciphertext using AES-128/CBC/NoPadding.
// Precondition:  the key and iv must have been previously set.
void AES_128::decrypt(const ByteArray& ciphertext, ByteArray& plaintext) {
    // Initialize decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL,
                              reinterpret_cast<const unsigned char*>(key.data()),
                              reinterpret_cast<const unsigned char*>(iv.data()))) {
        throw CryptoException("Failed to initialize decryption");
    }

    // Disable OpenSSL's padding - we use our own
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Prepare output buffer
    plaintext.resize(ciphertext.size() + blockSize);
    int len = 0, plaintext_len = 0;

    // Perform decryption
    if(1 != EVP_DecryptUpdate(ctx,
                             reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                             reinterpret_cast<const unsigned char*>(ciphertext.data()),
                             ciphertext.size())) {
        throw CryptoException("Failed during decryption");
    }
    plaintext_len = len;

    // Finalize decryption
    if(1 != EVP_DecryptFinal_ex(ctx,
                               reinterpret_cast<unsigned char*>(&plaintext[plaintext_len]),
                               &len)) {
        throw CryptoException("Failed to finalize decryption");
    }
    plaintext_len += len;

    // Resize to actual size
    plaintext.resize(plaintext_len);

    // Remove padding
    zeroUnPad(plaintext);
}

//-----------------------------------------------------------------------
void AES_128::zeroPad(ByteArray& plaintext) {
    while (plaintext.size() % blockSize != 0) {
        plaintext.push_back(0);
    }
}

//-----------------------------------------------------------------------
void AES_128::zeroUnPad(ByteArray& plaintext) {
    while (plaintext.size() > 0 && plaintext.back() == 0) {
        plaintext.pop_back();
    }
}

// In aes.cpp:
void AES_128::setKey(const ByteArray& key) {
    this->key = key;
}

void AES_128::setIV(const ByteArray& iv) {
    this->iv = iv;
}