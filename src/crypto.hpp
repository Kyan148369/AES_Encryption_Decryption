#pragma once
#include "aes.hpp"

#define NUM_KEY_SHARES 100

class Crypto {
public:
    static const unsigned int defaultSeed = 1234;

private:
    AES_128 cipher;
    Prng rng;
    ByteArray keyShare[NUM_KEY_SHARES];
    unsigned keyIndex1, keyIndex2;
    ByteArray key;
    ByteArray iv;
    ByteArray plaintext;
    ByteArray ciphertext;

public:
    // Declare constructor with default argument here, not in cpp file
    explicit Crypto(unsigned int seed = defaultSeed);
    void run(int argc, char* argv[]);

private:
    void findKey() {
        key = keyShare[keyIndex1];
        key ^ keyShare[keyIndex2];
    }

    void readKeySharesFile(const char* keyFile);
    void readPlaintext(const char* inFile);
    void readIVCiphertext(const char* inFile);

    void doKeyGen(const char* keyFile);
    void doEncrypt(const char* inFile, const char* outFile);
    void doDecrypt(const char* inFile, const char* outFile);
};