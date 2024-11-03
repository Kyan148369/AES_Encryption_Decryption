/*
 * crypto.hpp
 *
 *  Created on: Jan 21, 2012
 *      Author: Michael Fischer
 *      Derived from code by Ewa Syta
 *      Minor edits by Debayan Gupta
 */

#pragma once
#include "aes.hpp"

/* Crypto class implements Happy Hacker's SnakeOil cryptosystem based on AES-128.
 * It supports three subcommands:
 *
 * crypto -g keyshares generates and stores a random key share file.
 *
 * crypto -e keyshares idx1 idx2 in out
 *      encrypts "in" using key shares idx1 and idx2 to generate an AES key.
 *      It writes the ciphertext to "out".
 *
 * crypto -d keyshares idx1 idx2 in out
 *      decrypts "in" using key shares idx1 and idx2 to generate an AES key.
 *      It writes the plaintext to "out".
 *
 *  File formats:
 *  The key shares file consists of 100 * 16 whitespace-delimited hex bytes.
 *      These are interpreted as 100 key shares of 16 bytes each.
 *  The plaintext and ciphertext files are treated as raw bytes.
 *  The first 16 bytes of the ciphertext are taken as the initialization
 *      vector for AES-128 used in CBC mode.
 *  The remaining bytes are the ciphertext blocks.
 */

#define NUM_KEY_SHARES 100

class Crypto {
public:
    static unsigned int const defaultSeed = 1234;
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
    Crypto(unsigned int seed);
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
