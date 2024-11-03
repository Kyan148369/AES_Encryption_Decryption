/*
 * analyze.hpp
 *
 *  Created on: Jan 23, 2010
 *      Author: mike
 */

#pragma once

#include <iostream>
#include <fstream>
#include "aes.hpp"
#include "dist.hpp"
#include "bytearray.hpp"

using namespace std;

#define TINY_VAL -1e100
#define NUM_KEY_SHARES 100

class Analyze {
private:
    AES_128 cipher;
    Distribution dist;
    ByteArray keyShare[NUM_KEY_SHARES];
    unsigned keyIndex1, keyIndex2;
    ByteArray key;
    ByteArray iv;
    ByteArray plaintext;
    ByteArray ciphertext;

public:
    Analyze();
    void run(int argc, char* argv[]);
private:
    void guessKey();
    double divergence( const ByteArray& s ) const;

    void readKeySharesFile(const char* keyFile);
    void readIVCiphertext(const char* inFile);
};
