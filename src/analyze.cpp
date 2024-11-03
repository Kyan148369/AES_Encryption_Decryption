/*
 * analyze.cpp
 *
 *  Created on: Jan 23, 2010
 *      Author: mike
 */

#include <iostream>
#include <cfloat>
#include <cmath>
using namespace std;
#include "aes.hpp"
#include "analyze.hpp"
#include "exception.hpp"

using namespace std;

//-------------------------------------------------------------------
Analyze::Analyze() :
    key(AES_128::keyLength), iv(AES_128::blockSize) {
    for (unsigned k = 0; k < NUM_KEY_SHARES; k++)
        keyShare[k].resize(AES_128::keyLength);
}

//-------------------------------------------------------------------
void Analyze::run(int argc, char* argv[]) {
    if (argc != 5) {
        cout << "usage: " << argv[0] << " freq key in out" << endl;
        return;
    }
    char* freqFile = argv[1];
    char* keyFile = argv[2];
    char* inFile = argv[3];
    char* outFile = argv[4];

    // Get the distribution
    dist.readFreq(freqFile);

    // Get the key shares
    readKeySharesFile(keyFile);

    // Get the iv and ciphertext
    readIVCiphertext(inFile);

    cout << "IV:\n";
    iv.writeHex(cout) << endl;

    // Guess the key
    guessKey();

    // Check that the key works
    cipher.setKey(key);
    cipher.decrypt(ciphertext, plaintext);

    // Print results
    cout << "Guessed key:\n";
    cout << "Indices " << keyIndex1 << " and " << keyIndex2 << endl;
    key.writeHex(cout) << endl;

    // Write the plaintext to the output file
    ofstream out(outFile);
    if (!out)
        throw CryptoException(
                "bruteforce: can't open plaintext file for writing");
    out << plaintext;
    out.close();
}

//-------------------------------------------------------------------
// Read key from file
void Analyze::readKeySharesFile(const char* keyFile) {
    ifstream in(keyFile);
    if (!in)
        throw CryptoException("analyze: can't open key file");
    for (unsigned k = 0; k < NUM_KEY_SHARES; k++)
        keyShare[k].readHex(in);
    in.close();
}

//-------------------------------------------------------------------
// Read IV and ciphertext from file
void Analyze::readIVCiphertext(const char* inFile) {
    ifstream in(inFile);
    if (!in)
        throw CryptoException(
                "analyze: can't open ciphertext file for reading");
    iv.readBytes(in);
    ciphertext.readAllBytes(in);
    in.close();
}
