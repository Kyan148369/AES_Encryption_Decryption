/*
 * crypto.cpp
 *
 *  Created on: Jan 21, 2012
 *      Author: Michael Fischer
 *      Derived from code by Ewa Syta
 */

#include <stdexcept>
#include <fstream>
#include <algorithm>
#include "crypto.hpp"
#include "exception.hpp"

//-------------------------------------------------------------------
Crypto::Crypto(unsigned int seed = defaultSeed) :
    rng(seed), key(AES_128::keyLength), iv(AES_128::blockSize) {
    for (unsigned k = 0; k < NUM_KEY_SHARES; k++)
        keyShare[k].resize(AES_128::keyLength);
}

//-------------------------------------------------------------------
void Crypto::run(int argc, char* argv[]) {
    const string usage = "usage: " + string(argv[0])
            + "[-e|-d] keyFile idx1 idx2 inFile outFile\n"
                "       crypto -g keyFile";
    if (argc < 3 || argv[1][0] != '-') {
        throw invalid_argument(usage);
    }
    char op = argv[1][1]; // op code letter 'g', 'e', or 'd'
    char* keyFile = argv[2]; // name of key file

    if (op == 'g') { // generate random key
        doKeyGen(keyFile);
        return;
    }

    // Encode (-e) or decode (-d) switch; 4 more args required
    if (argc != 7)
        throw invalid_argument(usage);

    // Get the key shares
    readKeySharesFile(keyFile);

    // Set the master key indices
    keyIndex1 = atoi(argv[3]);
    keyIndex2 = atoi(argv[4]);

    // Compute the master key
    key = keyShare[ keyIndex1 ];
    key^keyShare[ keyIndex2 ];
    cout << "Master key:\n";
    key.writeHex(cout) << endl;

    // Get the input and output file names
    char* inFile = argv[5];
    char* outFile = argv[6];

    switch (op) {
    case 'e': // encrypt
        doEncrypt(inFile, outFile);
        break;

    case 'd': // decrypt
        doDecrypt(inFile, outFile);
        break;

    default:
        throw invalid_argument(usage);
    }
}

//-------------------------------------------------------------------
void Crypto::readKeySharesFile(const char* keyFile) {
    // Read key file into ByteArray key
    ifstream in(keyFile);
    if (!in)
        throw CryptoException("crypto: can't open key file");
    for (unsigned k = 0; k < NUM_KEY_SHARES; k++)
        keyShare[k].readHex(in);
    in.close();
}

//-------------------------------------------------------------------
void Crypto::readPlaintext(const char* inFile) {
    ifstream in(inFile);
    if (!in)
        throw CryptoException(
                "encrypt: can't open plaintext file for reading");
    plaintext.readAllBytes(in);
    in.close();
}

//-------------------------------------------------------------------
// Read IV and ciphertext from file
void Crypto::readIVCiphertext(const char* inFile) {
    ifstream in(inFile);
    if (!in)
        throw CryptoException(
                "decrypt: can't open ciphertext file for reading");
    iv.readBytes(in);
    ciphertext.readAllBytes(in);
    in.close();
}

//-------------------------------------------------------------------
void Crypto::doKeyGen(const char* keyFile) {
    ofstream out(keyFile);
    if (!out)
        throw CryptoException(
                "key generation: can't open key file for writing");

    // Fill the keyShare array with random strings and write to disk
    for (unsigned k = 0; k < NUM_KEY_SHARES; k++) {
        keyShare[k].fillRandom(rng);
        keyShare[k].writeHex(out);
        out << endl;
    }
    out.close();
}

//-------------------------------------------------------------------
void Crypto::doEncrypt(
        const char* inFile, const char* outFile) {

    // Generate a new random initialization vector
    iv.fillRandom(rng);

    // Get the plaintext
    readPlaintext(inFile);

    // Set the key and IV for use by the cipher
    cipher.setKey(key);
    cipher.setIV(iv);

    // Encrypt
    cipher.encrypt(plaintext, ciphertext);

    // Write the iv and ciphertext to the output file
    ofstream out(outFile);
    if (!out)
        throw CryptoException(
                "encrypt: can't open ciphertext file for writing");
    iv.writeBytes(out);
    ciphertext.writeBytes(out);
    out.close();
}

//-------------------------------------------------------------------
void Crypto::doDecrypt(
        const char* inFile, const char* outFile) {

    // Get the iv and ciphertext
    readIVCiphertext(inFile);

    // Set the key and IV for use by the cipher
    cipher.setKey(key);
    cipher.setIV(iv);

    // Decrypt
    cipher.decrypt(ciphertext, plaintext);

    // Write the plaintext to the output file
    ofstream out(outFile);
    if (!out)
        throw CryptoException(
                "decrypt: can't open plaintext file for writing");
    plaintext.writeBytes(out);
    out.close();
}

