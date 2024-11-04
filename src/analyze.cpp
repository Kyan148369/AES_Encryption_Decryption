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


// Calculates divergence between frequency distributions
double Analyze::divergence(const ByteArray& text) const {
    double sum = 0.0;
    int letterCounts[ALPHABETSIZE] = {0};  // Array to store character frequencies
    int totalChars = 0;                    // Total number of characters

    // Count frequency of each character in the text
    for (unsigned char c : text) {
        letterCounts[c]++;
        totalChars++;
    }

    // If text is empty, return very large divergence
    if (totalChars == 0) {
        return TINY_VAL;
    }

    // Calculate divergence using sum of squared differences
    // between normalized frequencies and expected probabilities
    for (int i = 0; i < ALPHABETSIZE; i++) {
        double observed = static_cast<double>(letterCounts[i]) / totalChars;
        double expected = dist[i];  // Expected probability from frequency table
        double diff = observed - expected;
        sum += diff * diff;  // Square the difference
    }

    return -sum;  // Negative because we want to maximize similarity
}

// Tries all possible key pairs to find the one that produces
// most likely plaintext based on character frequencies
void Analyze::guessKey() {
    double bestScore = TINY_VAL;
    ByteArray currentKey(AES_128::keyLength);
    ByteArray tempPlaintext;
    
    cipher.setIV(iv);  // Set the IV from the ciphertext

    // Try all possible pairs of key shares
    for (unsigned int i = 0; i < NUM_KEY_SHARES; i++) {
        for (unsigned int j = i + 1; j < NUM_KEY_SHARES; j++) {
            // Compute trial key as XOR of two shares
            currentKey = keyShare[i];
            currentKey ^ keyShare[j];  // XOR with second share
            
            try {
                // Set up cipher with trial key
                cipher.setKey(currentKey);
                
                // Try to decrypt
                cipher.decrypt(ciphertext, tempPlaintext);
                
                // Calculate how well the decryption matches expected frequencies
                double score = divergence(tempPlaintext);
                
                // Update best key if this produces better match
                if (score > bestScore) {
                    bestScore = score;
                    key = currentKey;
                    keyIndex1 = i;
                    keyIndex2 = j;
                    plaintext = tempPlaintext;  // Save best plaintext
                }
            }
            catch (const CryptoException& e) {
                // Skip invalid decryptions
                continue;
            }
        }
    }

    // If no valid decryption found
    if (bestScore == TINY_VAL) {
        throw CryptoException("No valid decryption found");
    }
}