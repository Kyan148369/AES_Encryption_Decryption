/*
 * dist.cpp
 *
 *  Created on: Jan 23, 2010
 *      Author: mike
 */

#include <fstream>
#include "dist.hpp"
#include "exception.hpp"

// ------------------------------------------------------------------
// Reads a file of byte frequencies, normalizes them, and stores the
// normalized values to data member "prob".
void Distribution::readFreq(const char* freqFile) {
    ifstream fin(freqFile);
    if (!fin)
        throw CryptoException("readFreq: can't open frequency file");
    int sum = 0;
    int freq[ALPHABETSIZE];
    for (int i = 0; i < ALPHABETSIZE; i++) {
        fin >> freq[i];
        if (!fin.good())
            throw CryptoException("Error reading frequency table");
        sum += freq[i];
    }
    fin.close();

    // Compute normalized values
    for (int i = 0; i < ALPHABETSIZE; i++) {
        prob[i] = double(freq[i]) / sum;
    }
}

// ------------------------------------------------------------------
// Prints the table of normalized frequencies
ostream& Distribution::print(ostream& out) const {
    out << "Probabilities\n";
    for (int i = 0; i < ALPHABETSIZE; i++) {
        out << "prob[" << i << "]=" << prob[i] << endl;
    }
    return out;
}
