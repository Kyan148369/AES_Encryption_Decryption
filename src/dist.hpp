/*
 * freq.hpp
 *
 *  Created on: Jan 23, 2010
 *      Author: mike
 */

#pragma once

#include <iostream>
using namespace std;

#define ALPHABETSIZE 256

// ------------------------------------------------------------------
class Distribution {
private:
    double prob[ALPHABETSIZE];
public:
    Distribution() {}
    void readFreq(const char* freqFile);
    const double operator[] (int k) const { return prob[k]; }
    ostream& print(ostream& out) const;
};

// ------------------------------------------------------------------
inline ostream& operator<<(ostream& out, Distribution& dist) {
    return dist.print(out);
}
