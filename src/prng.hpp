//============= ===============================================================
// Name        : prng.hpp
// Author      : Ewa Syta, es633, slightly modified by Michael Fischer, slightly modified by Debayan Gupta, dg447
// Description : Fills an array with random values
//============================================================================

#pragma once

#include <cstdlib>

typedef unsigned char byte;

class Prng {
private:
    //Parameters
    unsigned int seed; //Seed used to initialize the prng
    void init();

public:
    Prng (unsigned int s): seed(s) {
        init();
    }
    ~Prng () {}

    void nextBytes(byte buf[], unsigned n); //Fills a buffer with random bytes
    void reset();   //Resets the PRNG
};
