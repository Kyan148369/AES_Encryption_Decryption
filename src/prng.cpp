//============================================================================
// Name        : prng.cpp
// Author      : Ewa Syta, es633, slightly modified by Michael Fischer, slightly modified by Debayan Gupta, dg447
// Description : Defines prng.hpp
//============================================================================

#include <iostream>
#include <iomanip>
using namespace std;
#include "prng.hpp"

//-----------------------------------------------------------------------
//Initializes the PRNG
void
Prng::init(){
    srand(seed);
}
//-----------------------------------------------------------------------
//Resets the PRNG
void
Prng::reset(){
    srand(seed);
}
//-----------------------------------------------------------------------
//Fills an array with random bytes
void
Prng::nextBytes( byte buf[], unsigned n ){
    for (unsigned i=0; i < n; i++)
    {
        buf[i] = rand() % 256;
    }
}
