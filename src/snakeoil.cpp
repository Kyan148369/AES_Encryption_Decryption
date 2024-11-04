/*
 * main.cpp
 *
 *  Created on: Jan 21, 2012
 *      Author: Michael Fischer
 *      Derived from code by Ewa Syta
 *      Solutions and edits by Debayan Gupta
 */
#include <ctime>
#include "crypto.hpp"

int main(int argc, char* argv[]) {

    try {
        unsigned int seed = time(NULL);
        Crypto toplevel(seed);
        toplevel.run(argc, argv);
    }
    catch (exception& e) {
        cerr << "exception caught\n" << e.what() << endl;
    }
    return 0;
}
