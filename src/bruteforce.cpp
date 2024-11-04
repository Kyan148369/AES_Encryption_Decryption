/*
 * main.cpp
 *
 *  Created on: Jan 23, 2010
 *      Author: mike
 */

#include "analyze.hpp"

int main( int argc, char* argv[]) {

    try {
        Analyze anal;
        anal.run(argc, argv);
    }
    catch (exception& e) {
        cerr << "exception caught\n" << e.what() << endl;
    }
    return 0;
}
