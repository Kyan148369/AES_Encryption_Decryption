//============================================================================
// Name        : byteArray.hpp
// Author      : Michael Fischer, derived from code by Ewa Syta, es633, slightly modified by Debayan Gupta, dg447
// Description : A container for raw bytes
//============================================================================

#pragma once
#include <iostream>
#include <vector>
#include "prng.hpp"
using namespace std;

typedef unsigned char byte;

/* ByteArray is an adaptor to the standard container vector<byte>.
 * It augments vector with various I/O and random byte functions.
 * The element type is a raw 8-bit byte, defined to be an unsigned char.
 * This is consistent with the needs of ::Pipe.
 */
class ByteArray : public vector<byte> {
private:

public:
    ByteArray(unsigned int n=0) : vector<byte>(n) {}

    void fillRandom(Prng& rng);              // fills with random bytes
    ostream& writeHex(ostream& out) const;   // writes size() bytes in hex
    istream& readHex(istream& in);           // reads size() bytes in hex
    ostream& writeBytes(ostream& out) const; // writes size() raw bytes
    istream& readBytes(istream& in);         // reads size() raw bytes
    istream& readAllBytes(istream& in);      // reads raw bytes to EOF
    ByteArray& operator^(const ByteArray& op2);  // take XOR of ByteArray
};

inline ostream& operator<<(ostream& out, const ByteArray& ba) {
    return ba.writeBytes(out);
}
