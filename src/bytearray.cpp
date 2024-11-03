//============================================================================
// Name        : byteArray.hpp
// Author      : Michael Fischer, derived from code by Ewa Syta, es633, slightly modified by Debayan Gupta, dg447
// Description : A container for raw bytes
//============================================================================

#include <iostream>
#include <iomanip>
#include "bytearray.hpp"
#include "exception.hpp"

//-----------------------------------------------------------------------
void ByteArray::fillRandom(Prng& rng) {
    rng.nextBytes(&front(), size());
}

//-----------------------------------------------------------------------
// Writes the array in hex
ostream& ByteArray::writeHex(ostream& out) const {
    const_iterator ptr;
    for (ptr = begin(); ptr != end(); ptr++) {
        if (ptr > begin() && (ptr - begin()) % 8 == 0) //For displaying
            out << endl;
        out << setw(2) << hex << setfill('0') << (unsigned) *ptr << " "
                << dec; //Displays in hex
        if (!out.good())
            throw CryptoException("writeHex: I/O error");

    }
    return out << endl;
}

//-----------------------------------------------------------------------
// Reads the array in hex
// Tries to fill the array to its current size.
istream& ByteArray::readHex(istream& in) {
    iterator ptr;
    for (ptr = begin(); ptr != end(); ptr++) {
        unsigned b;
        in >> hex >> b;
        *ptr = b;
        if (!in.good())
            throw CryptoException("readHex: unexpected eof or bad data");
    }
    return in;
}

//-----------------------------------------------------------------------
// Writes raw bytes
ostream& ByteArray::writeBytes(ostream& out) const {
    const_iterator ptr;
    for (ptr = begin(); ptr != end(); ptr++) {
        out.put(*ptr);
        if (!out.good())
            throw CryptoException("writeBytes: I/O error");
    }
    return out;
}

//-----------------------------------------------------------------------
// Reads raw bytes
// Tries to fill the array to its current size
istream& ByteArray::readBytes(istream& in) {
    iterator ptr;
    for (ptr = begin(); ptr != end(); ptr++) {
        char b;
        in.get(b);
        if (!in.good())
            throw CryptoException(
                    "readBytes: unexpected eof or bad data");
        *ptr = b;
    }
    return in;
}

//-----------------------------------------------------------------------
// Reads raw bytes
// Read all bytes into array.
istream& ByteArray::readAllBytes(istream& in) {
    char ch;
    clear();
    for (;;) {
        in.get(ch);
        if (in.fail())
            break;
        push_back(ch);
    }
    if (!in.eof())
        throw CryptoException("readBytes: I/O error");
    return in;
}

//-----------------------------------------------------------------------
// take XOR of ByteArray
ByteArray& ByteArray::operator^(const ByteArray& op2) {
    if (size() != op2.size()) throw CryptoException( "XOR of ByteArray of unequal lengths not supported" );
    for (unsigned k=0; k<size(); k++)
        (*this)[k] ^= op2[k];
    return *this;
}

