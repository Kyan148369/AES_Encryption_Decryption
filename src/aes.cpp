/*
 * aes.cpp
 *
 *  Created on: Jan 19, 2012
 *      Author: Michael Fischer
 *      Derived from code by Ewa Syta
 */

#include <fstream>
#include "aes.hpp"
#include "exception.hpp"

//-----------------------------------------------------------------------
//Define static constants
const unsigned int AES_128::keyLength = 16;
const unsigned int AES_128::blockSize = 16;

//-----------------------------------------------------------------------
// Encrypts an arbitrary size plaintext using AES-128/CBC/NoPadding.
// Precondition:  the key and iv must have been previously set.
void AES_128::encrypt(const ByteArray& plaintext, ByteArray& ciphertext) {
    ByteArray padded(plaintext);
    zeroPad(padded);
    Botan::Pipe enc(
            Botan::get_cipher("AES-128/CBC/NoPadding", bkey, biv,
                    Botan::ENCRYPTION));
    enc.process_msg(padded.data(), padded.size()); //Puts the plaintext to the pipe
    //ciphertext = enc.read_all_as_string(); //Extracts the ciphertext0
    ciphertext.resize(enc.remaining()); // #bytes in pipe
    unsigned n = enc.read(&ciphertext.front(), ciphertext.size()); //Extracts the ciphertext
    if (n != ciphertext.size())
        throw CryptoException(
                "encrypt: failed to read expected # bytes from pipe");
}
//-----------------------------------------------------------------------
// Decrypts an arbitrary size ciphertext using AES-128/CBC/NoPadding.
// Precondition:  the key and iv must have been previously set.
void AES_128::decrypt(const ByteArray& ciphertext, ByteArray& plaintext) {
    Botan::Pipe dec(
            Botan::get_cipher("AES-128/CBC/NoPadding", bkey, biv,
                    Botan::DECRYPTION));
    dec.process_msg(ciphertext.data(), ciphertext.size()); //Puts the ciphertext to the pipe
    plaintext.resize(dec.remaining()); // #bytes in pipe
    unsigned n = dec.read(&plaintext.front(), plaintext.size()); //Extracts the plaintext
    if (n != plaintext.size())
        throw CryptoException(
                "decrypt: failed to read expected # bytes from pipe");
    zeroUnPad(plaintext);
}

//-----------------------------------------------------------------------
void AES_128::zeroPad(ByteArray& plaintext) {
    while (plaintext.size() % blockSize != 0) {
        plaintext.push_back(0);
    }
}

//-----------------------------------------------------------------------
void AES_128::zeroUnPad(ByteArray& plaintext) {
    while (plaintext.size() > 0 && plaintext.back() == 0) {
        plaintext.pop_back();
    }
}
