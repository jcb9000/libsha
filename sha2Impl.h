// sha2Impl.h
// Implementation of SHA-1 and SHA-2 message digest functions as described here:
//
// http://en.wikipedia.org/wiki/SHA-2
// 
// The sha class presents the public API. 
// This file contains the implementation of the SHA1 and SHA-2 algorithms.

/*
The MIT License (MIT)

Copyright (c) 2016 Charles Bushakra

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#pragma once

#include <string>
#include <array>
#include <iostream>
#include <fstream>
#include <ios>
#include <limits>
#include <inttypes.h>
#include <functional>


namespace shautil {

template<typename IntType, int ChunkSize>
class SHA2Impl
{
private:
    using SHAProcessDelegate_t = std::function<void()>;

    // Computed digest
    std::array<IntType, 8>  digest;

    // One chunk of the input stream (512-bits or 1024-bits depending on the algorithm)
    unsigned char           messageChunk[ChunkSize];
    uint64_t                messageLengthLo;         // Message length in bits
    uint64_t                messageLengthHi;

    // How many bytes are currently in the messageChunk buffer
    std::streamsize         chunkOffset;
    std::string             fileName;

    // Delegate function, assigned in initXXXX() to perform the desired SHA algorithm on
    // the message chunk.
    void (SHA2Impl::*processOp)();

    // These arrays are defined in the SHA-2 specifications.
    std::array<uint32_t, 64> k_256;
    std::array<uint64_t, 80> k_512;

    // Rotate (not shift) an integer to the left.
    // IntType is either a 32-bit int or a 64-bit int.
    // std::numeric_limits is used to determine how many bits are being rotated
    inline IntType leftRotate(IntType val, int bits) {
        return((val << bits) | (val >> (std::numeric_limits<IntType>::digits - bits)));
    }

    // Same as above except rotate right.
    inline IntType rightRotate(IntType val, int bits) {
        return((val >> bits) | (val << (std::numeric_limits<IntType>::digits - bits)));
    }

    // Implementation of the SHA-1 algorithm as described
    // in the specification. This function processes one
    // chunk of the data at a time.
    void processSHA1Chunk() {

        int i;
        uint32_t a, b, c, d, e, f, k, temp;
        uint32_t w[80];

        // Break chunk into 16 32-bit big-endian words
        for(i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)messageChunk[i * 4]) << 24;
            w[i] |= ((uint32_t)messageChunk[i * 4 + 1]) << 16;
            w[i] |= ((uint32_t)messageChunk[i * 4 + 2]) << 8;
            w[i] |= ((uint32_t)messageChunk[i * 4 + 3]);
        }


        // Extend the 16 32-bit words into 80 32-bit words
        for(i = 16; i < 80; i++) {
            w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }


        // Initialize variables for this chunk
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];

        for(i = 0; i < 80; ++i) {

            if(i >= 0 && i <= 19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else
                if(i >= 20 && i <= 39) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else
                    if(i >= 40 && i <= 59) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    }
                    else
                        if(i >= 60 && i <= 79) {
                            f = b ^ c ^ d;
                            k = 0xCA62C1D6;
                        }

            temp = leftRotate(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        // Add this chunk's hash to the result so far
        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
    }


    // Implement the SHA-256 algorithm as described in the
    // SHA-2 spec. This function processes one 64-byte chunk of
    // data at a time.
    // Note the same algorithm is used for SHA-224.
    void processSHA256Chunk() {

        int i;
        uint32_t a, b, c, d, e, f, g, h, s0, s1, maj, ch, temp1, temp2;
        uint32_t w[64];


        // Copy the message chunk into first 16 words of w.
        for(i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)messageChunk[i * 4]) << 24;
            w[i] |= ((uint32_t)messageChunk[i * 4 + 1]) << 16;
            w[i] |= ((uint32_t)messageChunk[i * 4 + 2]) << 8;
            w[i] |= ((uint32_t)messageChunk[i * 4 + 3]);
        }

        // Extend the first 16 words into the remaining 48 words
        for(i = 16; i < 64; ++i) {

            s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // Initialize working variables to hash value
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
        f = digest[5];
        g = digest[6];
        h = digest[7];

        for(i = 0; i < 64; ++i) {
            s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            ch = (e & f) ^ ((~e) & g);
            temp1 = h + s1 + ch + k_256[i] + w[i];
            s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Add the compressed chunk to the current hash value
        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
        digest[5] += f;
        digest[6] += g;
        digest[7] += h;
    }


    // Implement the SHA-512 algorithm as described in the SHA-2 spec.
    // This function processes 80 bytes at a time.
    // Note SHA-384 uses the same algorithm.
    void processSHA512Chunk() {

        int i;
        uint64_t a, b, c, d, e, f, g, h, s0, s1, maj, ch, temp1, temp2;
        uint64_t w[80];

        // Copy the message chunk into first 16 words of w.
        for(i = 0; i < 16; ++i) {
            w[i] = ((uint64_t)messageChunk[i * 8]) << 56;
            w[i] |= ((uint64_t)messageChunk[i * 8 + 1]) << 48;
            w[i] |= ((uint64_t)messageChunk[i * 8 + 2]) << 40;
            w[i] |= ((uint64_t)messageChunk[i * 8 + 3]) << 32;
            w[i] |= ((uint64_t)messageChunk[i * 8 + 4]) << 24;
            w[i] |= ((uint64_t)messageChunk[i * 8 + 5]) << 16;
            w[i] |= ((uint64_t)messageChunk[i * 8 + 6]) << 8;
            w[i] |= ((uint64_t)messageChunk[i * 8 + 7]);
        }

        // Extend the first 16 words into the remaining 48 words
        for(i = 16; i < 80; ++i) {

            s0 = rightRotate(w[i - 15], 1) ^ rightRotate(w[i - 15], 8) ^ (w[i - 15] >> 7);
            s1 = rightRotate(w[i - 2], 19) ^ rightRotate(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // Initialize working variables to hash value
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
        f = digest[5];
        g = digest[6];
        h = digest[7];

        for(i = 0; i < 80; ++i) {
            s1 = rightRotate(e, 14) ^ rightRotate(e, 18) ^ rightRotate(e, 41);
            ch = (e & f) ^ ((~e) & g);
            temp1 = h + s1 + ch + k_512[i] + w[i];
            s0 = rightRotate(a, 28) ^ rightRotate(a, 34) ^ rightRotate(a, 39);
            maj = (a & b) ^ (a & c) ^ (b & c);
            temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Add the compressed chunk to the current hash value
        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
        digest[5] += f;
        digest[6] += g;
        digest[7] += h;
    }

    // Finalize the digest after the entire file has been read and processed.
    // If necessary, pad the current chunk out as described in the specs.
    // Note this might necessitate one more call to the processOp delegate.
    //
    // Pad the final chunk of data read from the file. Each algorithm
    // requires a set amount of pad. The padding might overflow and create
    // yet one more final chunk of data (consisting entirely of padding)
    // which must be processed and added to the message digest.
    void finalize() {

        messageChunk[chunkOffset++] = 0x80;
        if(chunkOffset > (std::streamsize)(ChunkSize - (sizeof(IntType)* 2))) {

            while(chunkOffset < ChunkSize)
                messageChunk[chunkOffset++] = 0;

            (this->*processOp)();
            chunkOffset = 0;
        }

        while(chunkOffset < (std::streamsize)(ChunkSize - (sizeof(IntType)* 2))) {
            messageChunk[chunkOffset++] = 0;
        }


        messageChunk[ChunkSize - 8] = (unsigned char)((messageLengthLo & 0xff00000000000000ULL) >> 56);
        messageChunk[ChunkSize - 7] = (unsigned char)((messageLengthLo & 0x00ff000000000000ULL) >> 48);
        messageChunk[ChunkSize - 6] = (unsigned char)((messageLengthLo & 0x0000ff0000000000ULL) >> 40);
        messageChunk[ChunkSize - 5] = (unsigned char)((messageLengthLo & 0x000000ff00000000ULL) >> 32);
        messageChunk[ChunkSize - 4] = (unsigned char)((messageLengthLo & 0x00000000ff000000ULL) >> 24);
        messageChunk[ChunkSize - 3] = (unsigned char)((messageLengthLo & 0x0000000000ff0000ULL) >> 16);
        messageChunk[ChunkSize - 2] = (unsigned char)((messageLengthLo & 0x000000000000ff00ULL) >> 8);
        messageChunk[ChunkSize - 1] = (unsigned char)(messageLengthLo  & 0x00000000000000ffULL);

        if(ChunkSize == 128) {
            messageChunk[ChunkSize - 16] = (unsigned char)((messageLengthHi & 0xff00000000000000ULL) >> 56);
            messageChunk[ChunkSize - 15] = (unsigned char)((messageLengthHi & 0x00ff000000000000ULL) >> 48);
            messageChunk[ChunkSize - 14] = (unsigned char)((messageLengthHi & 0x0000ff0000000000ULL) >> 40);
            messageChunk[ChunkSize - 13] = (unsigned char)((messageLengthHi & 0x000000ff00000000ULL) >> 32);
            messageChunk[ChunkSize - 12] = (unsigned char)((messageLengthHi & 0x00000000ff000000ULL) >> 24);
            messageChunk[ChunkSize - 11] = (unsigned char)((messageLengthHi & 0x0000000000ff0000ULL) >> 16);
            messageChunk[ChunkSize - 10] = (unsigned char)((messageLengthHi & 0x000000000000ff00ULL) >> 8);
            messageChunk[ChunkSize - 9]  = (unsigned char)((messageLengthHi & 0x00000000000000ffULL));
        }

        // One last call to process the final block.
        (this->*processOp)();
    }

    // Initialize the constants (defined by SHA-1) and set the
    // processOp delegate to use the SHA-1 algorithm when processing the data chunk.
    void initSHA1(const std::string &file) {

        fileName = file;

        digest[0] = 0x67452301;
        digest[1] = 0xEFCDAB89;
        digest[2] = 0x98BADCFE;
        digest[3] = 0x10325476;
        digest[4] = 0xC3D2E1F0;

        processOp = &SHA2Impl::processSHA1Chunk;
    }


    // Initialize the SHA-256 constants and set the processOp
    // delegate to use the SHA-256 algorithm.
    void initSHA256(const std::string &file) {

        fileName = file;

        digest[0] = 0x6a09e667;
        digest[1] = 0xbb67ae85;
        digest[2] = 0x3c6ef372;
        digest[3] = 0xa54ff53a;
        digest[4] = 0x510e527f;
        digest[5] = 0x9b05688c;
        digest[6] = 0x1f83d9ab;
        digest[7] = 0x5be0cd19;

        processOp = &SHA2Impl::processSHA256Chunk;
    }


    // Initialize the SHA-224 constants and set the processOp
    // delegate to use the SHA-256 algorithm.
    // Note it's not a typo, it's the same algorithm with
    // different constants and a shorter message digest.
    void initSHA224(const std::string &file) {

        fileName = file;

        digest[0] = 0xc1059ed8;
        digest[1] = 0x367cd507;
        digest[2] = 0x3070dd17;
        digest[3] = 0xf70e5939;
        digest[4] = 0xffc00b31;
        digest[5] = 0x68581511;
        digest[6] = 0x64f98fa7;
        digest[7] = 0xbefa4fa4;

        processOp = &SHA2Impl::processSHA256Chunk;
    }

    // Initialize the SHA-384 constants and set the processOp
    // delegate to use the SHA-512 algorithm.
    // SHA-384 is the same as SHA-512 except different starting
    // constants and shorter digest.
    void initSHA384(const std::string &file) {

        fileName = file;

        digest[0] = 0xcbbb9d5dc1059ed8ULL;
        digest[1] = 0x629a292a367cd507ULL;
        digest[2] = 0x9159015a3070dd17ULL;
        digest[3] = 0x152fecd8f70e5939ULL;
        digest[4] = 0x67332667ffc00b31ULL;
        digest[5] = 0x8eb44a8768581511ULL;
        digest[6] = 0xdb0c2e0d64f98fa7ULL;
        digest[7] = 0x47b5481dbefa4fa4ULL;

        processOp = &SHA2Impl::processSHA512Chunk;
    }

    // Initialize the SHA-512 constants and set the processOp
    // delegate to use the SHA-512 algorithm.
    // Note also SHA-384 and SHA-512 use 64-bit integers instead of 32-bit.
    void initSHA512(const std::string &file) {

        fileName = file;

        digest[0] = 0x6a09e667f3bcc908ULL;
        digest[1] = 0xbb67ae8584caa73bULL;
        digest[2] = 0x3c6ef372fe94f82bULL;
        digest[3] = 0xa54ff53a5f1d36f1ULL;
        digest[4] = 0x510e527fade682d1ULL;
        digest[5] = 0x9b05688c2b3e6c1fULL;
        digest[6] = 0x1f83d9abfb41bd6bULL;
        digest[7] = 0x5be0cd19137e2179ULL;

        processOp = &SHA2Impl::processSHA512Chunk;
    }

    // Processes an entire file to produce the message digest.
    // The file name, and the processOp delegate have been set in the InitXXXX
    // functions above.
    void processFile() {

        std::streamsize bytesRead, bitsRead;
        std::basic_ifstream<char> inStream(fileName, std::ifstream::binary);

        // Apparently ifstream is not buffered at least on MSVC C++ runtime library.
        // The following line increases performance over 10x on Windows
        // (and thus puts it on par with the C runtime fopen/fread).
        // Note: Larger buffers do not seem to improve speed, and in fact
        // 4K is probably sufficient.
        inStream.rdbuf()->pubsetbuf(nullptr, 8192);

        bytesRead = 0;
        bitsRead = 0;
        while(inStream.good() == true && inStream.eof() == false) {

            inStream.read((char *)messageChunk, ChunkSize);
            bytesRead += inStream.gcount();

            bitsRead = bytesRead * std::numeric_limits<unsigned char>::digits;

            // Check for overflow...(...of a 64 bit unsigned int? Good luck to us all)
            if(bytesRead > 0) {
                if(messageLengthLo + bitsRead > messageLengthLo) {
                    messageLengthLo += bitsRead;
                }
                else {
                    messageLengthHi++;
                    messageLengthLo = bitsRead - 1;
                }
            }

            // Call the processOp delegate for this chunk, which has been set to
            // call the appropriate SHA algorithm.
            chunkOffset += bytesRead;
            if(bytesRead == ChunkSize) {
                (this->*processOp)();
                bytesRead = chunkOffset = 0;
            }

        }

        // Perform final padding of data as described in the
        // SHA-1 and SHA-2 specs. The final message digest
        // is calculated here.
        finalize();
    }


    // Constructor for the implementation. Set up the constants
    // used in the algorithms. These are called out in the SHA-2 specs.
    SHA2Impl()
    {
        k_512 = { {
                      0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
                      0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
                      0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
                      0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
                      0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
                      0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
                      0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
                      0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
                      0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
                      0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
                      0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
                      0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
                      0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
                      0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
                      0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
                      0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 } };

        k_256 = { {
                      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
                  } };

        messageLengthHi = 0;
        messageLengthLo = 0;
        chunkOffset = 0;
    }


public:

    static sha32BitFunc_t sha1()
    {
        // Return a function object that is set to perform
        // SHA-1 processing on a file.
        auto func = [](const std::string &file) {
            SHA2Impl<IntType, ChunkSize> s;
            s.initSHA1(file);
            s.processFile();
            s.digest[5] = s.digest[6] = s.digest[7] = 0;
            return s.digest;
        };

        return func;
    }


    // Return a function object that is set to perform
    // SHA256 processing on a file.
    static sha32BitFunc_t sha2_256()
    {
        auto func = [](const std::string &file) {
            SHA2Impl<IntType, ChunkSize> s;
            s.initSHA256(file);
            s.processFile();
            return s.digest;
        };

        return func;
    }


    // Return a function object that is set to perform
    // SHA224 processing on a file.
    static sha32BitFunc_t sha2_224()
    {
        auto func = [](const std::string &file) {
            SHA2Impl<IntType, ChunkSize> s;
            s.initSHA224(file);
            s.processFile();
            s.digest[7] = 0;
            return s.digest;
        };

        return func;
    }


    // Return a function object that is set to perform
    // SHA384 processing on a file.
    static sha64BitFunc_t sha2_384()
    {
        auto func = [](const std::string &file) {

            SHA2Impl<IntType, ChunkSize> s;

            s.initSHA384(file);
            s.processFile();
            s.digest[6] = s.digest[7] = 0;
            return s.digest;
        };

        return func;
    }


    // Return a function object that is set to perform
    // SHA512 processing on a file.
    static sha64BitFunc_t sha2_512()
    {
        auto func = [](const std::string &file) {
            SHA2Impl<IntType, ChunkSize> s;
            s.initSHA512(file);
            s.processFile();
            return s.digest;
        };

        return func;
    }

};

}
