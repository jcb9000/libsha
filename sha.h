// sha.h 
// 
// Public API for calculating message digests
// using the SHA-1 and SHA-2 algorithms. 

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
#include <sstream>
#include <ios>
#include <inttypes.h>
#include <filesystem>
#include <functional>


namespace shautil {

// SHA function return type
template<typename D>
struct shaResult {
    std::filesystem::path path;
    D digest;
};


// Public types usable by both the caller and internally.
using sha32BitDigest_t = std::array<uint32_t, 8>;
using sha32BitFunc_t = std::function<shaResult<sha32BitDigest_t>(const std::filesystem::path &path)>;
using sha64BitDigest_t = std::array<uint64_t, 8>;
using sha64BitFunc_t = std::function<shaResult<sha64BitDigest_t>(const std::filesystem::path &path)>;

// See sha.cpp for brief descriptions,
// and sha2Impl.h for full descriptions.
sha32BitFunc_t sha1();
sha32BitFunc_t sha2_256();
sha32BitFunc_t sha2_224();
sha64BitFunc_t sha2_384();
sha64BitFunc_t sha2_512();



/*
 * Function to convert the digest into a string
 */
template<typename D> std::string toString(const D &digest)
{
    std::ostringstream dstream;
    dstream << std::hex;
    for(auto d : digest) {
        dstream << d;
    }

    return dstream.str();
}

}
