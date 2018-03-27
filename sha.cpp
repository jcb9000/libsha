// sha.cpp
// 
// Public API for calculating message digests
// using the SHA-1 and SHA-2 algorithms. 
//
// These methods return function objects that perform the respective SHA algorithm when called.
//
// The function objects can be called directly, but they could also 
// be put onto a work queue structure (such as a blocking queue) 
// to take advantage of multi-core processors.

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

#include "sha.h"
#include "sha2Impl.h"


namespace shautil {

// Return a function object that is set to perform
// SHA-1 processing on a file.
sha32BitFunc_t sha1()
{
    return SHA2Impl<uint32_t, 64>::sha1();
}

// Return a function object that is set to perform
// SHA256 processing on a file.
sha32BitFunc_t sha2_256()
{
    return SHA2Impl<uint32_t, 64>::sha2_256();
}

// Return a function object that is set to perform
// SHA224 processing on a file.
sha32BitFunc_t sha2_224()
{
    return SHA2Impl<uint32_t, 64>::sha2_224();
}

// Return a function object that is set to perform
// SHA384 processing on a file.
sha64BitFunc_t sha2_384()
{
    return SHA2Impl<uint64_t, 128>::sha2_384();
}

// Return a function object that is set to perform
// SHA512 processing on a file.
sha64BitFunc_t sha2_512()
{
    return SHA2Impl<uint64_t, 128>::sha2_512();
}

}
