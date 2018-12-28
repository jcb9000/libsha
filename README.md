# libsha

C++  implementation of SHA1 and SHA-2 digest algorithms
This C++ code will compile with g++, Microsoft C++, and Intel C++ (Version 16 tested). I have not 
tested it with clang. The code uses std::filesystem, so it requires C++17.

Note: This code does not (yet) account for endian-ness of the host processor. It was written and 
tested on Intel processors.

# Usage

The file `sha.h` provides the public API for this library. The functions reside in the shautil namespace. 

The `shautil` namespace provides methods that return callable function objects for each SHA algorithm implementation. The 
function objects take a file name as a parameter, and return the calculated message digest. The function objects 
can be called directly, but they could also be placed on a producer-consumer queue to compute multiple digests 
asynchronously.

## Types

The types exposed in the `shautil` namespace are:

* `sha32BitDigest_t`: Digest returned by the 32-bit SHA-2 algorithms (SHA-1, SHA-224, SHA-256)
* `sha64BitDigest_t`: Digest returned by 64-bit SHA-2 algorithms (SHA-384, SHA-512)
* `sha32BitFunc_t`: Type of function object used for 32-bit algorithms
* `sha64BitFunc_t`: Type of function object used for 64-bit algorithms

## Example Usage

Functions in the `shautil` namespace provide the means to get a callable function object. As noted above, 
the function object returns one of the digest types, and takes a file name as a parameter. For example,
this is the signature of the callable function object for a SHA-256 digest:

```
  shautil::sha32BitFunc_t calcSHA256(const std::string &fileName);
```

The following code snippet demonstrates how to use the library to calculate a SHA-256 digest.

```
  using namespace shautil;
  ...
  // Declare a function object and digest.
  sha32BitFunc_t calcSHA256;
  sha32BitDigest_t digest;
  ...

  // Ask for a function object to calculate the SHA-256 digest.
  calcSHA256 = sha2_256();
  ...

  // Use the function object to calculate the digest for file foo.txt. 
  digest = calcSHA256("foo.txt");
```

The `digest` is an array of size appropriate for the type of digest you are calculating. Here
is a simple example of how to print a computed message digest:

```
void printDigest(const sha::sha32BitDigest_t &digest)
{

  std::cout << "    digest = ";
  for(uint32_t d : digest) {
    std::cout << std::hex << d;
  }

  std::cout << "\n";

}
```

Alternatively, you can use the shautil::toString() method to convert a digest to a string:

```
std::string dString;

dString = shautil::toString(digest);
```
