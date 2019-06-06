[![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Travis CI](https://travis-ci.org/KizzyCode/crypto_api_chachapoly.svg?branch=master)](https://travis-ci.org/KizzyCode/crypto_api_chachapoly)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/crypto_api_chachapoly?svg=true)](https://ci.appveyor.com/project/KizzyCode/crypto-api-chachapoly)

# crypto_api_chachapoly
Welcome to `crypto_api_chachapoly` 🎉


## About
This crate implements
[the IETF version of ChaCha20](https://tools.ietf.org/html/rfc8439#section-2.4),
[Poly1305](https://tools.ietf.org/html/rfc8439#section-2.5) and the
[ChachaPoly-IETF AEAD construction](https://tools.ietf.org/html/rfc8439#section-2.8).


## Security
⚠️ Some words of warning ahead: This library is alpha and has not been audited yet – use at your
own risk! ⚠️

However we try to do things right from the start – this library is
[KISS](https://en.wikipedia.org/wiki/KISS_principle), tested against various test vectors and uses
constant time implementations only.

### Test Vectors
All implementations pass all reference test vectors and are assumed to produce correct results even
in corner cases. We also use API test vectors (to test input validation) and failure test vectors to
test our MAC verification.

### Constant Time Implementations
All implementations are designed to be invulnerable against timing side-channel attacks by
performing all secret-dependent computations in constant time:
 - ChaCha20 already does this by design
 - Poly1305 is based on the 
   [public domain Poly1305-Donna implementation (32 bit version)](https://github.com/floodyberry/poly1305-donna)
   with some ideas from [BearSSL](https://bearssl.org) (note that this implementation may not be
   constant time [on some older/low end ARM CPUs](https://bearssl.org/ctmul.html#arm))
 - The AEAD construction is also constant time by design (provided that both underlying algorithms
   are constant time)

For more information about constant time implementations, take a look
[here](https://bearssl.org/constanttime.html) and [here](https://bearssl.org/ctmul.html).

### Memory Hygiene
`crypto_api_chachapoly` does not perform any attempts to erase sensitive contents from memory.
However all sensitive contents are stored in heap-allocated memory, so if you're using an erasing
memory-allocator like [MAProper](https://crates.io/crates/ma_proper) they will be erased nontheless.

Using an erasing memory allocator is a good idea anyway, because Rust makes it pretty hard to keep
track on how the memory is managed under the hood – the memory allocator on the other hand sees
everything that happens on the heap and can take care of it accordingly.


## Dependencies
Because this code implements the [`crypto_api`](https://github.com/KizzyCode/crypto_api), it depends
on the `crypto_api`-crate. Otherwise, it's dependency less.

(There are optional dependencies for[`rand`](https://crates.io/crates/rand) and
[`sodiumoxide`](https://crates.io/crates/sodiumoxide) for the example which are only compiled if the
feature `run_examples` is specified.)