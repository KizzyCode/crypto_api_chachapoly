[![docs.rs](https://docs.rs/crypto_api_chachapoly/badge.svg)](https://docs.rs/crypto_api_chachapoly)
[![License BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/crypto_api_chachapoly.svg)](https://crates.io/crates/crypto_api_chachapoly)
[![Download numbers](https://img.shields.io/crates/d/crypto_api_chachapoly.svg)](https://crates.io/crates/crypto_api_chachapoly)
[![Travis CI](https://travis-ci.org/KizzyCode/crypto_api_chachapoly.svg?branch=master)](https://travis-ci.org/KizzyCode/crypto_api_chachapoly)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/crypto_api_chachapoly?svg=true)](https://ci.appveyor.com/project/KizzyCode/crypto-api-chachapoly)
[![dependency status](https://deps.rs/crate/crypto_api_chachapoly/0.4.0/status.svg)](https://deps.rs/crate/crypto_api_chachapoly/0.4.0)

# crypto_api_chachapoly
Welcome to `crypto_api_chachapoly` 🎉


## About
This crate implements
[the IETF version of ChaCha20](https://tools.ietf.org/html/rfc8439#section-2.4), XChaCha20,
[Poly1305](https://tools.ietf.org/html/rfc8439#section-2.5),
[ChachaPoly-IETF AEAD construction](https://tools.ietf.org/html/rfc8439#section-2.8) and 
XChachaPoly.


## Security
⚠️ Some words of warning ahead: This library has not been audited yet – use at your own risk! ⚠️

However we try to do things right from the start – this library does not use unsafe Rust, is
[KISS](https://en.wikipedia.org/wiki/KISS_principle), tested against various test vectors and uses
constant time implementations only.

### Test Vectors
All implementations pass all reference test vectors and are assumed to produce correct results even
in corner cases. We also use API test vectors (to test input validation) and failure test vectors to
test our MAC verification.

### Fuzzing Against [`sodiumoxide`](https://crates.io/crates/sodiumoxide)
The git repository contains a `fuzz`-subcrate that generates random inputs and tests if this crate
and [`sodiumoxide`](https://crates.io/crates/sodiumoxide) produce the same result.

It can be run by cloning the git repo, going into "fuzz/" and running `cargo run --release`. The
crate uses all available CPU threads and stops only if there is an unexpected different result. You
can also specify the maximum length if the randomly generated and sized test input; just set 
`TEST_VECTOR_LIMIT` as environment variable. **If you find an unexpected different result, please
copy the entire output and create a new issue on GitHub! 😊**

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