# tlock: Practical Timelock Encryption/Decryption in Rust

[![Documentation](https://img.shields.io/badge/docs-main-blue.svg)][Documentation]
![License](https://img.shields.io/crates/l/tlock_age.svg)
[![crates.io](https://img.shields.io/crates/v/tlock_age.svg)][Crates.io]

[Crates.io]: https://crates.io/crates/tlock_age
[Documentation]: https://docs.rs/tlock_age/

tlock is a library to encrypt and decrypt 16-byte binaries using [tlock](https://eprint.iacr.org/2023/189) scheme. It provides `encrypt` and `decrypt` methods consuming Threshold BLS signatures provided by [drand](https://drand.love/docs/specification/) beacons.

The reference interroperable Go implementation is available at [drand/tlock](https://github.com/drand/tlock).

## Tables of Content

* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [Security Considerations](#security-considerations)
* [FAQ](#faq)
* [License](#license)

## Features

* Timelock encryption and decryption of 16-byte u8 array
* Encryption with public key on G1 and G2
* Interroperability with Go and JS implementation
* wasm32 compatible library

## Installation

| Environment        | CLI Command               |
|:-------------------|:--------------------------|
| Cargo (Rust 1.74+) | `cargo install tlock` |

The library is tested against the following targets: `x86_64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`, `aarch64-unknown-linux-gnu`, `wasm32-wasi`.

## Usage

Code examples are provided in [tlock/examples](./examples).

The tlock system relies on [unchained drand networks](https://drand.love/docs/cryptography/#randomness).

This crate does not provide a drand client. You can use [drand_core](https://github.com/thibmeu/drand-rs).

## Security Considerations

This software has not been audited. Please use at your sole discretion. With this in mind, dee security relies on the following:
* [tlock: Practical Timelock Encryption from Threshold BLS](https://eprint.iacr.org/2023/189) by Nicolas Gailly, Kelsey Melissaris, and Yolan Romailler, and its implementation in [drand/tlock](https://github.com/drand/tlock),
* [Identity-Based Encryption](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf) by Dan Boneh, and Matthew Franklin, and its implementation in [thibmeu/tlock-rs](https://github.com/thibmeu/tlock-rs),
* The choosen drand beacon to remain honest,

## FAQ

### I want to encrypt more than 16 bytes

You should consider using [tlock_age](https://github.com/thibmeu/tlock-rs). It relies on this library to encrypt an [age](https://github.com/C2SP/C2SP/blob/main/age.md) filekey, allowing for file of arbitrary size to use timelock-encryption.

### How does practical timelock encryption work

For the simple explanation, you can use [Handwaving Cryptography](../assets/handwaving-cryptography.md).

For a more detailed one, you should take time to read [tlock: Practical Timelock Encryption from Threshold BLS](https://eprint.iacr.org/2023/189) by Nicolas Gailly, Kelsey Melissaris, and Yolan Romailler.

### RFC 9380 Hashing to Elliptic Curve

[RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) standardises a lot of interactions with elliptic curves. tlock did not use it first, and has been upgraded to support it. The feature `rfc9380` is enabled by default starting 0.0.4. This is not a backward compatible change.

## License

This project is under the MIT license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be MIT licensed as above, without any additional terms or conditions.
