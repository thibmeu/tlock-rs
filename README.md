# tlock-rs: Practical Timelock Encryption/Decryption in Rust

This repo contains pure Rust implementation of [`drand/tlock`](https://github.com/drand/tlock) scheme. It provides time-based encryption and decryption capabilities by relying on a [drand](https://drand.love/) threshold network and identity-based encryption (IBE). The IBE scheme implemented here is [`Boneh-Franklin`](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf).

## Usage
The tlock system relies on [an unchained drand network](https://drand.love/docs/cryptography/#randomness). Working endpoints to retrieve these beacons are, for now:
- https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493
- https://drand.cloudflare.com/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493

This crate does not provide a drand client. You can use [drand_core](https://github.com/thibmeu/drand-rs).

### Encrypt and decrypt

Code examples are provided in [tlock_age/examples](./tlock_age/examples).

`tlock_age` supports [ASCII Armor](https://github.com/C2SP/C2SP/blob/main/age.md#ascii-armor) in the same format as age.

## Known issues
- No cross-library compatibility at the moment
