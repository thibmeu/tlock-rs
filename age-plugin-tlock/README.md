# age-plugin-tlock: tlock plugin for age clients

[![Documentation](https://img.shields.io/badge/docs-main-blue.svg)][Documentation]
![License](https://img.shields.io/crates/l/age-plugin-tlock.svg)
[![crates.io](https://img.shields.io/crates/v/age-plugin-tlock.svg)][Crates.io]

[Crates.io]: https://crates.io/crates/age-plugin-tlock
[Documentation]: https://docs.rs/age-plugin-tlock/

`age-plugin-tlock` is a plugin for age clients like [`age`](https://age-encryption.org/) and [`rage`](https://str4d.xyz/rage), which enables files to be encrypted to age identities represented by drand networks.

> The code is still experimental. Installation is from source only at the moment.

## Tables of Content

* [Features](#features)
* [What's next](#whats-next)
* [Installation](#installation)
* [Usage](#usage)
  * [Generate recipient and identity](#generate-recipient-and-identity)
  * [Timelock encryption](#timelock-encryption)
* [Security Considerations](#security-considerations)
* [FAQ](#faq)
* [License](#license)

## Features

* Online and offline decryption
* Plugin for age
* Compatible with age plugin API
* Cross platform (Linux, Windows, macOS)
* Interoperable with other tlock implementations (Go, JS, Rust)

## What's next

* Crate publication
* Consensus on age format
* Wider test suite

## Installation

| Environment | CLI Command |
|:------------|:------------|
| Cargo (Rust 1.74+) | `cargo install --git https://github.com/thibmeu/tlock-rs age-plugin-tlock` |

Read [age installation instructions](https://github.com/FiloSottile/age#installation) to install age. 

## Usage

You can use the `--help` option to get more details about the command and its options.

```bash
age-plugin-tlock [OPTIONS]
```

### Generate recipient and identity

None of the recipient or identity is secret. The identity secrecy resides in its usefulness only after a certain point in time.

Create an identity for fastnet.
```
age-plugin-tlock --generate --remote https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493 > fastnet.key
```

For convenience, you can also create an associated recipient
```
cat fastnet.key | grep 'recipient' | sed 's/.*\(age1.*\)/\1/' > fastnet.key.pub
```

### Timelock encryption

Encrypt `Hello age-plugin-tlock!` string to round 30 seconds in the future, using fastnet publickey. If you wait 30 seconds before decrypting, the message is decrypted using the new fastnet signature.

```
echo "Hello age-plugin-tlock" | ROUND="30s" age -a -R fastnet.key.pub > data.age
age --decrypt -i fastnet.key data.age
Hello age-plugin-tlock
```

## Security Considerations

This software has not been audited. Please use at your sole discretion. With this in mind, dee security relies on the following:
* [tlock: Practical Timelock Encryption from Threshold BLS](https://eprint.iacr.org/2023/189) by Nicolas Gailly, Kelsey Melissaris, and Yolan Romailler, and its implementation in [thibmeu/tlock-rs](https://github.com/thibmeu/tlock-rs),
* [Identity-Based Encryption](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf) by Dan Boneh, and Matthew Franklin, and its implementation in [thibmeu/tlock-rs](https://github.com/thibmeu/tlock-rs),
* The [League of Entropy](https://www.cloudflare.com/leagueofentropy/) to remain honest,
* [age](https://github.com/C2SP/C2SP/blob/main/age.md) encryption protocol, and its implementation in [str4d/rage](https://github.com/str4d/rage),

## FAQ

### What is the age format

To operate with age tooling, `age-plugin-tlock` needs all informations to be available from both the recipient and identity. At encryption time, it needs a recipient. At decryption time, it needs the identity that completes the stanza information.

This format has been defined ad-hoc, and is likely to evolve in the future. It follows two design contraints. The first one is identity files need to be transferable. The second is to be offline first.

#### Stanza

```
tlock <ROUND> <HASH>
```

* `<ROUND>` is the drand beacon round number,
* `<HASH>` is a drand chain hash hex encoded,

Encoded in plain text.

Example
```
tlock 4641203 dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493
```

#### Recipient

```
age1tlock1<HASH><PUBLIC_KEY><GENESIS><PERIOD>
```

* `<HASH>` is a drand chain hash,
* `<PUBLIC_KEY>` is a drand chain public key,
* `<GENESIS>` is the genesis unix time of a drand chain in seconds,
* `<PERIOD>` is the period between rounds of a drand chain in seconds,

Encoded as wireformat bech32 text.

Example
```
age1tlock1yrda2pkkaamwtuux7swx28wtszx9hj7h23cucn40506d77k5unzfxc9qhp32w5nlaca8xx7tty5q4d4t6ck4czmw5q7ufh0kvyhaljwsruqux92z2sthryp5wh43a3npt7xsmu9ckmww8pvpr4kulr97lwr4ne0xz63al5z5ey5fgpmxmxjmnku3uwmf0ewhp2t4rq0qqlu8ljj7lng8rlmrqvpvft27
```

`<HASH>` is required to fill the stanza, nothing more. `<PUBLIC_KEY>` is required for tlock encryption. `<GENESIS>` and `<PERIOD>` are used to parse beacon round information. Round is provided at encryption time. This is a tradeoff between being able to reuse the same identity multiple times (one per drand chain), and having a more accurate recipient, which would be limited to round and public key information.

#### Identity

```
AGE-PLUGIN-TLOCK-<TYPE><IDENTITY>
```

* `<TYPE>` is 0 for `RAW` or 1 for `HTTP`. It provides flexibility on upgrading the identity between implementation and threat model,
* `<IDENTITY>` is the bytes of the beacon signature corresponding to the round for `RAW`, and is an remote HTTP URL in case of `HTTP`,

Encoded as wireformat bech32 text.

Example
```
AGE-PLUGIN-TLOCK-1Q9TXSAR5WPEN5TE0V9CXJTNYWFSKUEPWWD5Z7ERZVS6NQDNYXEJKVDEKV56KVVECXENRGVTRXC6NZERRVGURQWRRX43XXCNYXU6NGDE3VD3NGETPVESNXE35V3NRWCTYX3JNGCE58YEJ74QEJUM
```

### Other implementations

At the time of writting, there are no other implementation of tlock as an age plugin. Recipient and identities have been defined ad-hoc according to what seemed sensible to the author.

## License

This project is under the MIT license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be MIT licensed as above, without any additional terms or conditions.
