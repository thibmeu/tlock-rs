//! # tlock_age
//!
//! tlock_age is a library to encrypt and decrypt messages using tlock encryption scheme and age encryption.
//! The reference interroperable Go implementation is available at [drand/tlock](https://github.com/drand/tlock).
//!
//! tlock relies on BLS, content is encrypted against BLS public key. Public key group is assessed based on the public key size.
//! age implementation is [str4d/rage](https://github.com/str4d/rage). When encrypting file, it generates an additional stanza `grease-the-join`, which other tlock implementation have to ignore.
//!
//! Both encryption and decryption are performed wihout network access. tlock_age expects the caller interact with the drand network of their choice, through whichever method they wish. To that end, a dedicated method `decrypt_header` is provided.
//! It's important to note that `decrypt_header` consumes bytes from the reader, and reader requires these headers to be passed as well. The caller needs to duplicates these inputs if needed.
//!
//! ## Features
//!
//! - `armor`: Enable armor output. This is required if you want to output bytes are ASCII printable.
//!
//! ## Example
//!
//! For a working example, refer to [examples/encrypt_decrypt.rs](../examples/encrypt_decrypt.rs).

#[cfg(feature = "armor")]
pub mod armor;
mod tle_age;

use std::{
    io::{self, copy, Read, Write},
    iter,
};
use thiserror::Error;
use tle_age::{HeaderIdentity, Identity, Recipient};

#[derive(Error, Debug)]
pub enum TLockAgeError {
    #[error(transparent)]
    Decrypt(#[from] age::DecryptError),
    #[error("cannot parse header. partial information: round {round:?}, chain {chain:?}")]
    Header {
        round: Option<String>,
        chain: Option<String>,
    },
    #[error("recipient cannot be a passphrase")]
    InvalidRecipient,
    #[error(transparent)]
    IO(#[from] io::Error),
}

/// Encrypt using tlock encryption scheme and age encryption.
///
/// `round` and `public_key` information are stored as an age header.
///
/// If you want to armor the output to output bytes are ASCII printable, you must enable `armor` feature.
///
/// Example using an empty 100-byte message, fastnet public key, at round 1000
///
/// ```rust
/// // curl -sS https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/info | jq -r '.public_key'
/// let chain_hash = hex::decode("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493").unwrap();
/// let pk_bytes = hex::decode("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e").unwrap();
/// let round = 1000;
/// let src = vec![0u8; 100];
///
/// // without armor
/// let mut encrypted = vec![];
/// tlock_age::encrypt(&mut encrypted, src.as_slice(), &chain_hash, &pk_bytes, round).unwrap();
///
/// // with armor
/// let mut encrypted = vec![];
/// let mut encrypted = tlock_age::armor::ArmoredWriter::wrap_output(encrypted).unwrap();
/// tlock_age::encrypt(&mut encrypted, src.as_slice(), &chain_hash, &pk_bytes, round);
/// encrypted.finish().unwrap();
/// ```
pub fn encrypt<W: Write, R: Read>(
    dst: W,
    mut src: R,
    chain_hash: &[u8],
    public_key_bytes: &[u8],
    round: u64,
) -> anyhow::Result<()> {
    let recipient = Recipient::new(chain_hash, public_key_bytes, round);
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .expect("we provided a recipient");

    let mut writer = encryptor.wrap_output(dst)?;
    copy(&mut src, &mut writer)?;
    writer.finish()?;

    Ok(())
}

/// Information stored in tlock age header
pub struct Header {
    round: u64,
    hash: Vec<u8>,
}

impl Header {
    fn new(round: u64, hash: &[u8]) -> Self {
        Self {
            round,
            hash: hash.to_vec(),
        }
    }

    /// Round the message is encrypted to.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Hash of the chain used to encrypt the message.
    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
}

/// Decrypt tlock age header.
///
/// tlock_age uses age encryption, and age header. These information might be needed before decryption.
/// For instance, one need to retrieve the round a message is encrypted to, in order to retrieve it.
///
/// Example using an empty 100-byte message, fastnet public key, at round 1000
///
/// ```rust
/// let chain_hash = hex::decode("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493").unwrap();
/// // curl -sS https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/1000 | jq -r '.signature'
/// let signature = hex::decode("b09eacd45767c4d58306b98901ad0d6086e2663766f3a4ec71d00cf26f0f49eaf248abc7151c60cf419c4e8b37e80412").unwrap();
///
/// // This message is the encryption of an empty 100-byte message, using fastnet public key, at round 1000
/// let encrypted = "-----BEGIN AGE ENCRYPTED FILE-----
/// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEwMDAgZGJkNTA2ZDZlZjc2
/// ZTVmMzg2ZjQxYzY1MWRjYjgwOGM1YmNiZDc1NDcxY2M0ZWFmYTNmNGRmN2FkNGU0
/// YzQ5MwppZ09hY2VnNC9hNUNrYzJXVTlhWkpkRHpFUkZOWWNaSDZVdy9tc2tiWXlK
/// SWx3Rnc2QWU4TDMzUXpZQ2NiY0dSCkRPZXFYeGl1dWI1SUVkRUVlV1doWkFTNmxk
/// TG02TDhZTDFCTE1HZ1ZPVHF2b2xQVDhYQVlSMGk4aUJNTFJyTGMKYStBbFQvZEtI
/// eWZIa0VrYW56ZFBNQ0l4WDFmOGlkU2N6RHpVZk92WGYrYwotPiAlVl8tZ3JlYXNl
/// CldreTFpeWxFdGd5MlZXRjJzZDdiRHRXc3dkc0VRQmVuUTA0MUdoY3R2QjQKLS0t
/// IEJyTDlWVEIvem5mbjFxYzlzYTUyTGFITm5iOGVQTFIwMzg5bUJQQU92a2cKB1ca
/// 67u0wjEVoC/sRHsi+F7E2SJ6Z7bQQAva+dS1YYpXt07AdXOmqllqVGy8YGhi3wSf
/// ZlxKpBAQw+Lz+nvn5vCJPPNQcp264wTd6om5h9QnuHBkxkbr7JBqBeRxNucdl6El
/// 2af/n+e6s7cuhvvZp/TPTtV000+2Crq8kmAQIpzTdVIe
/// -----END AGE ENCRYPTED FILE-----".as_bytes();
///
/// let header = tlock_age::decrypt_header(encrypted).unwrap();
/// ```
pub fn decrypt_header<R: Read>(src: R) -> anyhow::Result<Header, TLockAgeError> {
    let identity = HeaderIdentity::new();
    #[cfg(feature = "armor")]
    let src = age::armor::ArmoredReader::new(src);
    let decryptor = match age::Decryptor::new(src) {
        Ok(age::Decryptor::Recipients(d)) => d,
        Ok(age::Decryptor::Passphrase(_)) => return Err(TLockAgeError::InvalidRecipient),
        Err(e) => return Err(TLockAgeError::Decrypt(e)),
    };

    let _ = decryptor.decrypt(iter::once(&identity as &dyn age::Identity));
    match (identity.round(), identity.hash()) {
        (Some(round), Some(hash)) => Ok(Header::new(round, &hash)),
        (Some(round), None) => Err(TLockAgeError::Header {
            round: Some(round.to_string()),
            chain: None,
        }),
        (None, Some(hash)) => Err(TLockAgeError::Header {
            round: None,
            chain: Some(hex::encode(hash)),
        }),
        _ => Err(TLockAgeError::Header {
            round: None,
            chain: None,
        }),
    }
}

/// Decrypt using tlock encryption scheme and age encryption.
///
/// round and public key information are retrieved from age header.
/// signature has to be the one for that round.
/// src can be armored or not, decryption supports both.
///
/// Example using an empty 100-byte message, fastnet public key, at round 1000
///
/// ```rust
/// let chain_hash = hex::decode("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493").unwrap();
/// // curl -sS https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/1000 | jq -r '.signature'
/// let signature = hex::decode("b09eacd45767c4d58306b98901ad0d6086e2663766f3a4ec71d00cf26f0f49eaf248abc7151c60cf419c4e8b37e80412").unwrap();
///
/// // This message is the encryption of an empty 100-byte message, using fastnet public key, at round 1000
/// let encrypted = "-----BEGIN AGE ENCRYPTED FILE-----
/// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEwMDAgZGJkNTA2ZDZlZjc2
/// ZTVmMzg2ZjQxYzY1MWRjYjgwOGM1YmNiZDc1NDcxY2M0ZWFmYTNmNGRmN2FkNGU0
/// YzQ5MwppZ09hY2VnNC9hNUNrYzJXVTlhWkpkRHpFUkZOWWNaSDZVdy9tc2tiWXlK
/// SWx3Rnc2QWU4TDMzUXpZQ2NiY0dSCkRPZXFYeGl1dWI1SUVkRUVlV1doWkFTNmxk
/// TG02TDhZTDFCTE1HZ1ZPVHF2b2xQVDhYQVlSMGk4aUJNTFJyTGMKYStBbFQvZEtI
/// eWZIa0VrYW56ZFBNQ0l4WDFmOGlkU2N6RHpVZk92WGYrYwotPiAlVl8tZ3JlYXNl
/// CldreTFpeWxFdGd5MlZXRjJzZDdiRHRXc3dkc0VRQmVuUTA0MUdoY3R2QjQKLS0t
/// IEJyTDlWVEIvem5mbjFxYzlzYTUyTGFITm5iOGVQTFIwMzg5bUJQQU92a2cKB1ca
/// 67u0wjEVoC/sRHsi+F7E2SJ6Z7bQQAva+dS1YYpXt07AdXOmqllqVGy8YGhi3wSf
/// ZlxKpBAQw+Lz+nvn5vCJPPNQcp264wTd6om5h9QnuHBkxkbr7JBqBeRxNucdl6El
/// 2af/n+e6s7cuhvvZp/TPTtV000+2Crq8kmAQIpzTdVIe
/// -----END AGE ENCRYPTED FILE-----".as_bytes();
///
/// let decrypted = vec![];
/// tlock_age::decrypt(decrypted, encrypted, &chain_hash, &signature).unwrap();
/// ```
pub fn decrypt<W: Write, R: Read>(
    mut dst: W,
    src: R,
    chain_hash: &[u8],
    signature: &[u8],
) -> anyhow::Result<(), TLockAgeError> {
    let identity = Identity::new(chain_hash, signature);
    #[cfg(feature = "armor")]
    let src = age::armor::ArmoredReader::new(src);
    let decryptor = match age::Decryptor::new(src) {
        Ok(age::Decryptor::Recipients(d)) => d,
        Ok(age::Decryptor::Passphrase(_)) => return Err(TLockAgeError::InvalidRecipient),
        Err(e) => return Err(TLockAgeError::Decrypt(e)),
    };

    let mut reader = match decryptor.decrypt(iter::once(&identity as &dyn age::Identity)) {
        Ok(reader) => reader,
        Err(e) => return Err(TLockAgeError::Decrypt(e)),
    };
    copy(&mut reader, &mut dst)?;

    Ok(())
}
