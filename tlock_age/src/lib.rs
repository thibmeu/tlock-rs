mod tle_age;

use anyhow::anyhow;

use std::{
    io::{copy, Read, Write},
    iter,
};
use tle_age::{HeaderIdentity, Identity, Recipient};

pub fn encrypt<W: Write, R: Read>(
    dst: W,
    mut src: R,
    armor: bool,
    chain_hash: &[u8],
    public_key_bytes: &[u8],
    round: u64,
) -> anyhow::Result<()> {
    let recipient = Recipient::new(chain_hash, public_key_bytes, round);
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .expect("we provided a recipient");

    let output_format = if armor {
        age::armor::Format::AsciiArmor
    } else {
        age::armor::Format::Binary
    };
    let dst = age::armor::ArmoredWriter::wrap_output(dst, output_format)?;
    let mut writer = encryptor.wrap_output(dst)?;
    copy(&mut src, &mut writer)?;
    writer.finish().and_then(|armor| armor.finish()).unwrap();

    Ok(())
}
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

    pub fn round(&self) -> u64 {
        self.round
    }

    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
}

pub fn decrypt_header<R: Read>(src: R) -> anyhow::Result<Header> {
    let identity = HeaderIdentity::new();
    let decryptor = match age::Decryptor::new(age::armor::ArmoredReader::new(src)).unwrap() {
        age::Decryptor::Recipients(d) => d,
        _ => unreachable!(),
    };

    decryptor.decrypt(iter::once(&identity as &dyn age::Identity));
    match (identity.round(), identity.hash()) {
        (Some(round), Some(hash)) => Ok(Header::new(round, &hash)),
        _ => Err(anyhow!("Cannot decrypt round")),
    }
}

pub fn decrypt<W: Write, R: Read>(
    mut dst: W,
    src: R,
    chain_hash: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    let identity = Identity::new(chain_hash, signature);
    let decryptor = match age::Decryptor::new(age::armor::ArmoredReader::new(src)).unwrap() {
        age::Decryptor::Recipients(d) => d,
        _ => unreachable!(),
    };

    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .unwrap();
    copy(&mut reader, &mut dst)?;

    Ok(())
}
