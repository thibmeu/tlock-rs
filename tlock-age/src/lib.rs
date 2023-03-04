mod tle_age;

use std::{
    io::{copy, Read, Write},
    iter,
};
use tle_age::{Identity, Recipient};

pub fn encrypt<W: Write, R: Read>(
    network: tlock::client::Network,
    mut dst: W,
    mut src: R,
    round: u64,
) -> anyhow::Result<()> {
    let recipient = Recipient::new(network, round);
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .expect("we provided a recipient");

    let mut writer = encryptor.wrap_output(&mut dst).unwrap();
    copy(&mut src, &mut writer)?;
    writer.finish().unwrap();

    Ok(())
}

pub async fn decrypt<W: Write, R: Read>(
    network: tlock::client::Network,
    mut dst: W,
    src: R,
) -> anyhow::Result<()> {
    let identity = Identity::new(network);
    let decryptor = match age::Decryptor::new(src).unwrap() {
        age::Decryptor::Recipients(d) => d,
        _ => unreachable!(),
    };

    let mut reader = decryptor
        .decrypt(iter::once(&identity as &dyn age::Identity))
        .unwrap();
    copy(&mut reader, &mut dst)?;

    Ok(())
}
