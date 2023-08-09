use drand_core::HttpClient;

fn main() {
    let msg = b"Hello world! I'm encrypting a message using timelock encryption.".to_vec();

    // Use a drand client to retrieve beacon information
    let client: HttpClient =
        "https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493"
            .try_into()
            .unwrap();
    let info = client.chain_info().unwrap();
    let round = 1000;

    // Encryption as binary.
    let mut encrypted = vec![];
    tlock_age::encrypt(
        &mut encrypted,
        msg.as_slice(),
        &info.hash(),
        &info.public_key(),
        round,
    )
    .unwrap();

    // Decrypting the message. It requires the round signature, here retrieved from the beacon above.
    let mut decrypted = vec![];
    let signature = client.get(round).unwrap().signature();

    tlock_age::decrypt(
        &mut decrypted,
        encrypted.as_slice(),
        &info.hash(),
        &signature,
    )
    .unwrap();
    let decrypted = std::str::from_utf8(&decrypted).unwrap();

    println!("{decrypted}");
}
