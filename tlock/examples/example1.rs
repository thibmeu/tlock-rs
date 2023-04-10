use drand_core::HttpClient;

#[tokio::main]
async fn main() {
    let client: HttpClient =
        "https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493"
            .try_into()
            .unwrap();
    let info = client.chain_info().await.unwrap();

    let msg = vec![8; 16];
    let mut encrypted = vec![];
    tlock::encrypt(&mut encrypted, msg.as_slice(), &info.public_key(), 1000).unwrap();

    let beacon = client.get(1000).await.unwrap();

    let mut decrypted = vec![];
    tlock::decrypt(&mut decrypted, encrypted.as_slice(), &beacon.signature()).unwrap();

    assert_eq!(msg, decrypted);
    println!("Encryption and decryption were successful");
}
