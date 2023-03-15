use drand_core::{chain, http_chain_client};

#[tokio::main]
async fn main() {
    let chain = chain::Chain::new("https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf");
    let client = http_chain_client::HttpChainClient::new(chain, None);
    let info = client.chain().info().await.unwrap();

    let msg = vec![8; 32];
    let mut encrypted = vec![];
    tlock::encrypt(&mut encrypted, msg.as_slice(), &info.public_key(), 1000).unwrap();

    let beacon = client.get(1000).await.unwrap();

    let mut decrypted = vec![];
    tlock::decrypt(&mut decrypted, encrypted.as_slice(), &beacon.signature()).unwrap();

    assert_eq!(msg, decrypted);
    println!("Encryption and decryption were successful");
}
