use drand_core::{chain, http_chain_client};

#[tokio::main]
async fn main() {
    let chain = chain::Chain::new("https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf");
    use chain::ChainClient;
    let client = http_chain_client::HttpChainClient::new(chain, None);
    let info = client.chain().info().await.unwrap();

    let msg = vec![8; 32];
    let ct = tlock::time_lock(&info.public_key(), 1000, &msg);

    let beacon = client.get(1000).await.unwrap();

    let pt = tlock::time_unlock(&beacon.signature(), &ct);

    assert_eq!(msg, pt);
}
