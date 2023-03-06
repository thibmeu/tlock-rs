use crate::args::{Command, LockArgs, Options, UnlockArgs};
use anyhow::anyhow;
use cli_batteries::version;
use drand_core::{chain, http_chain_client};
use std::fs;

use tracing::{info, info_span, Instrument};

mod args;
mod time;

fn main() {
    cli_batteries::run(version!(), app);
}

async fn app(opts: Options) -> eyre::Result<()> {
    if let Some(command) = opts.command {
        match command {
            Command::Lock(args) => lock(args).await,
            Command::Unlock(args) => unlock(args).await,
        }
        .map_err(|e| eyre::anyhow!(e))?
    }

    Ok(())
}

async fn lock(args: LockArgs) -> anyhow::Result<()> {
    let chain = chain::Chain::new(&format!("{}/{}", args.network_host, args.chain_hash));
    let info = chain
        .info()
        .instrument(info_span!("getting network info"))
        .await
        .unwrap();

    let round_number = match args.round_number {
        None => {
            let d = args
                .duration
                .expect("duration is expected if round_number isn't specified")
                .into();
            time::round_after(&info, d)
        }
        Some(n) => n,
    };

    info!("locked until {round_number} round");

    let src = fs::File::open(args.input_path).map_err(|_e| anyhow!("error reading input file"))?;
    let dst =
        fs::File::create(args.output_path).map_err(|_e| anyhow!("error creating output file"))?;

    let info = chain.info().await?;
    tlock_age::encrypt(dst, src, &info.hash(), &info.public_key(), round_number)
}

async fn unlock(args: UnlockArgs) -> anyhow::Result<()> {
    let chain = chain::Chain::new(&format!("{}/{}", args.network_host, args.chain_hash));

    let src = fs::File::open(args.input_path.clone())
        .map_err(|_e| anyhow!("error reading input file"))?;

    let header = tlock_age::decrypt_header(src)?;
    let round = header.round();
    let chain_hash = header.hash();

    let src = fs::File::open(args.input_path).map_err(|_e| anyhow!("error reading input file"))?;
    let dst =
        fs::File::create(args.output_path).map_err(|_e| anyhow!("error creating output file"))?;

    use chain::ChainClient;
    let client = http_chain_client::HttpChainClient::new(chain, None);
    let beacon = client.get(round).await?;
    tlock_age::decrypt(dst, src, &chain_hash, &beacon.signature())
}
