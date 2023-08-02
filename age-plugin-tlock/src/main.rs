use age_plugin_tlock::{HTTPIdentityInfo, RecipientInfo};
use drand_core::{beacon, chain, HttpClient};
use tlock_age::Header;

mod cli;

pub const PLUGIN_NAME: &str = "tlock";

pub fn run_state_machine(state_machine: String) {
    // The plugin was started by an age client; run the state machine.
    age_plugin_tlock::run_state_machine(
        state_machine,
        PLUGIN_NAME,
        |info: &RecipientInfo, round: &str| {
            beacon::RandomnessBeaconTime::new(
                &chain::ChainTimeInfo::new(info.genesis_time(), info.period()),
                round,
            )
            .round()
        },
        |url: &str, header: &Header| {
            HttpClient::new(url, None)
                .unwrap()
                .get(header.round())
                .unwrap()
                .signature()
        },
    )
    .unwrap();
}

pub fn generate(url: &str) {
    let client = HttpClient::new(url, None).unwrap();
    let identity = HTTPIdentityInfo::new(&client.base_url());
    let recipient = RecipientInfo::new(
        &client.chain_info().unwrap().hash(),
        &client.chain_info().unwrap().public_key(),
        client.chain_info().unwrap().genesis_time(),
        client.chain_info().unwrap().period(),
    );
    age_plugin_tlock::print_new_identity(PLUGIN_NAME, &identity.into(), &recipient)
}

fn main() {
    let cli = cli::build();
    if let Some(state_machine) = cli.age_plugin {
        return run_state_machine(state_machine);
    }

    return generate(cli.remote.unwrap().as_str());
}
