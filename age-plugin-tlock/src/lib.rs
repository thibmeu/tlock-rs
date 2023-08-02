use std::{collections::HashMap, io};

use age::{Identity, Recipient};
use age_core::format::{FileKey, Stanza};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    Callbacks,
};
use bincode::{config, Decode, Encode};

use tlock_age::{internal::STANZA_TAG, Header};

/// Environment variable read to get round information non-interactively.
pub const ROUND_ENV: &str = "ROUND";

#[derive(Debug, Encode, Decode, PartialEq, Clone)]
/// Recipient information as defined for the age-plugin-tlock
/// These are required to encrypt information offline
/// hash is required for the stanza
/// public_key_bytes for encrypting towards
/// genesis_time and period to parse round information
pub struct RecipientInfo {
    hash: Vec<u8>,
    public_key_bytes: Vec<u8>,
    genesis_time: u64,
    period: u64,
}

impl RecipientInfo {
    pub fn new(hash: &[u8], public_key_bytes: &[u8], genesis_time: u64, period: u64) -> Self {
        Self {
            hash: hash.to_vec(),
            public_key_bytes: public_key_bytes.to_vec(),
            genesis_time,
            period,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, config::standard()).unwrap()
    }

    fn deserialize(data: &[u8]) -> Self {
        let (result, _) = bincode::decode_from_slice(data, config::standard()).unwrap();
        result
    }

    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }
    pub fn genesis_time(&self) -> u64 {
        self.genesis_time
    }
    pub fn period(&self) -> u64 {
        self.period
    }
}

struct RecipientPlugin {
    plugin_name: String,
    info: Option<RecipientInfo>,
    parse_round: fn(&RecipientInfo, &str) -> u64,
}

impl RecipientPlugin {
    pub fn new(plugin_name: &str, parse_round: fn(&RecipientInfo, &str) -> u64) -> Self {
        Self {
            plugin_name: plugin_name.to_owned(),
            info: None,
            parse_round,
        }
    }

    pub fn plugin_name(&self) -> String {
        self.plugin_name.clone()
    }

    pub fn info(&self) -> Option<RecipientInfo> {
        self.info.clone()
    }

    pub fn parse_round(&self, round: &str) -> u64 {
        (self.parse_round)(&self.info().unwrap(), round)
    }
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name == self.plugin_name() {
            let chain = RecipientInfo::deserialize(bytes);
            self.info = Some(chain);
            Ok(())
        } else {
            Err(recipient::Error::Recipient {
                index,
                message: "unsupported plugin".to_owned(),
            })
        }
    }

    fn add_identity(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        mut callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        let round = if let Ok(round) = std::env::var(ROUND_ENV) {
            round
        } else {
            let prompt_message = "Enter decryption round: ";
            match callbacks.request_public(prompt_message) {
                Ok(round) => round.unwrap_or("".to_owned()),
                Err(err) => return Err(err),
            }
        };
        let round = self.parse_round(&round);

        let info = self.info().unwrap();

        let recipient =
            tlock_age::internal::Recipient::new(&info.hash, &info.public_key_bytes, round);
        Ok(Ok(file_keys
            .into_iter()
            .map(|file_key| recipient.wrap_file_key(&file_key).unwrap())
            .collect()))
    }
}

/// Identity format as defined for the age-plugin-tlock
/// RAW allows for offline decryption of a specific round
/// HTTP allows for online decryption of an arbitrary round
pub enum IdentityFormat {
    RAW,
    HTTP,
}

#[derive(Debug, Encode, Decode, PartialEq, Clone)]
/// Identity information as defined for the age-plugin-tlock
pub enum IdentityInfo {
    RawIdentityInfo(RawIdentityInfo),
    HTTPIdentityInfo(HTTPIdentityInfo),
}

impl IdentityInfo {
    fn serialize(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, config::standard()).unwrap()
    }

    fn deserialize(data: &[u8]) -> Self {
        let (result, _) = bincode::decode_from_slice(data, config::standard()).unwrap();
        result
    }

    pub fn format(&self) -> IdentityFormat {
        match self {
            Self::RawIdentityInfo(_) => IdentityFormat::RAW,
            Self::HTTPIdentityInfo(_) => IdentityFormat::HTTP,
        }
    }
}

impl From<RawIdentityInfo> for IdentityInfo {
    fn from(value: RawIdentityInfo) -> Self {
        IdentityInfo::RawIdentityInfo(value)
    }
}

impl From<HTTPIdentityInfo> for IdentityInfo {
    fn from(value: HTTPIdentityInfo) -> Self {
        IdentityInfo::HTTPIdentityInfo(value)
    }
}

#[derive(Debug, Encode, Decode, PartialEq, Clone)]
pub struct RawIdentityInfo {
    signature: Vec<u8>,
}

impl RawIdentityInfo {
    pub fn new(signature: &[u8]) -> Self {
        Self {
            signature: signature.to_vec(),
        }
    }
}

#[derive(Debug, Encode, Decode, PartialEq, Clone)]
pub struct HTTPIdentityInfo {
    url: String,
}

impl HTTPIdentityInfo {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
        }
    }
}

struct IdentityPlugin {
    plugin_name: String,
    info: Option<IdentityInfo>,
    get_signature: fn(url: &str, header: &Header) -> Vec<u8>,
}

impl IdentityPlugin {
    pub fn new(
        plugin_name: &str,
        get_signature: fn(url: &str, header: &Header) -> Vec<u8>,
    ) -> Self {
        Self {
            plugin_name: plugin_name.to_owned(),
            info: None,
            get_signature,
        }
    }
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name == self.plugin_name.as_str() {
            let info = IdentityInfo::deserialize(bytes);
            self.info = Some(info);
            Ok(())
        } else {
            Err(identity::Error::Identity {
                index,
                message: "unsupported plugin".to_owned(),
            })
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        _callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut file_keys = HashMap::with_capacity(files.len());

        for (file, stanzas) in files.iter().enumerate() {
            for (_stanza_index, stanza) in stanzas.iter().enumerate() {
                if stanza.tag != STANZA_TAG {
                    continue;
                }
                if stanza.args.len() != 2 {
                    continue; // TODO: should be an error
                }
                let [round, hash] = [stanza.args[0].clone(), stanza.args[1].clone()];
                let round = round.parse().unwrap();
                let hash = hex::decode(hash).unwrap();
                let header = Header::new(round, &hash);

                let signature = match self.info.as_ref().unwrap() {
                    IdentityInfo::HTTPIdentityInfo(info) => {
                        (self.get_signature)(info.url.as_str(), &header)
                    }
                    IdentityInfo::RawIdentityInfo(info) => info.signature.clone(),
                };
                let identity = tlock_age::internal::Identity::new(&hash, &signature);

                let file_key = identity.unwrap_stanza(stanza).unwrap();
                let r = file_key.map_err(|e| {
                    vec![identity::Error::Identity {
                        index: file,
                        message: format!("{e}"),
                    }]
                });

                file_keys.entry(file).or_insert_with(|| r);
            }
        }
        Ok(file_keys)
    }
}

/// Run the state machine for the plugin, as defined on [GitHub](https://github.com/C2SP/C2SP/blob/main/age-plugin.md).
/// This is the entry point for the plugin. It is called by the age client.
pub fn run_state_machine(
    state_machine: String,
    plugin_name: &str,
    parse_round: fn(&RecipientInfo, &str) -> u64,
    get_signature: fn(&str, &Header) -> Vec<u8>,
) -> io::Result<()> {
    // The plugin was started by an age client; run the state machine.
    age_plugin::run_state_machine(
        &state_machine,
        || RecipientPlugin::new(plugin_name, parse_round),
        || IdentityPlugin::new(plugin_name, get_signature),
    )
}

/// Print the new identity information.
pub fn print_new_identity(plugin_name: &str, identity: &IdentityInfo, recipient: &RecipientInfo) {
    age_plugin::print_new_identity(plugin_name, &identity.serialize(), &recipient.serialize())
}
