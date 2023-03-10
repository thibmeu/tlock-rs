use std::{
    io,
    sync::{Arc, Mutex},
};

use age::secrecy::{ExposeSecret, Zeroize};
use age_core::format::{FileKey, Stanza};

pub const STANZA_TAG: &str = "tlock";

// Identity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
pub struct Identity {
    hash: Vec<u8>,
    signature: Vec<u8>,
}

impl Identity {
    pub fn new(hash: &[u8], signature: &[u8]) -> Self {
        Self {
            hash: hash.to_vec(),
            signature: signature.to_vec(),
        }
    }
}

impl age::Identity for Identity {
    // Unwrap is called by the age Decrypt API and is provided the DEK that was time
    // lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we decrypt
    // the DEK and provide back to age.
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 2 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let args: [String; 2] = [stanza.args[0].clone(), stanza.args[1].clone()];

        let _round = match args[0].parse::<u64>() {
            Ok(round) => round,
            Err(_err) => return Some(Err(age::DecryptError::InvalidHeader)),
        };

        if self.hash != hex::decode(&args[1]).unwrap() {
            return Some(Err(age::DecryptError::InvalidHeader));
        }

        let dst = InMemoryWriter::new();
        let decryption = tlock::decrypt(dst.to_owned(), &stanza.body[..], &self.signature);
        match decryption {
            Ok(_) => {
                let mut dst = dst.memory();
                dst.resize(16, 0);
                let file_key: [u8; 16] = dst[..].try_into().unwrap();
                Some(Ok(file_key.into()))
            }
            Err(_err) => Some(Err(age::DecryptError::DecryptionFailed)),
        }
    }
}

// Identity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
pub struct HeaderIdentity {
    hash: Mutex<Option<Vec<u8>>>,
    round: Mutex<Option<u64>>,
}

impl HeaderIdentity {
    pub fn new() -> Self {
        Self {
            hash: Mutex::new(None),
            round: Mutex::new(None),
        }
    }

    pub fn hash(&self) -> Option<Vec<u8>> {
        self.hash.lock().unwrap().clone()
    }

    pub fn round(&self) -> Option<u64> {
        *self.round.lock().unwrap()
    }
}

impl age::Identity for HeaderIdentity {
    // Unwrap is called by the age Decrypt API and is provided the DEK that was time
    // lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we extract
    // tlock header and assign it to the identity.
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 2 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let args: [String; 2] = [stanza.args[0].clone(), stanza.args[1].clone()];

        let round = match args[0].parse::<u64>() {
            Ok(round) => round,
            Err(_err) => return Some(Err(age::DecryptError::InvalidHeader)),
        };
        let hash = match hex::decode(&args[1]) {
            Ok(hash) => hash,
            Err(_) => return Some(Err(age::DecryptError::InvalidHeader)),
        };

        *self.round.lock().unwrap() = Some(round);
        *self.hash.lock().unwrap() = Some(hash);
        None
    }
}

/// Recipient implements the age Recipient interface. This is used to encrypt
/// data with the age Encrypt API.
pub struct Recipient {
    hash: Vec<u8>,
    public_key_bytes: Vec<u8>,
    round: u64,
}

impl Recipient {
    pub fn new(hash: &[u8], public_key_bytes: &[u8], round: u64) -> Self {
        Self {
            hash: hash.to_vec(),
            public_key_bytes: public_key_bytes.to_vec(),
            round,
        }
    }
}

#[derive(Clone)]
struct InMemoryWriter {
    memory: Arc<Mutex<Vec<u8>>>,
}

impl InMemoryWriter {
    pub fn new() -> Self {
        Self {
            memory: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn memory(&self) -> Vec<u8> {
        self.memory.lock().unwrap().to_owned()
    }
}

impl io::Write for InMemoryWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.memory.lock().unwrap().extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.memory.lock().unwrap().to_owned().zeroize();
        Ok(())
    }
}

impl age::Recipient for Recipient {
    /// Wrap is called by the age Encrypt API and is provided the DEK generated by
    /// age that is used for encrypting/decrypting data. Inside of Wrap we encrypt
    /// the DEK using time lock encryption.
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, age::EncryptError> {
        let src = &file_key.expose_secret()[..];
        let dst = InMemoryWriter::new();
        let _ = tlock::encrypt(dst.to_owned(), src, &self.public_key_bytes, self.round);

        Ok(vec![Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![self.round.to_string(), hex::encode(&self.hash)],
            body: dst.memory(),
        }])
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        iter,
    };

    use drand_core::{chain, http_chain_client};

    use crate::{Identity, Recipient};

    #[tokio::test]
    async fn it_works() {
        let chain = chain::Chain::new("https://pl-us.testnet.drand.sh/7672797f548f3f4748ac4bf3352fc6c6b6468c9ad40ad456a397545c6e2df5bf");
        let info = chain.info().await.unwrap();

        let client = http_chain_client::HttpChainClient::new(chain, None);

        let round = 100;
        let beacon = client.get(round).await.unwrap();
        let id = Identity::new(&info.hash(), &beacon.signature());
        let recipient = Recipient::new(&info.hash(), &info.public_key(), round);

        let mut plaintext = vec![0u8; 1000];
        plaintext.fill_with(rand::random);
        let encrypted = {
            let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
                .expect("we provided a recipient");

            let mut encrypted = vec![];
            let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
            writer.write_all(&plaintext).unwrap();
            writer.finish().unwrap();

            encrypted
        };

        let decrypted = {
            let decryptor = match age::Decryptor::new(&encrypted[..]).unwrap() {
                age::Decryptor::Recipients(d) => d,
                _ => unreachable!(),
            };

            let mut decrypted = vec![];
            let mut reader = decryptor
                .decrypt(iter::once(&id as &dyn age::Identity))
                .unwrap();
            reader.read_to_end(&mut decrypted).unwrap();

            decrypted
        };

        assert_eq!(decrypted, plaintext);
    }
}
