#[cfg(feature = "armor")]
pub mod armor;
mod tle_age;

use anyhow::anyhow;

use std::{
    io::{copy, Read, Write},
    iter,
};
use tle_age::{HeaderIdentity, Identity, Recipient};

/// Encrypt using tlock encryption scheme and age encryption.
///
/// `round` and `public_key` information are stored as an age header.
///
/// If you want to armor the output to output bytes are ASCII printable, you must enable `armor` feature.
///
/// Example using an empty 100-byte message, fastnet public key, at round 1000
///
/// ```rust
/// // curl -sS https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/info | jq -r '.public_key'
/// let chain_hash = hex::decode("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493").unwrap();
/// let pk_bytes = hex::decode("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e").unwrap();
/// let round = 1000;
/// let src = vec![0u8; 1000];
///
/// // without armor
/// let mut encrypted = vec![];
/// tlock_age::encrypt(&mut encrypted, src.as_slice(), &chain_hash, &pk_bytes, round).unwrap();
///
/// // with armor
/// let mut encrypted = vec![];
/// let mut encrypted = tlock_age::armor::ArmoredWriter::wrap_output(encrypted).unwrap();
/// tlock_age::encrypt(&mut encrypted, src.as_slice(), &chain_hash, &pk_bytes, round);
/// encrypted.finish().unwrap();
/// ```
pub fn encrypt<W: Write, R: Read>(
    dst: W,
    mut src: R,
    chain_hash: &[u8],
    public_key_bytes: &[u8],
    round: u64,
) -> anyhow::Result<()> {
    let recipient = Recipient::new(chain_hash, public_key_bytes, round);
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .expect("we provided a recipient");

    let mut writer = encryptor.wrap_output(dst)?;
    copy(&mut src, &mut writer)?;
    writer.finish()?;

    Ok(())
}

/// Information stored in tlock age header
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

    /// Round the message is encrypted to.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Hash of the chain used to encrypt the message.
    pub fn hash(&self) -> Vec<u8> {
        self.hash.clone()
    }
}

/// Decrypt tlock age header.
///
/// tlock_age uses age encryption, and age header. These information might be needed before decryption.
/// For instance, one need to retrieve the round a message is encrypted to, in order to retrieve it.
///
/// Example using an empty 100-byte message, fastnet public key, at round 1000
///
/// ```rust
/// let chain_hash = hex::decode("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493").unwrap();
/// // curl -sS https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/1000 | jq -r '.signature'
/// let signature = hex::decode("b09eacd45767c4d58306b98901ad0d6086e2663766f3a4ec71d00cf26f0f49eaf248abc7151c60cf419c4e8b37e80412").unwrap();
///
/// // This message is the encryption of an empty 100-byte message, using fastnet public key, at round 1000
/// let encrypted = "-----BEGIN AGE ENCRYPTED FILE-----
/// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEwMDAgZGJkNTA2ZDZlZjc2
/// ZTVmMzg2ZjQxYzY1MWRjYjgwOGM1YmNiZDc1NDcxY2M0ZWFmYTNmNGRmN2FkNGU0
/// YzQ5MwpqRDhmd1B3a3BEOG01WThxY2VNdjl5Wko1elMzdDJ2RS9MWUhEYW16T1E4
/// K3BqMGZ1Nm1RSjF3Tk1zNDZqWnU4CkVydkRaQU5hd2lBL1oxZHlka2NrbUR5bHBz
/// cTl2SUY5OE80NlVvT2dCcms4M004dk1VWkFnVGNyR3dJM2tSd0IKbDN3TUdoRi9K
/// QWlmWlFodjlrVEVIMmJ1VWZJRVhpanZkSWFrTFovbnhpZ2V5b3ZpUk1LQnNEZmx2
/// N2pJdUhGcQp3VFEvNWJ2MWZZMXAxWkhMRU4vVnh3Ci0+IGdVV0FmPD5JLWdyZWFz
/// ZQpteVBMbHlLcGJlUzVFSk1mMmk3OWVDS0FBYzBFNTdvT2hUK1NVWFM1SjNyMW1L
/// ZkxvQ3M0TUFZaGxUWQotLS0gSU8vZnlZME5WaDZZcE9lSmVJK0Nsdno1aFVsaGdU
/// enFkd2FBUzN1dG0rbwqFjuGr/hykL9N9dY8DyYRnlbe/0pecd2X6MrdR7N1qbu7T
/// U7HVgSBC8BM2B467MN0pGS2pSWbFKRv0XH1Yty1jaEC6FDlrmDPzK1sSgU6a3FAU
/// dA8v7Y9w6xSGSe5SZZGhZzktSpkqG2Vv4JvjJ1jQEDP5DMo4ZF/4fWjE13hrtmvU
/// PsAnSm9yfVX+ID36d8c5KENTq7s9XUuOgL6h3Gd02nZrz8on+cyZNnbf/7MslSaW
/// jQRPjDeWhwMUeJoNs+hLVkpjbWFdeTPqWEhXY0rwxVHg2HiBEypOLPgZxdKWGpCU
/// 1TxkAx3AD51upcDVG/MuiebnQr3O9mheotQTh+ZV8BurJALlYhWd/U2okNKRITK4
/// hrFL3y3oc0Q9pw9L4Qd03qeH3zVt9isp6lX++0A+pTtApYppdvS/EJUDATjjZOD8
/// Aji01We+Lgib/ruI5pQWTh5i7ovCgXPRsbmAp/grVJgWTLRL9Dw1D9MVCAW4+8OB
/// fHlpHTeXiaVDE57Y+mZ+vMAiMlxpBQoVnt5rGDzYWujreHTm4hfVKx9utHVx+q4J
/// txYpwLVdOfhUjLG+p/MKmfqmXErgN4I0cLEtIE6CvIpxTaymz2Ez8Rw1vhk+rh9j
/// lJZL/XiEl5UfWzKf6OmXCjUzFOhRAxHRcu3uxuO6UREFQg+mVK0tDBFdwYZbsD61
/// cl36G4Rcv2uCAuRweq1h9/Re9jLXqWbME9dtYop208OwGlHK11DnFXCjCdc7gKLt
/// OD1n5DkvHO0RRIzsUx1AiilWYNB/Cv+Qzfm93qF6KMrnsMUhLCfKPHT+b2LuFAg9
/// cVXQHx1/gr4pate4CJIwLdWwbqKj3Qj8DWnyK33jqdkbFLpYCHgw490wGfbKBx+W
/// fbNFO9E0mrDgDH+5U+66G7AllRpXL2Hqp7iLUja6t5LxnzrTaDiLwgWZmGVj92Wt
/// 5X5zpAz3U6VfarWPbASAKSkKQdGX4sNLxEyq14KrmmgrOjAMkw51KeZ5eqXzMxvS
/// kBrT0/frKXCfDEXsoVMqhIKzUcKGGh6b2Lo/0Fsi/8FMxwZOmre+r4GdP7U/C/IX
/// tY3VHlhguVMthtgJQ7AxxOW0UCE97+kgCIKXUNiryBkrZEk+rIQH3tWKUDeyEAPK
/// pXgZTSCBzBCMKO7UCFAkjQEH8IBWY9KR45deXoPuRxLoihZf3qtje8DOm4w0t0Y/
/// AuOorwmqvyyW3d6NJsbHsKsVXil69suo3Khxcu7tHwfikoffIRCNrFKPAjwxix4J
/// YxB0kOKzVes83ukIOH47X0mMXmLsuZWKieyxlCmly/CrlwcCiTNcrgJDdOUyjB/u
/// OUaCgyP2yEfH2yDgc+T/8yQktcoX6GIEfvk1HfqhJOUlMzJLhWY=
/// -----END AGE ENCRYPTED FILE-----".as_bytes();
///
/// let header = tlock_age::decrypt_header(encrypted).unwrap();
/// ```
pub fn decrypt_header<R: Read>(src: R) -> anyhow::Result<Header> {
    let identity = HeaderIdentity::new();
    #[cfg(feature = "armor")]
    let src = age::armor::ArmoredReader::new(src);
    let decryptor = match age::Decryptor::new(src) {
        Ok(age::Decryptor::Recipients(d)) => d,
        Ok(age::Decryptor::Passphrase(_)) => {
            return Err(anyhow!("recipient cannot be a passphrase"))
        }
        Err(e) => return Err(anyhow!(e)),
    };

    let _ = decryptor.decrypt(iter::once(&identity as &dyn age::Identity));
    match (identity.round(), identity.hash()) {
        (Some(round), Some(hash)) => Ok(Header::new(round, &hash)),
        _ => Err(anyhow!("Cannot decrypt round")),
    }
}

/// Decrypt using tlock encryption scheme and age encryption.
///
/// round and public key information are retrieved from age header.
/// signature has to be the one for that round.
/// src can be armored or not, decryption supports both.
///
/// Example using an empty 100-byte message, fastnet public key, at round 1000
///
/// ```rust
/// let chain_hash = hex::decode("dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493").unwrap();
/// // curl -sS https://api.drand.sh/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/1000 | jq -r '.signature'
/// let signature = hex::decode("b09eacd45767c4d58306b98901ad0d6086e2663766f3a4ec71d00cf26f0f49eaf248abc7151c60cf419c4e8b37e80412").unwrap();
///
/// // This message is the encryption of an empty 100-byte message, using fastnet public key, at round 1000
/// let encrypted = "-----BEGIN AGE ENCRYPTED FILE-----
/// YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDEwMDAgZGJkNTA2ZDZlZjc2
/// ZTVmMzg2ZjQxYzY1MWRjYjgwOGM1YmNiZDc1NDcxY2M0ZWFmYTNmNGRmN2FkNGU0
/// YzQ5MwpqRDhmd1B3a3BEOG01WThxY2VNdjl5Wko1elMzdDJ2RS9MWUhEYW16T1E4
/// K3BqMGZ1Nm1RSjF3Tk1zNDZqWnU4CkVydkRaQU5hd2lBL1oxZHlka2NrbUR5bHBz
/// cTl2SUY5OE80NlVvT2dCcms4M004dk1VWkFnVGNyR3dJM2tSd0IKbDN3TUdoRi9K
/// QWlmWlFodjlrVEVIMmJ1VWZJRVhpanZkSWFrTFovbnhpZ2V5b3ZpUk1LQnNEZmx2
/// N2pJdUhGcQp3VFEvNWJ2MWZZMXAxWkhMRU4vVnh3Ci0+IGdVV0FmPD5JLWdyZWFz
/// ZQpteVBMbHlLcGJlUzVFSk1mMmk3OWVDS0FBYzBFNTdvT2hUK1NVWFM1SjNyMW1L
/// ZkxvQ3M0TUFZaGxUWQotLS0gSU8vZnlZME5WaDZZcE9lSmVJK0Nsdno1aFVsaGdU
/// enFkd2FBUzN1dG0rbwqFjuGr/hykL9N9dY8DyYRnlbe/0pecd2X6MrdR7N1qbu7T
/// U7HVgSBC8BM2B467MN0pGS2pSWbFKRv0XH1Yty1jaEC6FDlrmDPzK1sSgU6a3FAU
/// dA8v7Y9w6xSGSe5SZZGhZzktSpkqG2Vv4JvjJ1jQEDP5DMo4ZF/4fWjE13hrtmvU
/// PsAnSm9yfVX+ID36d8c5KENTq7s9XUuOgL6h3Gd02nZrz8on+cyZNnbf/7MslSaW
/// jQRPjDeWhwMUeJoNs+hLVkpjbWFdeTPqWEhXY0rwxVHg2HiBEypOLPgZxdKWGpCU
/// 1TxkAx3AD51upcDVG/MuiebnQr3O9mheotQTh+ZV8BurJALlYhWd/U2okNKRITK4
/// hrFL3y3oc0Q9pw9L4Qd03qeH3zVt9isp6lX++0A+pTtApYppdvS/EJUDATjjZOD8
/// Aji01We+Lgib/ruI5pQWTh5i7ovCgXPRsbmAp/grVJgWTLRL9Dw1D9MVCAW4+8OB
/// fHlpHTeXiaVDE57Y+mZ+vMAiMlxpBQoVnt5rGDzYWujreHTm4hfVKx9utHVx+q4J
/// txYpwLVdOfhUjLG+p/MKmfqmXErgN4I0cLEtIE6CvIpxTaymz2Ez8Rw1vhk+rh9j
/// lJZL/XiEl5UfWzKf6OmXCjUzFOhRAxHRcu3uxuO6UREFQg+mVK0tDBFdwYZbsD61
/// cl36G4Rcv2uCAuRweq1h9/Re9jLXqWbME9dtYop208OwGlHK11DnFXCjCdc7gKLt
/// OD1n5DkvHO0RRIzsUx1AiilWYNB/Cv+Qzfm93qF6KMrnsMUhLCfKPHT+b2LuFAg9
/// cVXQHx1/gr4pate4CJIwLdWwbqKj3Qj8DWnyK33jqdkbFLpYCHgw490wGfbKBx+W
/// fbNFO9E0mrDgDH+5U+66G7AllRpXL2Hqp7iLUja6t5LxnzrTaDiLwgWZmGVj92Wt
/// 5X5zpAz3U6VfarWPbASAKSkKQdGX4sNLxEyq14KrmmgrOjAMkw51KeZ5eqXzMxvS
/// kBrT0/frKXCfDEXsoVMqhIKzUcKGGh6b2Lo/0Fsi/8FMxwZOmre+r4GdP7U/C/IX
/// tY3VHlhguVMthtgJQ7AxxOW0UCE97+kgCIKXUNiryBkrZEk+rIQH3tWKUDeyEAPK
/// pXgZTSCBzBCMKO7UCFAkjQEH8IBWY9KR45deXoPuRxLoihZf3qtje8DOm4w0t0Y/
/// AuOorwmqvyyW3d6NJsbHsKsVXil69suo3Khxcu7tHwfikoffIRCNrFKPAjwxix4J
/// YxB0kOKzVes83ukIOH47X0mMXmLsuZWKieyxlCmly/CrlwcCiTNcrgJDdOUyjB/u
/// OUaCgyP2yEfH2yDgc+T/8yQktcoX6GIEfvk1HfqhJOUlMzJLhWY=
/// -----END AGE ENCRYPTED FILE-----".as_bytes();
///
/// let decrypted = vec![];
/// tlock_age::decrypt(decrypted, encrypted, &chain_hash, &signature).unwrap();
/// ```
pub fn decrypt<W: Write, R: Read>(
    mut dst: W,
    src: R,
    chain_hash: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    let identity = Identity::new(chain_hash, signature);
    #[cfg(feature = "armor")]
    let src = age::armor::ArmoredReader::new(src);
    let decryptor = match age::Decryptor::new(src) {
        Ok(age::Decryptor::Recipients(d)) => d,
        Ok(age::Decryptor::Passphrase(_)) => {
            return Err(anyhow!("recipient cannot be a passphrase"))
        }
        Err(e) => return Err(anyhow!(e)),
    };

    let mut reader = match decryptor.decrypt(iter::once(&identity as &dyn age::Identity)) {
        Ok(reader) => reader,
        Err(e) => return Err(anyhow!(e)),
    };
    copy(&mut reader, &mut dst)?;

    Ok(())
}
