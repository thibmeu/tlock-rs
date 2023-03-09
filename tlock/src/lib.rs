pub mod ibe;

use crate::ibe::Ciphertext;
use anyhow::anyhow;

use ibe::GAffine;
use sha2::Digest;
use std::io;
use tracing::info_span;

pub fn encrypt<W: io::Write, R: io::Read>(
    mut dst: W,
    mut src: R,
    public_key_bytes: &[u8],
    round_number: u64,
) -> anyhow::Result<()> {
    let mut message = [0; 32];
    src.read(&mut message)
        .map_err(|e| anyhow!("error reading {e}"))?;

    let ct = info_span!("ibe::encryption")
        .in_scope(|| time_lock(public_key_bytes, round_number, message));

    {
        let mut buffer = unsigned_varint::encode::u64_buffer();
        dst.write_all(unsigned_varint::encode::u64(round_number, &mut buffer))
            .unwrap();
    }

    dst.write_all(&ct.u.to_compressed()).unwrap();
    dst.write_all(&ct.v).unwrap();
    dst.write_all(&ct.w).unwrap();

    Ok(())
}

pub fn decrypt_round<R: io::Read>(mut src: R) -> anyhow::Result<u64> {
    unsigned_varint::io::read_u64(&mut src).map_err(|e| anyhow!("error reading {e}"))
}

pub fn decrypt<W: io::Write, R: io::Read>(
    mut dst: W,
    mut src: R,
    signature: &[u8],
) -> anyhow::Result<()> {
    let _round = unsigned_varint::io::read_u64(&mut src).map_err(|e| anyhow!("error reading {e}"));
    let c = {
        let u = if signature.len() == ibe::G1_SIZE {
            let mut u = [0u8; ibe::G2_SIZE];
            src.read_exact(&mut u)
                .map_err(|e| anyhow!("error reading {e}"))?;
            u.to_vec()
        } else {
            let mut u = [0u8; ibe::G1_SIZE];
            src.read_exact(&mut u)
                .map_err(|e| anyhow!("error reading {e}"))?;
            u.to_vec()
        };
        let mut v = [0u8; 32];
        src.read_exact(&mut v)
            .map_err(|e| anyhow!("error reading {e}"))?;
        let mut w = [0u8; 32];
        src.read_exact(&mut w)
            .map_err(|e| anyhow!("error reading {e}"))?;

        Ciphertext {
            u: u.as_slice().try_into()?,
            v: v.to_vec(),
            w: w.to_vec(),
        }
    };

    let mut pt = time_unlock(signature, &c);

    //note(thibault): I'm not sure why this condition was choosen, but this does not work as expected
    // it stems to time_unlock always decrypting to 32 bytes
    // thing is, sometimes, data to be encrypted ends with 0
    // the following lines destroy this data
    if let Some(i) = pt.iter().rposition(|x| *x != 0) {
        pt.truncate(i + 1);
    }

    dst.write_all(&pt).map_err(|e| anyhow!("error write {e}"))
}

pub fn time_lock<M: AsRef<[u8]>>(
    public_key_bytes: &[u8],
    round_number: u64,
    message: M,
) -> ibe::Ciphertext {
    let public_key = GAffine::try_from(public_key_bytes).unwrap();
    let id = {
        let mut hash = sha2::Sha256::new();
        hash.update(round_number.to_be_bytes());
        &hash.finalize().to_vec()[0..32]
    };

    ibe::encrypt(public_key, id, message)
}

pub fn time_unlock(signature: &[u8], c: &Ciphertext) -> Vec<u8> {
    ibe::decrypt(signature.try_into().unwrap(), c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pk_g1_sig_g2() {
        let pk_bytes = hex::decode("8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11").unwrap();

        let msg = vec![8; 32];
        let ct = time_lock(&pk_bytes, 1000, msg.clone());

        let signature = hex::decode("a4721e6c3eafcd823f138cd29c6c82e8c5149101d0bb4bafddbac1c2d1fe3738895e4e21dd4b8b41bf007046440220910bb1cdb91f50a84a0d7f33ff2e8577aa62ac64b35a291a728a9db5ac91e06d1312b48a376138d77b4d6ad27c24221afe").unwrap();

        let pt = time_unlock(&signature, &ct);
        assert_eq!(pt, msg)
    }

    #[test]
    fn test_pk_g2_sig_g1() {
        // fastnet https://drand.cloudflare.com/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/info
        let pk_bytes = hex::decode("a0b862a7527fee3a731bcb59280ab6abd62d5c0b6ea03dc4ddf6612fdfc9d01f01c31542541771903475eb1ec6615f8d0df0b8b6dce385811d6dcf8cbefb8759e5e616a3dfd054c928940766d9a5b9db91e3b697e5d70a975181e007f87fca5e").unwrap();


        // at round 1000
        // https://drand.cloudflare.com/dbd506d6ef76e5f386f41c651dcb808c5bcbd75471cc4eafa3f4df7ad4e4c493/public/1000
        let msg = vec![8; 32];
        let ct = time_lock(&pk_bytes, 1000, msg.clone());

        let signature = hex::decode("b09eacd45767c4d58306b98901ad0d6086e2663766f3a4ec71d00cf26f0f49eaf248abc7151c60cf419c4e8b37e80412").unwrap();

        let pt = time_unlock(&signature, &ct);
        assert_eq!(pt, msg)
    }
}
