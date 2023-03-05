pub mod ibe;

use crate::ibe::{public_key, Ciphertext};
use anyhow::anyhow;
use bls12_381_plus::{G1Affine, G2Affine};
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

    dst.write_all(ct.u.to_compressed().as_ref()).unwrap();
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
    let c = {
        let mut u = [0u8; 48];
        src.read_exact(&mut u)
            .map_err(|e| anyhow!("error reading {e}"))?;
        let mut v = [0u8; 32];
        src.read_exact(&mut v)
            .map_err(|e| anyhow!("error reading {e}"))?;
        let mut w = [0u8; 32];
        src.read_exact(&mut w)
            .map_err(|e| anyhow!("error reading {e}"))?;

        Ciphertext {
            u: G1Affine::from_compressed(&u).unwrap(),
            v: v.to_vec(),
            w: w.to_vec(),
        }
    };

    let mut pt = time_unlock(signature, &c);

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
    let public_key = public_key(public_key_bytes).unwrap();
    let id = {
        let mut hash = sha2::Sha256::new();
        hash.update(round_number.to_be_bytes());
        &hash.finalize().to_vec()[0..32]
    };

    ibe::encrypt(public_key, id, message)
}

pub fn time_unlock(signature: &[u8], c: &Ciphertext) -> Vec<u8> {
    let private = G2Affine::from_compressed((signature).try_into().unwrap()).unwrap();

    ibe::decrypt(private, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e() {
        let pk_bytes = hex::decode("8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11").unwrap();

        let msg = vec![8; 32];
        let ct = time_lock(&pk_bytes, 1000, msg.clone());

        let signature = hex::decode("a4721e6c3eafcd823f138cd29c6c82e8c5149101d0bb4bafddbac1c2d1fe3738895e4e21dd4b8b41bf007046440220910bb1cdb91f50a84a0d7f33ff2e8577aa62ac64b35a291a728a9db5ac91e06d1312b48a376138d77b4d6ad27c24221afe").unwrap();

        let pt = time_unlock(&signature, &ct);
        assert_eq!(pt, msg)
    }
}
