use anyhow::{anyhow, Result};
use bls12_381_plus::{ExpandMsgXmd, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use group::Curve;
use itertools::Itertools;
use rand::distributions::Uniform;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ops::Mul;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum GAffine {
    G1Affine(G1Affine),
    G2Affine(G2Affine),
}

impl GAffine {
    pub fn projective_pairing(&self, id: &[u8]) -> Gt {
        match self {
            GAffine::G1Affine(g) => {
                let qid = G2Projective::hash::<ExpandMsgXmd<Sha256>>(id, H2C_DST).to_affine();
                bls12_381_plus::pairing(g, &qid)
            }
            GAffine::G2Affine(g) => {
                let qid = G1Projective::hash::<ExpandMsgXmd<Sha256>>(id, H2C_DST).to_affine();
                bls12_381_plus::pairing(&qid, g)
            }
        }
    }

    pub fn pairing(&self, other: &GAffine) -> Result<Gt> {
        match (self, other) {
            (GAffine::G1Affine(s), GAffine::G2Affine(o)) => Ok(bls12_381_plus::pairing(s, o)),
            (GAffine::G2Affine(s), GAffine::G1Affine(o)) => Ok(bls12_381_plus::pairing(o, s)),
            _ => Err(anyhow!(
                "pairing requires affines to be on different curves"
            )),
        }
    }

    pub fn generator(&self) -> Self {
        match self {
            GAffine::G1Affine(_) => G1Affine::generator().into(),
            GAffine::G2Affine(_) => G2Affine::generator().into(),
        }
    }

    pub fn mul(&self, s: Scalar) -> Self {
        match self {
            GAffine::G1Affine(g) => g.mul(s).to_affine().into(),
            GAffine::G2Affine(g) => g.mul(s).to_affine().into(),
        }
    }

    pub fn to_compressed(&self) -> Vec<u8> {
        match self {
            GAffine::G1Affine(g) => g.to_compressed().to_vec(),
            GAffine::G2Affine(g) => g.to_compressed().to_vec(),
        }
    }
}

impl From<G1Affine> for GAffine {
    fn from(g1: G1Affine) -> Self {
        GAffine::G1Affine(g1)
    }
}

impl From<G2Affine> for GAffine {
    fn from(g2: G2Affine) -> Self {
        GAffine::G2Affine(g2)
    }
}

impl TryFrom<&[u8]> for GAffine {
    type Error = anyhow::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() == G1_SIZE {
            let bytes = bytes
                .try_into()
                .map_err(|_| anyhow!("invalid public key size"))?;
            Ok(G1Affine::from_compressed(bytes).unwrap().into())
        } else if bytes.len() == G2_SIZE {
            let bytes = bytes
                .try_into()
                .map_err(|_| anyhow!("invalid public key size"))?;
            Ok(G2Affine::from_compressed(bytes).unwrap().into())
        } else {
            Err(anyhow!("invalid size for public key"))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub u: GAffine,
    pub v: Vec<u8>,
    pub w: Vec<u8>,
}

const BLOCK_SIZE: usize = 32;
pub const H2C_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;

pub fn encrypt<I: AsRef<[u8]>, M: AsRef<[u8]>>(master: GAffine, id: I, msg: M) -> Ciphertext {
    assert!(
        msg.as_ref().len() <= BLOCK_SIZE,
        "plaintext too long for the block size"
    );

    let mut rng = rand::thread_rng();
    // 1. Compute Gid = e(master,Q_id)
    let gid = master.projective_pairing(id.as_ref());
    // dirty fix: loop to sample randomness that won't mess up constant time operation.
    // otherwise can `Scalar::from_bytes(r).unwrap()` panic from subtle crate
    let (sigma, r) = loop {
        // 2. Derive random sigma
        let sigma: [u8; BLOCK_SIZE] = (0..BLOCK_SIZE)
            .map(|_| rng.sample(Uniform::new(0u8, 8u8)))
            .collect_vec()
            .try_into()
            .unwrap();

        // 3. Derive r from sigma and msg
        let r = {
            let mut hash = Sha256::new();
            hash.update(b"h3");
            hash.update(&sigma[..]);
            hash.update(msg.as_ref());
            let r = &hash.finalize().to_vec()[0..32].try_into().unwrap();

            Scalar::from_bytes(r)
        };

        if r.is_some().unwrap_u8() == 1u8 {
            break (sigma, r.unwrap());
        }
    };

    // 4. Compute U = G^r
    let u = master.generator().mul(r);

    // 5. Compute V = sigma XOR H(rGid)
    let v = {
        let mut hash = sha2::Sha256::new();
        let r_gid = gid.mul(r);
        hash.update(b"h2"); // dst
        hash.update(r_gid.to_bytes());
        let h_r_git = &hash.finalize().to_vec()[0..BLOCK_SIZE];

        xor(&sigma, h_r_git)
    };

    // 6. Compute W = M XOR H(sigma)
    let w = {
        let mut hash = sha2::Sha256::new();
        hash.update(b"h4");
        hash.update(&sigma[..]);
        let h_sigma = &hash.finalize().to_vec()[0..BLOCK_SIZE];
        xor(msg.as_ref(), h_sigma)
    };

    Ciphertext { u, v, w }
}

pub fn decrypt(private: GAffine, c: &Ciphertext) -> Vec<u8> {
    assert!(
        c.w.len() <= BLOCK_SIZE,
        "ciphertext too long for the block size"
    );

    // 1. Compute sigma = V XOR H2(e(rP,private))
    let sigma = {
        let mut hash = sha2::Sha256::new();
        let r_gid = private.pairing(&c.u).unwrap();
        hash.update(b"h2");
        hash.update(r_gid.to_bytes());
        let h_r_git = &hash.finalize().to_vec()[0..BLOCK_SIZE];
        xor(h_r_git, &c.v)
    };

    // 2. Compute Msg = W XOR H4(sigma)
    let msg = {
        let mut hash = sha2::Sha256::new();
        hash.update(b"h4");
        hash.update(&sigma);
        let h_sigma = &hash.finalize().to_vec()[0..BLOCK_SIZE];
        xor(h_sigma, &c.w)
    };

    // 3. Check U = G^r
    let r_g = {
        let mut hash = sha2::Sha256::new();
        hash.update(b"h3");
        hash.update(&sigma[..]);
        hash.update(&msg);
        let r = &hash.finalize().to_vec()[0..BLOCK_SIZE];
        let r = Scalar::from_bytes(r.try_into().unwrap()).unwrap();
        c.u.generator().mul(r)
    };
    assert_eq!(c.u, r_g);

    msg
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_extended_truth_table() {
        let a = vec![0b00000000u8, 0b11111111, 0b00000000, 0b11111111];
        let b = vec![0b11111111u8, 0b00000000, 0b00000000, 0b11111111];
        let x = vec![0b11111111u8, 0b11111111, 0b00000000, 0b00000000];
        assert_eq!(xor(&a, &b), x);
    }

    #[test]
    fn test_xor_empty() {
        let a = vec![];
        let b = vec![];
        let x = vec![];
        assert_eq!(xor(&a, &b), x);
    }
}
