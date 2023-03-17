use anyhow::{anyhow, Result};
use bls12_381_plus::{
    ExpandMsg, ExpandMsgXmd, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar,
};
use group::Curve;
use itertools::Itertools;
use rand::distributions::Uniform;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{digest::BlockInput, Digest, Sha256};
use std::{marker::PhantomData, ops::Mul};

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
const FP_CHUNK_SIZE: usize = 48;
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
        let sigma: [u8; 16] = (0..16)
            .map(|_| rng.sample(Uniform::new(0u8, 8u8)))
            .collect_vec()
            .try_into()
            .unwrap();

        // 3. Derive r from sigma and msg
        let r = {
            let hash = Sha256::new()
                .chain(b"IBE-H3")
                .chain(&sigma[..])
                .chain(msg.as_ref())
                .finalize();
            let r = hash.as_slice();

            let mut buf = [0u8; BLOCK_SIZE];
            ExpandMsgDrand::<Sha256>::expand_message(r, &[], &mut buf);
            Scalar::from_bytes(&buf)
        };

        if r.is_some().unwrap_u8() == 1u8 {
            break (sigma, r.unwrap());
        }
    };

    // 4. Compute U = G^r
    let u = master.generator().mul(r);

    // 5. Compute V = sigma XOR H(rGid)
    let v = {
        let r_gid = gid.mul(r);
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H2") // dst
            .chain(rev_chunks(&r_gid.to_bytes(), FP_CHUNK_SIZE))
            .finalize();
        let h_r_git = &hash.to_vec()[0..16];

        xor(&sigma, h_r_git)
    };

    // 6. Compute W = M XOR H(sigma)
    let w = {
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H4")
            .chain(&sigma[..])
            .finalize();
        let h_sigma = &hash.to_vec()[0..16];
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
        let r_gid = private.pairing(&c.u).unwrap();
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H2")
            .chain(rev_chunks(&r_gid.to_bytes(), FP_CHUNK_SIZE))
            .finalize();
        let h_r_git = &hash.to_vec()[0..16];
        xor(h_r_git, &c.v[c.v.len() - 16..])
    };

    // 2. Compute Msg = W XOR H4(sigma)
    let msg = {
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H4")
            .chain(&sigma)
            .finalize();
        let h_sigma = &hash.to_vec()[0..16];
        xor(h_sigma, &c.w[c.w.len() - 16..])
    };

    // 3. Check U = G^r
    let r_g = {
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H3")
            .chain(&sigma)
            .chain(&msg)
            .finalize();
        let r = hash.as_slice();
        let mut buf = [0u8; BLOCK_SIZE];
        ExpandMsgDrand::<Sha256>::expand_message(r, &[], &mut buf);
        let r = Scalar::from_bytes(&buf).unwrap();
        c.u.generator().mul(r)
    };
    assert_eq!(c.u, r_g);

    msg
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a.len() != b.len() {
        panic!("array length should be the same");
    }
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}

/// Placeholder type for implementing expand_message_drand based on a hash function
#[derive(Debug)]
pub struct ExpandMsgDrand<HashT> {
    phantom: PhantomData<HashT>,
}

/// ExpandMsgXmd implements expand_message_drand for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgDrand<HashT>
where
    HashT: Digest + BlockInput,
{
    fn expand_message(msg: &[u8], _dst: &[u8], buf: &mut [u8]) {
        // drand "hash"
        const BITS_TO_MASK_FOR_BLS12381: usize = 1;
        for i in 1..u16::MAX {
            // We hash iteratively: H(i || H("IBE-H3" || sigma || msg)) until we get a
            // value that is suitable as a scalar.
            let mut h = HashT::new()
                .chain(i.to_le_bytes())
                .chain(msg)
                .finalize()
                .to_vec();
            *h.first_mut().unwrap() = h.first().unwrap() >> BITS_TO_MASK_FOR_BLS12381;
            // let rev: Vec<u8> = data.lock().unwrap().iter().copied().rev().collect();
            // test if we can build a valid scalar out of n
            // this is a hash method to be compatible with the existing implementation
            let rev: Vec<u8> = h.iter().copied().rev().collect();
            let ret = rev.as_slice().try_into().unwrap();
            if Scalar::from_bytes(&ret).is_some().unwrap_u8() == 1u8 {
                buf.copy_from_slice(&ret);
                return;
            }
        }
    }
}

// Reverse a u8 array, chunks at a time
// Example
// ```rust
// let a = vec![1, 2, 3, 4];
// assert_eq!(tlock::ibe::rev_chunks(&a, 2), vec![3, 4, 1, 2]);
// ```
fn rev_chunks(a: &[u8], chunk_size: usize) -> Vec<u8> {
    a.chunks(chunk_size)
        .into_iter()
        .rev()
        .collect_vec()
        .concat()
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
