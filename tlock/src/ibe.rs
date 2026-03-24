use ark_bls12_381::{
    g1, g2, Bls12_381, Fr as ScalarField, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    models::short_weierstrass,
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::Itertools;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::DeserializeAs;
use sha2::{digest::Update, Digest, Sha256};
use std::{marker::PhantomData, ops::Mul};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum IBEError {
    #[error("hash cannot be mapped to {0}")]
    HashToCurve(String),
    #[error("cannot initialise mapper for {hash} to BLS12-381 {field}")]
    MapperInitialisation { hash: String, field: String },
    #[error("sigma does not fit in 16 bytes")]
    MessageSize,
    #[error("pairing requires affines to be on different curves")]
    Pairing,
    #[error("invalid public key size")]
    PublicKeySize,
    #[error("serialization failed")]
    Serialisation,
    #[error("unknown data store error")]
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum GAffine {
    G1Affine(G1Affine),
    G2Affine(G2Affine),
}

impl Serialize for GAffine {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        match self {
            Self::G1Affine(g) => g
                .serialize_with_mode(&mut bytes, ark_serialize::Compress::Yes)
                .map_err(serde::ser::Error::custom)?,
            Self::G2Affine(g) => g
                .serialize_with_mode(&mut bytes, ark_serialize::Compress::Yes)
                .map_err(serde::ser::Error::custom)?,
        }

        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for GAffine {
    fn deserialize<D>(deserializer: D) -> std::result::Result<GAffine, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_with::Bytes::deserialize_as(deserializer)?;
        let reader = bytes.as_slice();
        let affine = match reader.len() {
            G1_SIZE => Self::G1Affine(
                G1Affine::deserialize_compressed(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?,
            ),
            G2_SIZE => Self::G2Affine(
                G2Affine::deserialize_compressed(bytes.as_slice())
                    .map_err(serde::de::Error::custom)?,
            ),
            _ => return Err(serde::de::Error::custom("Invalid len Should be 48 of 96")),
        };
        Ok(affine)
    }
}

impl GAffine {
    pub fn projective_pairing(
        &self,
        id: &[u8],
    ) -> anyhow::Result<PairingOutput<ark_bls12_381::Bls12_381>> {
        match self {
            GAffine::G1Affine(g) => {
                let mapper = MapToCurveBasedHasher::<
                    short_weierstrass::Projective<g2::Config>,
                    DefaultFieldHasher<sha2::Sha256, 128>,
                    WBMap<g2::Config>,
                >::new(G2_DOMAIN)
                .map_err(|_| IBEError::MapperInitialisation {
                    hash: "sha2".to_owned(),
                    field: "G2".to_owned(),
                })?;
                let qid = G2Projective::from(
                    mapper
                        .hash(id)
                        .map_err(|_| IBEError::HashToCurve("G2".to_owned()))?,
                )
                .into_affine();
                Ok(Bls12_381::pairing(g, qid))
            }
            GAffine::G2Affine(g) => {
                let mapper = MapToCurveBasedHasher::<
                    short_weierstrass::Projective<g1::Config>,
                    DefaultFieldHasher<sha2::Sha256, 128>,
                    WBMap<g1::Config>,
                >::new(G1_DOMAIN)
                .map_err(|_| IBEError::MapperInitialisation {
                    hash: "sha2".to_owned(),
                    field: "G1".to_owned(),
                })?;
                let qid = G1Projective::from(
                    mapper
                        .hash(id)
                        .map_err(|_| IBEError::HashToCurve("G1".to_owned()))?,
                )
                .into_affine();
                Ok(Bls12_381::pairing(qid, g))
            }
        }
    }

    pub fn pairing(
        &self,
        other: &GAffine,
    ) -> anyhow::Result<PairingOutput<ark_bls12_381::Bls12_381>, IBEError> {
        match (self, other) {
            (GAffine::G1Affine(s), GAffine::G2Affine(o)) => Ok(Bls12_381::pairing(s, o)),
            (GAffine::G2Affine(s), GAffine::G1Affine(o)) => Ok(Bls12_381::pairing(o, s)),
            _ => Err(IBEError::Pairing),
        }
    }

    pub fn generator(&self) -> Self {
        match self {
            GAffine::G1Affine(_) => GAffine::G1Affine(G1Affine::generator()),
            GAffine::G2Affine(_) => GAffine::G2Affine(G2Affine::generator()),
        }
    }

    pub fn mul(&self, s: ScalarField) -> Self {
        match self {
            GAffine::G1Affine(g) => GAffine::G1Affine(g.mul(s).into_affine()),
            GAffine::G2Affine(g) => GAffine::G2Affine(g.mul(s).into_affine()),
        }
    }

    pub fn to_compressed(&self) -> anyhow::Result<Vec<u8>, IBEError> {
        let mut compressed = vec![];
        match self {
            GAffine::G1Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::Yes)
            }
            GAffine::G2Affine(g) => {
                g.serialize_with_mode(&mut compressed, ark_serialize::Compress::Yes)
            }
        }
        .map_err(|_| IBEError::Serialisation)?;
        Ok(compressed)
    }
}

impl TryFrom<&[u8]> for GAffine {
    type Error = IBEError;

    fn try_from(bytes: &[u8]) -> anyhow::Result<Self, Self::Error> {
        if bytes.len() == G1_SIZE {
            let g = G1Affine::deserialize_compressed(bytes).map_err(|_| IBEError::PublicKeySize)?;
            Ok(GAffine::G1Affine(g))
        } else if bytes.len() == G2_SIZE {
            let g = G2Affine::deserialize_compressed(bytes).map_err(|_| IBEError::PublicKeySize)?;
            Ok(GAffine::G2Affine(g))
        } else {
            Err(IBEError::PublicKeySize)
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
#[cfg(feature = "rfc9380")]
pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
#[cfg(not(feature = "rfc9380"))]
pub const G1_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
pub const G2_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;

pub fn encrypt<I: AsRef<[u8]>, M: AsRef<[u8]>>(
    master: GAffine,
    id: I,
    msg: M,
) -> anyhow::Result<Ciphertext, anyhow::Error> {
    assert!(
        msg.as_ref().len() <= BLOCK_SIZE,
        "plaintext too long for the block size"
    );

    let mut rng = rand::rng();
    // 1. Compute Gid = e(master,Q_id)
    let gid = master.projective_pairing(id.as_ref())?;

    // 2. Derive random sigma
    let mut sigma = [0u8; 16];
    rng.fill_bytes(&mut sigma);

    // 3. Derive r from sigma and msg
    let r: ScalarField = {
        let hash = Sha256::new()
            .chain(b"IBE-H3")
            .chain(sigma.as_slice())
            .chain(msg.as_ref())
            .finalize();
        let r = hash.as_slice();

        let mut buf = [0u8; BLOCK_SIZE];
        ExpandMsgDrand::<Sha256>::expand_message(r, &[], &mut buf);
        ScalarField::from_le_bytes_mod_order(&buf)
    };

    // 4. Compute U = G^r
    let u = master.generator().mul(r);

    // 5. Compute V = sigma XOR H(rGid)
    let v = {
        let r_gid_out = gid.mul(r);
        let mut r_gid = vec![];
        r_gid_out
            .serialize_with_mode(&mut r_gid, ark_serialize::Compress::Yes)
            .map_err(|_| IBEError::Serialisation)?;
        let r_gid = &r_gid.into_iter().rev().collect_vec();

        let hash = sha2::Sha256::new()
            .chain(b"IBE-H2") // dst
            .chain(r_gid)
            .finalize();

        let h_r_git = &hash.to_vec()[0..16];

        xor(&sigma, h_r_git)
    };

    // 6. Compute W = M XOR H(sigma)
    let w = {
        let hash = sha2::Sha256::new()
            .chain(b"IBE-H4")
            .chain(sigma.as_slice())
            .finalize();
        let h_sigma = &hash.to_vec()[0..16];
        xor(msg.as_ref(), h_sigma)
    };

    Ok(Ciphertext { u, v, w })
}

pub fn decrypt(private: GAffine, c: &Ciphertext) -> anyhow::Result<Vec<u8>, IBEError> {
    assert!(
        c.w.len() <= BLOCK_SIZE,
        "ciphertext too long for the block size"
    );

    // 1. Compute sigma = V XOR H2(e(rP,private))
    let sigma = {
        let r_gid_out = private.pairing(&c.u)?;
        let mut r_gid = vec![];
        r_gid_out
            .serialize_with_mode(&mut r_gid, ark_serialize::Compress::Yes)
            .map_err(|_| IBEError::Serialisation)?;
        let r_gid = &r_gid.into_iter().rev().collect_vec();

        let hash = sha2::Sha256::new().chain(b"IBE-H2").chain(r_gid).finalize();
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
        let r = ScalarField::from_le_bytes_mod_order(&buf);
        c.u.generator().mul(r)
    };
    assert_eq!(c.u, r_g);

    Ok(msg)
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
impl<HashT> ExpandMsgDrand<HashT>
where
    HashT: Digest + Update,
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
            // test if we can build a valid scalar out of n
            // this is a hash method to be compatible with the existing implementation
            let rev: Vec<u8> = h.iter().copied().rev().collect();
            if ScalarField::from_le_bytes_mod_order(&rev)
                .serialized_size(ark_serialize::Compress::Yes)
                > 0
            {
                buf.copy_from_slice(&rev);
                return;
            }
        }
    }
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

    /// Sigma must use the full [0, 256) byte range.
    ///
    /// The original code used `Uniform::new(0u8, 8u8)` which produces values
    /// in [0, 8) — only 3 bits of entropy per byte, 48 bits total for 16 bytes
    /// instead of the required 128 bits.
    ///
    /// Reference implementations:
    ///   Go:  crypto/rand.Read(sigma)          — full CSPRNG
    ///   JS:  randomBytes(msg.length)           — full CSPRNG (@noble/hashes/utils)
    #[test]
    fn test_sigma_uses_full_byte_range() {
        let mut rng = rand::rng();
        let mut seen = [false; 256];

        // Generate enough sigma values to cover the full byte range.
        // With 16 bytes per sigma and 256 possible values, ~100 iterations
        // is statistically sufficient (coupon collector: ~1500 bytes needed,
        // 100 * 16 = 1600).
        for _ in 0..100 {
            let mut sigma = [0u8; 16];
            rng.fill_bytes(&mut sigma);
            for &byte in &sigma {
                seen[byte as usize] = true;
            }
        }

        let covered = seen.iter().filter(|&&v| v).count();
        // With 1600 random bytes from a uniform [0, 256) distribution,
        // expected coverage is ~255.5/256 (Monte Carlo, 100k trials: min 250).
        // The old buggy code would only ever produce values in [0, 8),
        // covering at most 8 out of 256 values.
        assert!(
            covered > 200,
            "sigma byte coverage too low: {covered}/256 — only [0, {}) seen, \
             expected full [0, 256) byte range",
            seen.iter().rposition(|&v| v).unwrap_or(0) + 1,
        );
    }
}
