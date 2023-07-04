use wasm_bindgen::prelude::*;

impl From<crate::TLockAgeError> for JsValue {
    fn from(source: crate::TLockAgeError) -> JsValue {
        JsValue::from_str(&source.to_string())
    }
}

#[wasm_bindgen]
pub fn encrypt(
    src: &[u8],
    chain_hash: &[u8],
    public_key_bytes: &[u8],
    round: u64,
) -> Result<Vec<u8>, JsValue> {
    let mut encrypted = vec![];
    crate::encrypt(
        &mut encrypted,
        src,
        chain_hash,
        public_key_bytes,
        round,
    )?;
    Ok(encrypted)
}

#[wasm_bindgen(inspectable, getter_with_clone)]
pub struct Header {
    pub round: u64,
    pub hash: Vec<u8>,
}

impl From<crate::Header> for Header {
    fn from(source: crate::Header) -> Header {
        Header {
            round: source.round,
            hash: source.hash,
        }
    }
}

#[wasm_bindgen]
pub fn decrypt_header(src: &[u8]) -> Result<JsValue, JsValue> {
    let value: Header = crate::decrypt_header(src)?.into();
    Ok(value.into())
}

#[wasm_bindgen]
pub fn decrypt(
    src: &[u8],
    chain_hash: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut decrypted = vec![];
    crate::decrypt(&mut decrypted, src, chain_hash, signature)?;
    Ok(decrypted)
}
