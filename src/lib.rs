//! # aes-wasm
//!
//! High-performance AES256GCM for WebAssembly/WASI.
//!
//! This crate provides a simple, dependency-free API for cryptography in WASI environments.
//! ORIGINALLY from https://github.com/jedisct1/rust-aes-wasm
//!
//! ## Example: AES-256-GCM
//! ```rust
//! use aes_wasm::aes256gcm::{encrypt, decrypt, Key, Nonce};
//! let key = Key::default();
//! let nonce = Nonce::default();
//! let msg = b"hello world";
//! let ad = b"extra data";
//! let ciphertext = encrypt(msg, ad, &key, nonce);
//! let plaintext = decrypt(ciphertext, ad, &key, nonce).unwrap();
//! assert_eq!(plaintext, msg);
//! ```
use wasm_bindgen::prelude::*; 
use core::fmt::{self, Display};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Ciphertext verification failed.
    VerificationFailed,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed => write!(f, "Verification failed"),
        }
    }
} 
pub mod aes256gcm;
use crate::aes256gcm::{Key, Nonce};

#[wasm_bindgen]
pub fn new_key() -> Vec<u8> {
    Key::default().to_vec()          // Vec<u8> *is* IntoWasmAbi :contentReference[oaicite:1]{index=1}
}

#[wasm_bindgen]
pub fn new_nonce() -> Vec<u8> {
    Nonce::default().to_vec()
}

/// Encrypt: Uint8Array → Uint8Array
#[wasm_bindgen]
pub fn encrypt_js(
    msg: &[u8], ad: &[u8], key: &[u8], nonce: &[u8],
) -> Vec<u8> {
    // run-time length checks keep undefined behaviour out
    let key: &Key   = key.try_into().expect("key must be 32 bytes");
    let nonce: &Nonce = nonce.try_into().expect("nonce must be 12 bytes");
    aes256gcm::encrypt(msg, ad, key, *nonce)
}

/// Decrypt and map Rust errors to JS throws
#[wasm_bindgen]
pub fn decrypt_js(
    ct_and_tag: &[u8], ad: &[u8], key: &[u8], nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let key:  &Key   = key.try_into().map_err(|_| JsValue::from_str("bad key len"))?;
    let nonce:&Nonce = nonce.try_into().map_err(|_| JsValue::from_str("bad nonce len"))?;
    aes256gcm::decrypt(ct_and_tag, ad, key, *nonce)
        .map_err(|_| JsValue::from_str("verification failed"))
}
