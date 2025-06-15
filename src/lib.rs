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
