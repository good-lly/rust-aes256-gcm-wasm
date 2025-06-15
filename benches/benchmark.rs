use aes_wasm::*;
use aes_gcm::aead::Payload;
// use aes_gcm::aes;
use aes_gcm::{aead::Aead as _, aead::KeyInit as _,  Aes256Gcm};

use benchmark_simple::*;

fn test_aes256gcm_rust(m: &mut [u8]) {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let state = Aes256Gcm::new(key);
    black_box(state.encrypt(nonce, Payload { msg: m, aad: &[] }).unwrap());
}

fn test_aes256gcm(m: &mut [u8]) {
    use aes256gcm::*;
    let key = Key::default();
    let nonce = Nonce::default();
    black_box(encrypt_detached(m, [], &key, nonce));
}


fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 10_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_aes256gcm_rust(&mut m));
    println!(
        "aes256-gcm   (aes crate)  : {}",
        res.throughput(m.len() as _)
    );

    let res = bench.run(options, || test_aes256gcm(&mut m));
    println!(
        "aes256-gcm   (this crate) : {}",
        res.throughput(m.len() as _)
    );

}
