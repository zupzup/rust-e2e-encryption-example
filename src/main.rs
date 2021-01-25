use serde::{Deserialize, Serialize};
use sodiumoxide::{
    crypto::aead::xchacha20poly1305_ietf::{self, Key, Nonce},
    hex, randombytes,
    utils::memcmp,
};

#[derive(Serialize, Deserialize)]
struct Data {
    version: &'static str,
    nonce: String,
    extra: Option<String>,
}

const VERSION: &str = "V1";

fn main() {
    println!("Hello, world!");
}

// TODO: implement v2, using generichash::State
// compare with
// https://github.com/paragonie/sodium-plus/blob/24312a9f19094810f0c06b38c72e1499a306518f/docs/SodiumPlus/general-purpose-cryptographic-hash.md
// - len default 32, buffer not needed
// TODO: call update with nonce?
// TODO: create Key from return value (xchacha key)

fn encrypt_data(message: &[u8], key: &[u8], assoc_data: Option<String>) -> String {
    let nonce: Vec<u8> = randombytes::randombytes(24);
    let aad = serde_json::to_vec(&Data {
        version: VERSION,
        nonce: hex::encode(&nonce),
        extra: assoc_data,
    })
    .expect("can serialize JSON");

    let encrypted = xchacha20poly1305_ietf::seal(
        &message,
        Some(&aad),
        &Nonce::from_slice(&nonce).expect("can convert nonce"),
        &Key::from_slice(&key).expect("can convert key"),
    );

    let mut result = String::new();
    result.push_str(VERSION);
    result.push_str(hex::encode(&nonce).as_str());
    result.push_str(std::str::from_utf8(&encrypted).expect("can convert encrypted to utf8"));
    result
}

fn decrypt_data(encrypted: &[u8], key: &[u8], assoc_data: Option<String>) -> String {
    let version = &encrypted[0..2];
    if !memcmp(version, VERSION.as_bytes()) {
        panic!("incorrect version");
    }

    let nonce: Vec<u8> = hex::decode(&encrypted[2..50]).expect("nonce is hex");
    let ciphertext = &encrypted[50..];
    let aad = serde_json::to_vec(&Data {
        version: VERSION,
        nonce: hex::encode(&nonce),
        extra: assoc_data,
    })
    .expect("can serialize JSON");

    let plaintext = xchacha20poly1305_ietf::open(
        &ciphertext,
        Some(&aad),
        &Nonce::from_slice(&nonce).expect("can convert nonce"),
        &Key::from_slice(&key).expect("can convert key"),
    )
    .expect("can decrypt data");

    std::str::from_utf8(&plaintext)
        .expect("plaintext is utf8")
        .to_owned()
}
