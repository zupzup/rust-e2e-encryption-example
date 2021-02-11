use serde::{Deserialize, Serialize};
use sodiumoxide::{
    base64::{self, Variant},
    crypto::aead::{
        xchacha20poly1305_ietf::{self, Nonce},
        Key,
    },
    crypto::box_::{curve25519xsalsa20poly1305::gen_keypair, PublicKey, SecretKey},
    crypto::generichash,
    crypto::sign::ed25519::{
        gen_keypair as ed25519_gen_keypair, sign_detached, verify_detached,
        PublicKey as ED25519PublicKey, SecretKey as ED25519SecretKey, Signature,
    },
    hex, randombytes,
    utils::memcmp,
};

#[derive(Serialize, Deserialize)]
struct Data {
    version: &'static str,
    nonce: String,
    extra: Option<String>,
}

type KeyPair = (PublicKey, SecretKey);
const VERSION: &str = "v2";

fn main() {
    let keypair = ed25519_gen_keypair();
    let signing_key = keypair.1;
    let verification_key = keypair.0;
    let signed_bundle = x3dh_pre_key(&signing_key, Some(100));

    let public_keys: Vec<PublicKey> = signed_bundle
        .bundle
        .iter()
        .map(|k| {
            PublicKey::from_slice(&hex::decode(&k).expect("can decode hex"))
                .expect("can create public key from decoded bundle key")
        })
        .collect();
    let verified = verify_bundle(
        &verification_key,
        &public_keys,
        &Signature::from_slice(
            &base64::decode(&signed_bundle.signature, Variant::Original)
                .expect("can decode base64"),
        )
        .expect("can get signature from slice"),
    );

    println!("bundle: {:?}, verified: {}", signed_bundle, verified);
}

fn derive_keys(key: &[u8], nonce: &Vec<u8>) -> (Key, Vec<u8>) {
    let mut key_hash_state = generichash::State::new(32, Some(key)).expect("hash can be created");
    key_hash_state
        .update(&[0x01])
        .expect("can update hash with 1");
    key_hash_state
        .update(&nonce)
        .expect("can update hash with nonce");
    let key_hash = key_hash_state.finalize().expect("can create key hash");
    let enc_key = Key::from_slice(key_hash.as_ref()).expect("can create key from hash");

    let mut comm_hash_state = generichash::State::new(32, Some(key)).expect("hash can be created");
    comm_hash_state
        .update(&[0x02])
        .expect("can update hash with 1");
    comm_hash_state
        .update(&nonce)
        .expect("can update hash with nonce");
    let comm_hash = comm_hash_state
        .finalize()
        .expect("can create commitment hash");

    (enc_key, comm_hash.as_ref().to_vec())
}

// TODO: https://berty.tech/blog/e2e-encryption
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

fn generate_key_pair() -> KeyPair {
    gen_keypair()
}

fn generate_bundle(key_count: usize) -> Vec<KeyPair> {
    let mut bundle = Vec::new();
    for _ in 0..key_count {
        bundle.push(generate_key_pair())
    }
    bundle
}

fn prehash_public_keys_for_signing(public_keys: &Vec<PublicKey>) -> Vec<u8> {
    let mut hash_state = generichash::State::new(32, None).expect("hash can be created");
    let pk_len: [u8; 4] = [
        ((public_keys.len() >> 24) & 0xff) as u8,
        ((public_keys.len() >> 16) & 0xff) as u8,
        ((public_keys.len() >> 8) & 0xff) as u8,
        (public_keys.len() & 0xff) as u8,
    ];
    hash_state
        .update(&pk_len)
        .expect("can update hash with pk len");

    for pk in public_keys {
        hash_state
            .update(&pk.as_ref())
            .expect("can update hash with pk");
    }
    hash_state
        .finalize()
        .expect("can create hash")
        .as_ref()
        .to_vec()
}

fn sign_bundle(signing_key: &ED25519SecretKey, public_keys: &Vec<PublicKey>) -> Signature {
    sign_detached(&prehash_public_keys_for_signing(public_keys), signing_key)
}

fn verify_bundle(
    verification_key: &ED25519PublicKey,
    public_keys: &Vec<PublicKey>,
    signature: &Signature,
) -> bool {
    verify_detached(
        &signature,
        &prehash_public_keys_for_signing(public_keys),
        verification_key,
    )
}

#[derive(Debug)]
struct SignedBundle {
    pub signature: String,
    pub bundle: Vec<String>,
}

fn x3dh_pre_key(signing_key: &ED25519SecretKey, num_keys: Option<usize>) -> SignedBundle {
    let num_of_keys = num_keys.unwrap_or_else(|| 100);

    let bundle = generate_bundle(num_of_keys);
    let public_keys: Vec<PublicKey> = bundle.into_iter().map(|kp| kp.0).collect();
    let signature = sign_bundle(&signing_key, &public_keys);

    // TODO: persist signing key and bundle

    let mut encoded_bundle = Vec::new();
    for pk in public_keys {
        encoded_bundle.push(hex::encode(&pk.as_ref()));
    }

    SignedBundle {
        signature: base64::encode(&signature.as_ref(), Variant::Original),
        bundle: encoded_bundle,
    }
}
