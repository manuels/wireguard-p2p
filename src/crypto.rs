use bytes::BytesMut;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305 as crypto;

pub use crypto::PrecomputedKey;
pub use crypto::SecretKey;
pub use crypto::PublicKey;
pub use crypto::precompute;

pub fn decrypt(key: &crypto::PrecomputedKey, ciphertext: Vec<u8>) -> Result<Vec<u8>, ()> {
    if ciphertext.len() < crypto::NONCEBYTES {
        return Err(());
    }

    let (nonce, ciphertext) = ciphertext.split_at(crypto::NONCEBYTES);
    let nonce = crypto::Nonce::from_slice(nonce).ok_or(())?;

    crypto::open_precomputed(ciphertext, &nonce, key)
}

pub fn encrypt(key: &crypto::PrecomputedKey, plaintext: BytesMut) -> Vec<u8> {
    let mut nonce = crypto::Nonce([0; 24]);
    sodiumoxide::randombytes::randombytes_into(&mut nonce.0);

    let ciphertext = crypto::seal_precomputed(&plaintext, &nonce, key);

    [&nonce.0, &ciphertext[..]].concat()
}
