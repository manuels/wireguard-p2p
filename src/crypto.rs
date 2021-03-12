use crate::api::PublicKeyCrypto;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::NONCEBYTES;

use base64;
use bytes::BufMut;

#[derive(Clone)]
pub struct PublicKey(pub box_::PublicKey);
pub struct SecretKey(pub box_::SecretKey);

pub struct Sodiumoxide(box_::PrecomputedKey);

impl Sodiumoxide {
    pub fn new(their_pk: &PublicKey, our_sk: &SecretKey) -> Self {
        let precomputed_key = box_::precompute(&their_pk.0, &our_sk.0);
        Self(precomputed_key)
    }
}

impl PublicKeyCrypto for Sodiumoxide {
    fn encrypt(&self, plaintext: &[u8]) -> anyhow::Result<bytes::Bytes> {
        let nonce = box_::gen_nonce();

        let ciphertext = box_::seal_precomputed(plaintext, &nonce, &self.0);

        let mut buf = bytes::BytesMut::new();
        buf.put(&nonce.0[..]);
        buf.put(&ciphertext[..]);

        return Ok(buf.freeze());
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < NONCEBYTES {
            dbg!("Decryption failed");
            return None;
        }
        let (nonce, ciphertext) = ciphertext.split_at(NONCEBYTES);

        if let Some(nonce) = box_::Nonce::from_slice(&nonce[..]) {
            let r = box_::open_precomputed(&ciphertext, &nonce, &self.0);
            if r.is_err() {
                dbg!("Decryption failed");
            }
            r.ok()
        } else {
            None
        }
    }
}

impl PublicKey {
    pub fn new(buf: [u8; 32]) -> Self {
        Self(box_::PublicKey(buf))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}", base64::encode(self.0.0))
    }
}

impl SecretKey {
    pub fn new(buf: [u8; 32]) -> Self {
        Self(box_::SecretKey(buf))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }
}
