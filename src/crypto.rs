use std::sync::{Once, ONCE_INIT};

use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::Nonce;
use sodiumoxide::crypto::box_::NONCEBYTES;
pub use sodiumoxide::crypto::box_::PrecomputedKey;

static INIT: Once = ONCE_INIT;

pub trait Encrypt {
    fn encrypt(&self, key: &PrecomputedKey) -> BytesMut;
}

impl Encrypt for Bytes {
    fn encrypt(&self, key: &PrecomputedKey) -> BytesMut {
        INIT.call_once(|| sodiumoxide::init().unwrap());

        let nonce = box_::gen_nonce();
        let ciphertext = box_::seal_precomputed(self, &nonce, &key);

        let mut out = BytesMut::with_capacity(1024);
        out.put(&nonce[..]);
        out.put(&ciphertext);

        out
    }
}

pub trait Decrypt {
    fn decrypt(&self, key: &PrecomputedKey) -> Result<Bytes, ()>;
}

impl Decrypt for Vec<u8> {
    fn decrypt(&self, key: &PrecomputedKey) -> Result<Bytes, ()> {
        INIT.call_once(|| sodiumoxide::init().unwrap());

        let (nonce, msg) = self.split_at(NONCEBYTES);

        let nonce = Nonce::from_slice(nonce).ok_or(())?;
        let buf = box_::open_precomputed(msg, &nonce, key)?;
        Ok(Bytes::from(buf))
    }
}

#[test]
fn test_crypto() {
    let (ourpk, oursk) = box_::gen_keypair();
    let (theirpk, theirsk) = box_::gen_keypair();
    let our_precomputed_key = box_::precompute(&theirpk, &oursk);

    let plaintext = Bytes::from("plaintext");
    let ciphertext = plaintext.encrypt(&our_precomputed_key);

    let their_precomputed_key = box_::precompute(&ourpk, &theirsk);
    let their_plaintext = ciphertext.to_vec().decrypt(&their_precomputed_key).unwrap();
    assert!(plaintext == &their_plaintext[..]);
}