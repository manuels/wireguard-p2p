use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::SecretKey;
use sodiumoxide::crypto::box_::PublicKey;
use sodiumoxide::crypto::box_::Nonce;

use errors::Result;

pub trait Crypto {
    fn encrypt(&self, msg: &[u8]) -> Vec<u8>;
    fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

impl<'a> Crypto for (&'a SecretKey, &'a PublicKey) {
    fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        let &(secret_key, public_key) = self;

        let nonce = box_::gen_nonce();
        let m = box_::seal(msg, &nonce, public_key, secret_key);

        [&nonce[..], &m[..]].concat().to_vec()
    }

    fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let &(secret_key, public_key) = self;
        let (n, m) = (24, 44);

        if msg.len() != n + m {
            return Err("Message does not have the right length!".into());
        }
        let (nonce, msg) = msg.split_at(n);

        let err = "Nonce is not 24 byte";
        let nonce = Nonce::from_slice(nonce).ok_or(err)?;

        let err = |_| "Decryption failed!".into();
        box_::open(msg, &nonce, public_key, secret_key).map_err(err)
    }
}

impl Crypto for (SecretKey, PublicKey) {
    fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        let &(ref sk, ref pk) = self;
        (sk, pk).encrypt(msg)
    }

    fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let &(ref sk, ref pk) = self;
        (sk, pk).decrypt(msg)
    }
}
