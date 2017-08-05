use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::SecretKey;
use sodiumoxide::crypto::box_::PublicKey;
use sodiumoxide::crypto::box_::Nonce;

use errors::Result;

pub trait Encrypt {
    fn encrypt(&self, msg: &[u8]) -> Vec<u8>;
    fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

impl Encrypt for (SecretKey, PublicKey) {
    fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        let &(ref secret_key, ref public_key) = self;

        let nonce = box_::gen_nonce();
        let m = box_::seal(msg, &nonce, &public_key, &secret_key);

        [&nonce[..], &m[..]].concat().to_vec()
    }

    fn decrypt(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let &(ref secret_key, ref public_key) = self;

        let n = 24;
        let m = 44;

        if msg.len() != n + m {
            return Err("Message does not have the right length!".into());
        }
        let (nonce, msg) = msg.split_at(n);

        let err = || "Nonce is not 24 byte";
        let nonce = Nonce::from_slice(nonce).ok_or_else(err)?;

        let err = |_| "Decryption failed!".into();
        box_::open(&msg, &nonce, &public_key, &secret_key).map_err(err)
    }
}
