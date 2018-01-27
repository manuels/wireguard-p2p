use base64;
use errors::Result;
use tokio_core::reactor::Handle;
use futures::prelude::*;

use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

use dht::Dht;
use dht::deserialize_public_key;

#[async]
/// Program entry point for 'wg-p2p search'
pub fn search(handle: Handle, peer_name: String) -> Result<()> {
    let key_list: Vec<PublicKey>;

    let dht = Dht::new(handle)?;
    let values = await!(dht.get(peer_name.as_bytes().to_vec()))?; // TODO: await stream?
    key_list = values.iter().filter_map(deserialize_public_key).collect();

    if key_list.is_empty() {
        println!("No public keys found for '{}'!", peer_name);
        return Ok(());
    }

    println!("{} public key(s) found:", key_list.len());
    for (i, k) in key_list.iter().enumerate() {
        println!("  {}) {}", i + 1, base64::encode(k));
    }

    Ok(())
}

