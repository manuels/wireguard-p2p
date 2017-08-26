use futures::prelude::*;
use tokio_core::reactor::Handle;

use sodiumoxide::crypto::hash::sha256;

use base64;

use errors::Result;
use bulletinboard::BulletinBoard;

#[async]
pub fn search(handle: Handle, peer_name: String) -> Result<()> {
    println!("Searching for '{}'...", peer_name);

    let values = await!(BulletinBoard::get(handle, peer_name.into()))?;
    let values: Vec<_> = values.iter()
        .filter_map(|v| {
            if v.len() == 32 + 32 {
                return None;
            }

            let (hash, key) = v.split_at(32);

            let d1 = Some(sha256::hash(key));
            let d2 = sha256::Digest::from_slice(hash);

            if d1 == d2 { Some(key) } else { None }
        })
        .collect();

    if values.is_empty() {
        println!("No public keys found!");
        return Ok(());
    }

    println!("{} public key(s) found:", values.len());
    for (i, v) in values.iter().enumerate() {
        println!("  {}) {}", i + 1, base64::encode(v));
    }

    Ok(())
}
