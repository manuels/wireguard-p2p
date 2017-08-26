use futures::prelude::*;
use tokio_core::reactor::Handle;

use sodiumoxide::crypto::hash::sha256;

use base64;

use errors::Result;
use wg::WireGuardConfig;
use bulletinboard::BulletinBoard;


#[async]
pub fn publish(handle: Handle, interface: String, peer_name: String) -> Result<()> {
    let key = WireGuardConfig::new(&interface[..])?.public_key()?;

    let hash = sha256::hash(&key[..]);
    let value = [&hash[..], &key[..]].concat();

    println!(
        "Publishing public key for interface '{}' ({}...) as '{}'...",
        interface,
        &base64::encode(&key[..])[..7],
        peer_name
    );

    let res = await!(BulletinBoard::insert(handle, peer_name.into(), value));

    let msg = if res.is_ok() { "Done." } else { "Failed!" };
    println!("{}", msg);

    Ok(())
}
