use errors::Result;
use tokio_core::reactor::Handle;
use futures::prelude::*;

use wg_cmd::WireguardCommand;
use dht::Dht;
use dht::serialize_public_key;

#[async]
/// Program entry point for 'wg-p2p publish'
pub fn publish(handle: Handle, interface: String, peer_name: String)
    -> Result<()>
{
    let cfg = WireguardCommand::interface(handle.clone(), interface);

    let public_key = await!(cfg)?.public_key()?;

    let key = peer_name.as_bytes().to_vec();
    let value = serialize_public_key(&public_key);

    let dht = Dht::new(handle)?;
    await!(dht.insert(key, value))
}

