use futures::Future;
use futures::future::result;
use tokio_core::reactor::Core;

use sodiumoxide::crypto::hash::sha256;

use base64;

use errors::Result;
use errors::ResultExt;
use wg::WireGuardConfig;
use bulletinboard::BulletinBoard;


pub fn publish(interface: String, peer_name: String) -> Result<()> {
    let err = || "Failed to create tokio Core";
    let mut core = Core::new().chain_err(err)?;
    let handle = core.handle();

    let err = || "Failed to read WireGuard configuration";
    let cfg = WireGuardConfig::new(&interface[..]).chain_err(err)?;

    let err = || "Failed to calculate public key";
    let key = cfg.interface.public_key().chain_err(err)?;

    let hash = sha256::hash(&key[..]);
    let value = [&hash[..], &key[..]].concat();

    println!("Publishing public key for interface '{}' ({}...) as '{}'...",
        interface, &base64::encode(&key[..])[..7], peer_name);

    let future = BulletinBoard::insert(handle, peer_name.as_bytes(), &value[..]);

    let future = future.then(|res| {
        if res.is_ok() {
            println!("Done.");
        } else {
            println!("Failed!");
        }

        result(Ok(()) as Result<()>)
    });

    let err = || "Failed run tokio Core";
    core.run(future)
        .chain_err(err)
}

