use futures::Future;
use futures::future::ok;
use tokio_core::reactor::Core;

use sodiumoxide::crypto::hash::sha256;

use base64;

use errors::Result;
use errors::ResultExt;
use bulletinboard::BulletinBoard;


pub fn search(peer_name: String) -> Result<()> {
    let err = || "Failed to create tokio Core";
    let mut core = Core::new().chain_err(err)?;
    let handle = core.handle();

    println!("Searching for '{}'...", peer_name);
    let future = BulletinBoard::get(handle, peer_name.as_bytes());

    let future = future.and_then(move |values| {
        let values: Vec<_> = values
            .iter()
            .filter(|v| v.len() == 32 + 32)
            .filter_map(|v| {
                let key = &v[32..];

                let d1 = sha256::Digest::from_slice(&v[..32]);
                let d2 = Some(sha256::hash(key));

                if d1 == d2 { Some(key) } else { None }
            })
            .collect();

        if values.len() == 0 {
            println!("No public keys found!");
        } else {
            println!("{} public key(s) found:", values.len());

            for (i, v) in values.iter().enumerate() {
                println!("  {}) {}", i + 1, base64::encode(v));
            }
        }

        ok(())
    });

    let err = || "Failed run tokio Core";
    core.run(future).chain_err(err)
}
