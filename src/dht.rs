use std::io::Cursor;
use std::io::Error;
use std::time::Duration;
use std::time::SystemTime;

use futures::prelude::*;
use futures::Stream;
use futures::Sink;

use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;

use stun3489;
use stun3489::Connectivity;

use sodiumoxide::crypto::box_::SecretKey;

use MsgPair;
use bulletinboard::BulletinBoard;

use errors::Result;
use crypto::Crypto;
use serialization::Serialize;
use wg::WireGuardConfig;
use wg::PublicKey;

// TODO: refactor
#[async]
pub fn dht_get(handle: Handle,
               secret_key: SecretKey,
               local_key: PublicKey,
               remote_key: PublicKey)
    -> Result<Option<Connectivity>>
{
    let key_pair = (secret_key, remote_key);

    let key = [&remote_key[..], &local_key[..]].concat();
    let value_list = await!(BulletinBoard::get(handle, key))?;

    info!("Found {} potential remote credentials", value_list.len());
    let value_list = value_list.into_iter().filter_map(|v| {
        if let Ok(v) = key_pair.decrypt(&v[..]) {
            Serialize::deserialize(&mut Cursor::new(v)).ok()
        } else {
            None
        }
    });

    let mut conn_list: Vec<(SystemTime, Connectivity)>;
    conn_list = value_list.collect();
    conn_list.sort_by(|a, b| a.0.cmp(&b.0).reverse());

    let mut conn_list = conn_list.into_iter().map(|t| t.1);
    let v = conn_list.next();
    Ok(v)
}

// TODO: refactor
#[async]
pub fn stun_publish(
    handle: Handle,
    sink: Box<Sink<SinkItem = MsgPair, SinkError = Error>>,
    stream: Box<Stream<Item = MsgPair, Error = Error>>,
    interface: String,
    remote_key: PublicKey,
) -> Result<()>
{
    let timeout = Duration::from_secs(1);
    let bind_addr = ([0,0,0,0], 0).into();
    let server = ([192,95,17,62], 3478).into(); // stun.callwithus.com

    let mut res = await!(stun3489::stun3489_generic(
            sink,
            stream,
            bind_addr,
            server,
            handle.clone(),
            timeout,
        ));

    loop {
        let (sink, stream, conn) = match res {
            Ok((sink, stream, conn)) => (sink, stream, Some(conn)),
            Err((sink, stream, _)) => (sink, stream, None),
        };

        if let Some(conn) = conn {
            info!("{:?} detected.", conn);

            let cfg = WireGuardConfig::new(&interface[..]).unwrap();
            let local_key = cfg.public_key().unwrap();
            let key_pair = (cfg.secret_key, remote_key);

            let mut wrt = vec![];
            (SystemTime::now(), conn).serialize(&mut wrt).unwrap();

            let key = [&local_key[..], &remote_key[..]].concat();
            let value = key_pair.encrypt(&wrt[..]);

            let _ = await!(BulletinBoard::insert(handle.clone(), key, value));
        }

        await!(Timeout::new(Duration::from_secs(60), &handle)?)?;

        res = await!(stun3489::stun3489_generic(
            sink,
            stream,
            bind_addr,
            server,
            handle.clone(),
            timeout,
        ));
    }
}

