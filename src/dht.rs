use std::io;
use std::io::Cursor;
use std::io::ErrorKind;
use std::time::Duration;
use std::time::SystemTime;

use futures::Stream;
use futures::Sink;
use futures::Future;
use futures::future::ok;
use futures::future::BoxFuture;
use futures::future::FutureResult;

use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;

use stun3489;
use stun3489::Connectivity;

use errors::*;
use errors::Error;

use MsgPair;
use catch_and_report_error;
use bulletinboard::BulletinBoard;

use wg::WireGuardConfig;
use wg::PublicKey;
use serialization::Serialize;
use crypto::Encrypt;

pub fn stun_publish<SI, ST, E>(
    handle: Handle,
    sink: SI,
    stream: ST,
    interface: String,
    remote_key: PublicKey,
) -> BoxFuture<(), ()>
where
    SI: Sink<SinkItem = MsgPair, SinkError = E> + Send + 'static,
    ST: Stream<Item = MsgPair, Error = E> + Send + 'static,
{
    let timeout = Duration::from_secs(1);
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let server = "192.95.17.62:3478".parse().unwrap(); // stun.callwithus.com

    // TODO: filter stream for stun messages
    let stream = stream.map_err(|_| io::Error::new(ErrorKind::Other, ""));
    let sink = sink.sink_map_err(|_| io::Error::new(ErrorKind::Other, ""));

    let stun = stun3489::stun3489_generic(
        stream.boxed(),
        Box::new(sink),
        bind_addr,
        server,
        &handle,
        timeout,
    );
    let stun = stun.and_then(|(stream, sink, conn)| {
        info!("{:?} detected.", conn);
        ok((stream, sink, conn))
    });

    let remote = handle.remote().clone();
    let dht_publish = move |(stream, sink, c)| {
        let iface = interface.clone();
        remote.clone().spawn(move |handle| {
            let future = catch_and_report_error(move || {
                let cfg = WireGuardConfig::new(&interface[..]).chain_err(
                    || "Reading WireGuard config failed.",
                )?;
                let local_key = cfg.interface.public_key().chain_err(
                    || "Failed getting our public key.",
                )?;

                let key = [&local_key[..], &remote_key[..]].concat();
                let mut value = vec![];
                (SystemTime::now(), c).serialize(&mut value).chain_err(
                    || "Encoding DHT message failed.",
                )?;
                let value = (cfg.interface.secret_key, remote_key).encrypt(&value[..]);

                let future = BulletinBoard::insert(handle.clone(), &key[..], &value[..]);
                let future = future.then(move |res| {
                    if let Err(e) = res {
                        warn!("Publishing Connectivity failed: {:?}", e);
                    } else {
                        debug!("Connectivity published.");
                    }
                    ok(()) as FutureResult<(), ()>
                });

                debug!("Publishing connectivity...");
                Ok(future)
            });

            future.flatten().then(move |_| {
                remote.clone().spawn(move |handle| {
                    let timeout = Timeout::new(Duration::from_secs(5 * 60), &handle).unwrap();
                    timeout.then(move |_| {
                        remote.spawn(move |handle| {
                            stun_publish(handle.clone(), sink, stream, iface, remote_key)
                        });

                        ok(())
                    })
                });

                ok(())
            })
        });
        ok(())
    };

    stun.and_then(dht_publish)
        .map(|_| ())
        .map_err(|_| ())
        .boxed()
}

pub fn dht_get(
    handle: Handle,
    interface: String,
    remote_key: PublicKey,
) -> Result<Box<Future<Item = Option<Connectivity>, Error = Error>>> {
    let cfg = WireGuardConfig::new(&interface[..]).chain_err(
        || "Reading WireGuard config failed.",
    )?;
    let local_key = cfg.interface.public_key().chain_err(
        || "Failed getting our public key.",
    )?;

    let key_pair = (cfg.interface.secret_key, remote_key);
    let key = [&remote_key[..], &local_key[..]].concat();
    let future = BulletinBoard::get(handle, &key[..]);

    let future = future.and_then(move |value_list| {
        info!("value_list len={}", value_list.len());
        let value_list = value_list.into_iter();
        let value_list = value_list.filter_map(|v| key_pair.decrypt(&v[..]).ok());
        let value_list =
            value_list.filter_map(|r| Serialize::deserialize(&mut Cursor::new(r)).ok());

        let mut value_list: Vec<(SystemTime, Connectivity)> = value_list.collect();
        value_list.sort_by_key(|t| t.0);

        let mut value_list = value_list.into_iter().map(|t| t.1);
        Ok(value_list.next())
    });

    Ok(Box::new(future))
}
