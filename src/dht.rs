use std::io;
use std::io::Cursor;
use std::io::ErrorKind;
use std::time::Duration;
use std::time::SystemTime;

use futures::Stream;
use futures::Sink;
use futures::Future;
use futures::future::ok;

use tokio_core::reactor::Handle;

use stun3489;
use stun3489::Connectivity;

use errors::*;
use errors::Error;

use MsgPair;
use catch_and_report_error;
use bulletinboard::BulletinBoard;

use BoxedFuture;
use crypto::Encrypt;
use serialization::Serialize;
use wg::WireGuardConfig;
use wg::PublicKey;

pub fn stun_publish(handle: Handle,
                    sink: Box<Sink<SinkItem=MsgPair, SinkError=Error>>,
                    stream: Box<Stream<Item=MsgPair, Error=Error>>,
                    interface: String,
                    remote_key: PublicKey)
    -> Box<Future<Item=(Box<Sink<SinkItem=MsgPair, SinkError=Error>>,
                        Box<Stream<Item=MsgPair, Error=Error>>),
                  Error=(Box<Sink<SinkItem=MsgPair, SinkError=Error>>,
                         Box<Stream<Item=MsgPair, Error=Error>>,
                         Error)>>
{
    let timeout = Duration::from_secs(1);

    let err = || "Unable to parse bind address";
    let bind_addr = "0.0.0.0:0".parse().unwrap();
//    let bind_addr = box_try!("0.0.0.0:0".parse().chain_err(err));

    let err = || "Unable to parse stun server address";
    let server = "192.95.17.62:3478".parse().unwrap(); // stun.callwithus.com
//    let server = box_try!("192.95.17.62:3478".parse().chain_err(err)); // stun.callwithus.com

    // TODO: filter stream for stun messages
    let stream = stream.map_err(|_| io::Error::new(ErrorKind::Other, ""));
    let sink = sink.sink_map_err(|_| io::Error::new(ErrorKind::Other, ""));

    let future = stun3489::stun3489_generic(Box::new(stream), Box::new(sink),
        bind_addr, server, &handle, timeout);

    let future = future.and_then(|(stream, sink, conn)| {
        info!("{:?} detected.", conn);
        ok((sink, stream, conn))
    });

    let future = future.and_then(move |(sink, stream, conn)| {
        let remote = handle.remote();
        let mut wrt = vec![];

        let err = || "Reading WireGuard config failed.";
        let cfg = WireGuardConfig::new(&interface[..]).chain_err(err).unwrap();
        let interface = cfg.interface;

        let err = || "Failed getting our public key.";
        let local_key = interface.public_key().chain_err(err).unwrap();

        let key_pair = (interface.secret_key, remote_key);

        let err = || "Encoding DHT message failed.";
        (SystemTime::now(), conn).serialize(&mut wrt).chain_err(err).unwrap();

        remote.spawn(move |handle: &Handle| {
            let key = [&local_key[..], &remote_key[..]].concat();
            let value = key_pair.encrypt(&wrt[..]);

            BulletinBoard::insert(handle.clone(), &key[..], &value[..]).map_err(|_| ())
        });

        ok((sink, stream))
    });

    Box::new(future.map_err(|(stream, sink, e)| {
        (Box::new(sink.sink_map_err(|e| Error::with_chain(e, ""))) as Box<Sink<SinkItem=MsgPair, SinkError=Error>>,
         Box::new(stream.map_err(|e| Error::with_chain(e, ""))) as Box<Stream<Item=MsgPair, Error=Error>>,
         Error::with_chain(e, "")
         )
    }).map(|(sink, stream)| {
        (Box::new(sink.sink_map_err(|e| Error::with_chain(e, ""))) as Box<Sink<SinkItem=MsgPair, SinkError=Error>>,
         Box::new(stream.map_err(|e| Error::with_chain(e, ""))) as Box<Stream<Item=MsgPair, Error=Error>>,
         )
    }))
}

pub fn dht_get(handle: Handle,
               interface: &str,
               remote_key: PublicKey)
    -> Result<BoxedFuture<Option<Connectivity>>>
{
    let err = || "Reading WireGuard config failed.";
    let cfg = WireGuardConfig::new(&interface[..]).chain_err(err)?;
    let iface = cfg.interface;

    let err = || "Failed getting our public key.";
    let local_key = iface.public_key().chain_err(err)?;

    let key = [&remote_key[..], &local_key[..]].concat();
    let future = BulletinBoard::get(handle, &key[..]);

    let future = future.and_then(move |value_list| {
        let key_pair = (iface.secret_key, remote_key);

        info!("Found {} potential remote credentials", value_list.len());
        let value_list = value_list.into_iter();
        let value_list = value_list.filter_map(|v| key_pair.decrypt(&v[..]).ok());
        let value_list = value_list.map(Cursor::new);
        let value_list = value_list.filter_map(|mut r| Serialize::deserialize(&mut r).ok());

        let mut conn_list: Vec<(SystemTime, Connectivity)>;
        conn_list = value_list.collect();
        conn_list.sort_by(|a, b| a.0.cmp(&b.0).reverse());

        let mut conn_list = conn_list.into_iter().map(|t| t.1);
        Ok(conn_list.next())
    });

    Ok(Box::new(future))
}
