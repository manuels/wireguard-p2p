#![recursion_limit = "1024"]

extern crate futures;
extern crate tokio_core;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate stun3489;
extern crate dbus;
extern crate dbus_tokio;
extern crate byteorder;
extern crate ini;
extern crate sodiumoxide;
extern crate base64;

#[macro_use]
extern crate error_chain;

mod errors {
    error_chain!{}
}

use errors::ResultExt;

mod wg;
mod dht;
mod crypto;
mod duplicate;
mod serialization;
mod bulletinboard;

use std::ops::DerefMut;
use std::io::Write;
use std::io::Result;
use std::net::SocketAddr;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;

use futures::Stream;
use futures::Sink;
use futures::Future;
use futures::future::BoxFuture;
use futures::future::FutureResult;
use futures::future::ok;
use futures::future::err;
use futures::stream::SplitSink;
use futures::sync::mpsc::Receiver;
use futures::sync::mpsc::Sender;

use tokio_core::reactor::Core;
use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;
use tokio_core::reactor::Remote;
use tokio_core::net::UdpSocket;
use tokio_core::net::UdpCodec;
use tokio_core::net::UdpFramed;

use duplicate::duplicate_stream;
use duplicate::duplicate_sink;

use dht::dht_get;

use wg::WireGuardConfig;

struct RawCodec;

type MsgPair = (Vec<u8>, SocketAddr);

use wg::PublicKey;

impl UdpCodec for RawCodec {
    type In = MsgPair;
    type Out = MsgPair;

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> Result<Self::In> {
        debug!("IN  len={} src={:?}", buf.len(), src);
        Ok((buf.to_vec(), src.clone()))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (m, dst) = msg;

        debug!("OUT len={} dst={:?}", m.len(), dst);
        buf.write(&m).unwrap();
        dst
    }
}

fn get_local_sink<'a, 'b>(
    handle: &'a Handle,
    sinks: &'b mut HashMap<SocketAddr, (SplitSink<UdpFramed<RawCodec>>, SocketAddr)>,
    public_sink: Sender<MsgPair>,
    remote_addr: SocketAddr,
) -> Option<&'b mut (SplitSink<UdpFramed<RawCodec>>, SocketAddr)> {
    let local_addr_mask = "127.0.0.1:0".parse().unwrap();

    if !sinks.contains_key(&remote_addr) {
        debug!("New connection from {}.", remote_addr);

        let ((local_sink, local_stream), local_addr) = {
            let msg = format!("Unable to bind UDP socket {}", local_addr_mask);
            let local_sock = UdpSocket::bind(&local_addr_mask, handle).expect(&msg);
            let local_addr = local_sock.local_addr().unwrap();

            debug!("Adding new proxy for {:?}: {:?}", remote_addr, local_addr);
            (local_sock.framed(RawCodec).split(), local_addr)
        };

        let dst = remote_addr.clone();
        let send_to_public = local_stream.map(move |(buf, _)| {
            debug!("len={} dst={}", buf.len(), dst);
            (buf, dst)
        });

        handle.spawn(
            send_to_public
                .map_err(|_| ())
                .forward(public_sink.sink_map_err(|_| ()))
                .map(|_| ()),
        );

        sinks.insert(remote_addr, (local_sink, local_addr));
    }

    sinks.get_mut(&remote_addr)
}

fn wireguard_dispatch(
    sinks: Arc<Mutex<HashMap<SocketAddr, (SplitSink<UdpFramed<RawCodec>>, SocketAddr)>>>,
    public_sink: Sender<MsgPair>,
    public_stream: Receiver<MsgPair>,
    remote: &Remote,
    wg_addr: SocketAddr,
) -> BoxFuture<(), ()> {
    let remote = remote.clone();

    public_stream
        .for_each(move |(buf, remote_addr)| {
            let sinks = sinks.clone();
            let public_sink = public_sink.clone();
            debug!("public stream: src {:?}", remote_addr);

            remote.spawn(move |handle| {
                let mut sinks = sinks.lock().unwrap();

                if let Some(&mut (ref mut local_sink, _)) =
                    get_local_sink(&handle, sinks.deref_mut(), public_sink, remote_addr)
                {
                    debug!("dispatch to {:?}", wg_addr);
                    if let Err(_) = local_sink.start_send((buf, wg_addr)) {
                        unimplemented!();
                    }
                    if local_sink.poll_complete().is_err() {
                        unimplemented!();
                    }
                } else {
                    unreachable!()
                };

                ok(())
            });
            ok(())
        })
        .boxed()
}

fn update_endpoint(
    handle: Handle,
    interface: String,
    remote_key: PublicKey,
    public_sink: Sender<MsgPair>,
    sinks: Arc<Mutex<HashMap<SocketAddr, (SplitSink<UdpFramed<RawCodec>>, SocketAddr)>>>,
) -> Box<Future<Item = (), Error = ()>> {
    let remote = handle.remote().clone();
    let res = dht_get(handle.clone(), interface.clone(), remote_key);

    debug!("Getting remote connectivity...");
    let iface = interface.clone();
    let future = if let Ok(future) = res {
        info!("Remote future...");
        let handle = handle.clone();
        let public_sink = public_sink.clone();
        let sinks = sinks.clone();

        Box::new(
            future
                .or_else(|e| {
                    warn!("err={:?}", e);
                    err(e)
                })
                .map_err(|_| ())
                .and_then(move |conn| {
                    info!("Remote connectivity: {:?}", conn);
                    let mut cfg = WireGuardConfig::new(&iface[..]).unwrap();

                    let peer = cfg.peers.remove(&remote_key).unwrap();
                    if let Some(addr) = conn.and_then(|c| c.into()) {
                        let mut sinks = sinks.lock().unwrap();
                        if let Some(&mut (_, local_addr)) =
                            get_local_sink(&handle, &mut sinks, public_sink, addr)
                        {
                            peer.set_endpoint(&iface[..], local_addr).unwrap();
                            // TODO: add duplicate... set endpoint to this duplicate...
                        }
                    }

                    ok(())
                }),
        ) as Box<Future<Item = (), Error = ()>>
    } else {
        info!("Remote connectivity not found.");
        Box::new(ok(())) as Box<Future<Item = (), Error = ()>>
    };

    let timeout = Timeout::new(Duration::from_secs(1 * 60), &handle).unwrap();
    Box::new(future.then(|_| timeout).then(move |_| {
        info!("respawn...");
        remote.spawn(move |handle| {
            update_endpoint(handle.clone(), interface, remote_key, public_sink, sinks)
        });
        ok(())
    }))
}

fn main() {
    env_logger::init().unwrap();

    let mut argv = std::env::args().skip(1);
    let interface = argv.next().unwrap();
    let remote_key = base64::decode(&argv.next().unwrap()).unwrap();
    let remote_key = PublicKey::from_slice(&remote_key[..]).unwrap();

    let public_addr = "0.0.0.0:0".parse().unwrap();

    let cfg = WireGuardConfig::new(&interface[..]).unwrap();
    let wg_addr: SocketAddr = format!("127.0.0.1:{}", cfg.interface.listen_port)
        .parse()
        .unwrap();

    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let sinks = Arc::new(Mutex::new(HashMap::<
        SocketAddr,
        (SplitSink<UdpFramed<RawCodec>>, SocketAddr),
    >::new()));

    let public_socket = UdpSocket::bind(&public_addr, &handle).unwrap();
    let (public_sink, public_stream) = public_socket.framed(RawCodec).split();

    let public_sink = public_sink.sink_map_err(|_| ());
    let public_sink = duplicate_sink(&handle, public_sink);

    let public_stream = public_stream.then(|e| e.chain_err(|| "public_stream failed"));
    let (public_stream1, public_stream2) = duplicate_stream(&handle, public_stream);

    let public_stream1 = public_stream1.map_err(|_| ());
    let public_sink1 = public_sink.clone().sink_map_err(|_| ());
    let future = dht::stun_publish(
        handle.clone(),
        public_sink1,
        public_stream1,
        interface.to_string(),
        remote_key,
    );
    let future = future.map_err(|_| ());
    handle.spawn(future);

    handle.spawn(update_endpoint(
        handle.clone(),
        interface.to_string(),
        remote_key.clone(),
        public_sink.clone(),
        sinks.clone(),
    ));

    let future = wireguard_dispatch(sinks, public_sink, public_stream2, handle.remote(), wg_addr);
    core.run(future).unwrap();
}

fn catch_and_report_error<F, R>(func: F) -> FutureResult<R, ()>
where
    F: FnOnce() -> errors::Result<R>,
{
    match func() {
        Ok(r) => ok(r),
        Err(e) => {
            error!("error: {}", e);
            for e in e.iter().skip(1) {
                error!("caused by: {}", e);
            }

            if let Some(backtrace) = e.backtrace() {
                error!("backtrace: {:?}", backtrace);
            }
            err(())
        }
    }
}
