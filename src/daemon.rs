use std::ops::DerefMut;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;

use base64;

use ini::Ini;

use futures::Stream;
use futures::Sink;
use futures::Future;
use futures::future::ok;
use futures::future::err;
use futures::future::result;
use futures::stream::SplitSink;
use futures::sync::mpsc::Receiver;
use futures::sync::mpsc::Sender;

use tokio_core::reactor::Core;
use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;
use tokio_core::net::UdpSocket;
use tokio_core::net::UdpCodec;
use tokio_core::net::UdpFramed;

use duplicate::duplicate_stream;
use duplicate::duplicate_sink;

use MsgPair;
use dht;
use interval::Interval;
use wg::WireGuardConfig;
use wg::PublicKey;

use errors::Error;
use errors::Result;
use errors::ResultExt;

struct RawCodec;

impl UdpCodec for RawCodec {
    type In = MsgPair;
    type Out = MsgPair;

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        debug!("IN  len={} src={:?}", buf.len(), src);
        Ok((buf.to_vec(), src.clone()))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (mut m, dst) = msg;

        debug!("OUT len={} dst={:?}", m.len(), dst);
        buf.append(&mut m);
        dst
    }
}

fn get_local_sink<'a, 'b>(
    handle: &'a Handle,
    sinks: &'b mut HashMap<SocketAddr, (SplitSink<UdpFramed<RawCodec>>, SocketAddr)>,
    public_sink: Sender<MsgPair>,
    remote_addr: SocketAddr,
) -> Result<&'b mut (SplitSink<UdpFramed<RawCodec>>, SocketAddr)> {
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

    let err = "Did not to find sink".into();
    sinks.get_mut(&remote_addr).ok_or(err)
}

fn wireguard_dispatch(
    sinks: Arc<Mutex<HashMap<SocketAddr, (SplitSink<UdpFramed<RawCodec>>, SocketAddr)>>>,
    public_sink: Sender<MsgPair>,
    public_stream: Receiver<MsgPair>,
    handle: Handle,
    wg_addr: SocketAddr,
) -> Box<Future<Item = (), Error = ()>> {
    let future = public_stream.for_each((move |(buf, remote_addr)| report_errors!({
        let public_sink = public_sink.clone();
        debug!("public stream: src {:?}", remote_addr);

        let mut sinks = sinks.lock().unwrap();
        let res = get_local_sink(&handle, sinks.deref_mut(), public_sink, remote_addr);
        let &mut (ref mut local_sink, _) = box_try!(res);

        debug!("dispatching to {:?}", wg_addr);

        let err = || "Failed to dispatch to WireGuard address";
        let res = local_sink.start_send((buf, wg_addr));
        box_try!(res.chain_err(err));

        let err = || "Failed to dispatch to WireGuard address";
        let res = local_sink.poll_complete();
        box_try!(res.chain_err(err));

        Box::new(result(Ok(()) as Result<_>))
    })));

    Box::new(future)
}

fn update_endpoint(
    handle: Handle,
    interface: String,
    remote_key: PublicKey,
    public_sink: Sender<MsgPair>,
    sinks: Arc<Mutex<HashMap<SocketAddr, (SplitSink<UdpFramed<RawCodec>>, SocketAddr)>>>,
) -> Box<Future<Item = (), Error = ()>> {
    let res = dht::dht_get(handle.clone(), &interface[..], remote_key);

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

                        let &mut (_, local_addr) = get_local_sink(&handle, &mut sinks, public_sink, addr).unwrap();
                        peer.set_endpoint(&iface[..], local_addr).unwrap();
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
        update_endpoint(handle.clone(), interface, remote_key, public_sink, sinks);
        ok(())
    }))
}

pub fn daemon(conf_path: String) -> Result<()> {
    let msg = || "Failed to read config file";
    let ini = Ini::load_from_file(conf_path).chain_err(msg)?;

    let msg = "INI file has no sections";
    let mut section_iter = ini.iter().filter(|&(ref k, _)| k.is_some());
    let (interface, section) = section_iter.next().ok_or(msg)?;

    let msg = "INI file has no section";
    let interface = interface.clone().ok_or(msg)?;

    let msg = "INI section has no Peer1";
    let remote_key = section.get("Peer1").ok_or(msg)?;
    let remote_key = base64::decode(remote_key).unwrap();

    let msg = "Failed to read public key";
    let remote_key = PublicKey::from_slice(&remote_key[..]).ok_or(msg)?;

    let msg = || "Failed to bind to parse public address";
    let public_addr = "0.0.0.0:0".parse().chain_err(msg)?;

    let msg = || "Failed to parse WireGuard configuration";
    let cfg = WireGuardConfig::new(&interface[..]).chain_err(msg)?;

    let msg = || "Failed to parse WireGuard address";
    let wg_addr: SocketAddr = format!("127.0.0.1:{}", cfg.interface.listen_port)
        .parse()
        .chain_err(msg)?;

    let msg = || "Failed to create tokio Core";
    let mut core = Core::new().chain_err(msg)?;
    let handle = core.handle();

    let sinks = Arc::new(Mutex::new(HashMap::new()));

    let msg = || "Failed to bind to public address";
    let public_socket = UdpSocket::bind(&public_addr, &handle).chain_err(msg)?;
    let (public_sink, public_stream) = public_socket.framed(RawCodec).split();

    let public_sink = public_sink.sink_map_err(|_| ());
    let public_sink = duplicate_sink(&handle, public_sink);

    let public_stream = public_stream.then(|e| e.chain_err(|| "public_stream failed"));
    let (public_stream1, public_stream2) = duplicate_stream(&handle, public_stream);

    let public_stream1 = public_stream1.map_err(|e| "Stream failed".into());
    let public_sink1 = public_sink.clone().sink_map_err(|e| "Stream failed".into());

    let interval = Interval::new(handle.clone(), Duration::from_secs(5 * 60));
    let iface = interface.clone();
    let f = interval.run(
        Box::new(public_sink1),
        Box::new(public_stream1),
        move |handle, public_sink, public_stream| {
            let future = dht::stun_publish(
                handle.clone(),
                public_sink,
                public_stream,
                iface.to_string(),
                remote_key,
            );
            future.then(|res| match res {
                Ok((sink, stream)) => ok((sink, stream)),
                Err((sink, stream, e)) => err((sink, stream, e)),
            })
        },
    );
    handle.spawn(f.map_err(|_| ()));

    handle.spawn(update_endpoint(
        handle.clone(),
        interface.to_string(),
        remote_key.clone(),
        public_sink.clone(),
        sinks.clone(),
    ));

    let future = wireguard_dispatch(sinks, public_sink, public_stream2, handle, wg_addr);
    let future = future.map_err(|_| Error::from_kind("wireguard_dispatch failed".into()));

    let err = || "Failed run tokio Core";
    core.run(future).chain_err(err)
}
