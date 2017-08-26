use std::io;
use std::rc::Rc;
use std::net::SocketAddr;
use std::net::Ipv4Addr;
use std::io::ErrorKind;
use std::time::Duration;
use std::time::Instant;
use std::collections::HashMap;
use std::sync::Mutex;

use base64;

use ini::Ini;

use futures::prelude::*;
use futures::Sink;
use futures::Stream;
use futures::Future;
use futures::stream::SplitSink;
use futures::sync::mpsc::Sender;

use tokio_core::reactor::Core;
use tokio_core::reactor::Handle;
use tokio_core::reactor::Interval;
use tokio_core::net::UdpSocket;
use tokio_core::net::UdpCodec;
use tokio_core::net::UdpFramed;

use duplicate::duplicate_stream;
use duplicate::duplicate_sink;

use MsgPair;
use dht;
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
        Ok((buf.to_vec(), *src))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (mut m, dst) = msg;

        debug!("OUT len={} dst={:?}", m.len(), dst);
        buf.append(&mut m);
        dst
    }
}

type PeerSink = SplitSink<UdpFramed<RawCodec>>;

struct ProxyConnections {
    wg_addr: SocketAddr,
    sinks: HashMap<SocketAddr, (PeerSink, SocketAddr)>,
    handle: Handle,
    public_sink: Sender<MsgPair>,
}

impl ProxyConnections {
    fn new(handle: Handle, public_sink: Sender<MsgPair>, wg_addr: SocketAddr)
        -> ProxyConnections
    {
        ProxyConnections {
            handle,
            public_sink,
            wg_addr,
            sinks: HashMap::new(),
        }
    }

    pub fn get_local_addr(&mut self, remote_addr: SocketAddr) -> SocketAddr {
        let &mut (_, ref local_addr) = self.get_entry(remote_addr);

        *local_addr
    }

    fn get_local_sink(&mut self, remote_addr: SocketAddr) -> &mut PeerSink {
        let &mut (ref mut sink, _) = self.get_entry(remote_addr);

        sink
    }

    fn new_connection(handle: &Handle,
                      public_sink: Sender<MsgPair>,
                      remote_addr: SocketAddr)
        -> (PeerSink, SocketAddr)
    {
        debug!("New connection from {}.", remote_addr);

        let ((local_sink, local_stream), local_addr) = {
            let local_addr_mask = ([127,0,0,1], 0).into();
            let msg = "Unable to bind to a UDP socket on localhost";
            let local_sock = UdpSocket::bind(&local_addr_mask, handle).expect(msg);
            let local_addr = local_sock.local_addr().unwrap();

            debug!("Adding new proxy for {:?}: {:?}", remote_addr, local_addr);
            (local_sock.framed(RawCodec).split(), local_addr)
        };

        let redirect_to_public = local_stream.map(move |(buf, _)| {
            debug!("len={} dst={}", buf.len(), remote_addr);
            (buf, remote_addr)
        });

        handle.spawn(
            redirect_to_public
                .map_err(|_| ())
                .forward(public_sink.sink_map_err(|_| ()))
                .map(|_| ()),
        );

        (local_sink, local_addr)
    }

    fn get_entry(&mut self, remote_addr: SocketAddr) -> &mut (PeerSink, SocketAddr) {
        let handle = &self.handle;
        let public_sink = self.public_sink.clone();

        let create_connection = || Self::new_connection(handle, public_sink, remote_addr);

        let entry = self.sinks.entry(remote_addr);
        entry.or_insert_with(create_connection)
    }

    pub fn forward(&mut self,
                   msg: Vec<u8>,
                   remote_addr: SocketAddr)
        -> Result<()>
    {
        let wg_addr = self.wg_addr;
        debug!("forwardig to {:?}", wg_addr);

        let sink = &mut *self.get_local_sink(remote_addr);
        sink.start_send((msg, wg_addr))?;
        sink.poll_complete()?;

        Ok(())
    }
}

#[async]
fn update_endpoint(handle: Handle, proxies: Rc<Mutex<ProxyConnections>>,
                   interface: String, remote_key: PublicKey)
    -> Result<()>
{
    let repeat = Interval::new_at(Instant::now(), Duration::from_secs(60), &handle)?;

    #[async]
    for _ in repeat {
        let cfg = WireGuardConfig::new(&interface[..])?;

        let local_key = cfg.public_key()?;
        let secret_key = cfg.secret_key;

        let conn = await!(dht::dht_get(handle.clone(), secret_key, local_key, remote_key))?;
        info!("Remote connectivity: {:?}", conn);

        if let Some(remote_addr) = conn.and_then(|c| c.into()) {
            let local_addr = proxies.lock().unwrap().get_local_addr(remote_addr);

            let peer = &cfg.peers[&remote_key];
            peer.set_endpoint(local_addr)?;
        }
    }

    Ok(())
}

pub fn daemon(conf_path: String) -> Result<()> {
    let ini = Ini::load_from_file(conf_path)?;

    let msg = "INI file has no sections";
    let mut section_iter = ini.iter().filter(|&(k, _)| k.is_some());
    let (interface, section) = section_iter.next().ok_or(msg)?;

    let msg = "INI file has no section";
    let interface = interface.clone().ok_or(msg)?;

    let msg = "INI section has no Peer1";
    let remote_key = section.get("Peer1").ok_or(msg)?;
    let remote_key = base64::decode(remote_key)?;

    let msg = "Failed to read public key";
    let remote_key = PublicKey::from_slice(&remote_key[..]).ok_or(msg)?;

    let mut core = Core::new()?;
    let handle = core.handle();

    let public_addr = ([0,0,0,0], 0).into();
    let public_socket = UdpSocket::bind(&public_addr, &handle)?;
    let (public_sink, public_stream) = public_socket.framed(RawCodec).split();

    let public_sink = public_sink.sink_map_err(|_| ());
    let public_sink = duplicate_sink(&handle, public_sink);

    let public_stream = public_stream.then(|e| e.chain_err(|| "public_stream failed"));
    let (public_stream1, public_stream2) = duplicate_stream(&handle, public_stream);

    let public_sink1 = public_sink.clone().sink_map_err(|_| io::Error::new(ErrorKind::Other, ""));
    let public_stream1 = public_stream1.map_err(|_| io::Error::new(ErrorKind::Other, ""));

    let iface = interface.clone();
    let future = dht::stun_publish(
            handle.clone(),
            Box::new(public_sink1),
            Box::new(public_stream1),
            iface.to_string(),
            remote_key,
    );
    handle.spawn(future.map_err(|_| ()));

    let localhost: Ipv4Addr = [127,0,0,1].into();

    let cfg = WireGuardConfig::new(&interface).unwrap();
    let wg_addr = cfg.listen_port;

    let proxies = Rc::new(Mutex::new(ProxyConnections::new(
        handle.clone(),
        public_sink,
        (localhost, wg_addr).into(),
    )));

    let future = update_endpoint(handle.clone(), proxies.clone(),
            interface, remote_key);
    handle.spawn(future.map_err(|_| ()));

    let future = public_stream2.for_each(|(buf, remote_addr)| {
        proxies.lock().unwrap().forward(buf, remote_addr).map_err(|_| ())
    });
    let future = future.map_err(|_| Error::from_kind("wireguard_dispatch failed".into()));

    core.run(future)
}

