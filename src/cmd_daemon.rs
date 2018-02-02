use base64;
use errors::Result;
use std::io;
use std::io::Cursor;
use std::io::ErrorKind;
use std::fs::File;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::collections::HashMap;
use ini::Ini;
use futures;
use futures::prelude::*;
use futures::future;
use futures::Sink;
use futures::Stream;
use futures::unsync::mpsc::Sender;
use futures::unsync::mpsc::Receiver;
use futures::unsync::mpsc::SendError;
use tokio_core::reactor::Interval;
use tokio_core::reactor::Handle;
use tokio_core::net::UdpCodec;
use tokio_core::net::UdpSocket;
use tokio_timer::Timer;

use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

use crypto::Crypto;
use serialize::Serialize;
use dht::Dht;
use wg_cmd::WireguardCommand;
use stun3489;
use stun3489::Connectivity;

struct RawCodec;

pub fn as_ipv6(addr: &SocketAddr) -> SocketAddrV6 {
    match *addr {
            SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_compatible(), a.port(), 0, 0),
            SocketAddr::V6(a) => SocketAddrV6::new(*a.ip(), a.port(), 0, 0),
    }
}

impl UdpCodec for RawCodec {
    type In = (SocketAddr, Vec<u8>);
    type Out = (SocketAddr, Vec<u8>);

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        Ok((*src, buf.to_vec()))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        let (dst, mut data) = msg;
        buf.append(&mut data);
        dst
    }
}

#[async]
fn publish_credentials(handle: Handle,
                       sink: Sender<(SocketAddr, Vec<u8>)>,
                       stream: Receiver<(SocketAddr, Vec<u8>)>,
                       stun_running: Rc<RefCell<bool>>,
                       secret_key: SecretKey,
                       peers: HashMap<String, String>)
     -> Result<()>
{
    let repeat = Duration::from_secs(60);
    let timeout = Duration::from_secs(1);

    let bind_addr = SocketAddr::from(([0,0,0,0], 0));
    let stun_server = SocketAddr::from(([158,69,26,138], 3478)); // stun.wtfismyip.com

    let sink = sink.sink_map_err(|_| io::Error::new(ErrorKind::Other, "oh no!"));
    let stream = stream.map_err(|()| io::Error::new(ErrorKind::Other, "oh no!"));
    let (mut sink, astream) = stun3489::codec(sink, stream);

    let mut stream: Box<Stream<Item=(u64, stun3489::codec::Response),Error=io::Error>>;
    stream = Box::new(Timer::default().timeout_stream(astream, timeout));

    #[async]
    for _ in Interval::new_at(Instant::now(), repeat, &handle)? {
        debug!("Trying to determine STUN3489 connectivity...");

        { *stun_running.borrow_mut() = true };
        let res = stun3489::connectivity(sink, stream, bind_addr, stun_server);

        let conn = match await!(res) {
            Ok(((asink, astream), conn)) => {
                sink = asink;
                stream = astream;
                conn
            },
            Err(((asink, astream), e)) => {
                warn!("STUN3489 failed: {:?}.", e);
                sink = asink;
                stream = astream;
                continue
            },
        };
        { *stun_running.borrow_mut() = false };
        // TODO: drain stream to prevent potential deadlock in send() (unlikely)

        info!("Connectivity: {:?}.", conn);

        let mut value = vec![];
        let now = SystemTime::now();
        (now, conn).serialize(&mut value)?;

        let peers = peers.clone();
        for (_, peer_key) in peers.into_iter() {
            let local_key = secret_key.public_key();
            let remote_key = str2key(&peer_key)?;
            let key = [&remote_key[..], &local_key[..]].concat();

            let encrypted_value = (&secret_key, &remote_key).encrypt(&value);

            debug!("Publishing credentials for {:?}...", peer_key);
            let dht = Dht::new(handle.clone())?;
            await!(dht.insert(key, encrypted_value))?;
            info!("Credentials published for {:?}.", peer_key);
        }
    }

    unreachable!();

    Ok(())
}

#[async]
fn lookup_credentials(handle: Handle,
                      outbound: Sender<(SocketAddr, Vec<u8>)>,
                      dev: String,
                      secret_key: SecretKey,
                      remote_key: String,
                      inet2wg: Rc<RefCell<HashMap<SocketAddrV6, Sender<(SocketAddr, Vec<u8>)>>>>,
                      mappings: Rc<RefCell<HashMap<SocketAddrV6, SocketAddr>>>)
    -> Result<()>
{
    let peer_key = str2key(&remote_key)?;
    let time = Duration::from_secs(60);
    let local_key = secret_key.public_key();
    let key = [&local_key[..], &peer_key[..]].concat();

    #[async]
    for _ in Interval::new_at(Instant::now(), time, &handle)? {
        debug!("Looking up credentials for {:?}", remote_key);
        let dht = Dht::new(handle.clone())?;
        let value_list = await!(dht.get(key.clone()))?;

        let conn: Option<SocketAddr>;
        conn = value_list.iter()
            .filter_map(|v| (&secret_key, &peer_key).decrypt(&v).ok())
            .filter_map(|v| Serialize::deserialize(&mut Cursor::new(v)).ok())
            .fold(None, |v1:Option<(SystemTime, Connectivity)>, v2:(SystemTime, Connectivity)| {
                if let Some(v1) = v1 {
                    if v1.0 > v2.0 {
                        return Some(v1);
                    }
                }
                return Some(v2);
            })
            .and_then(|(_,conn)| conn.into());

        info!("Credentials for {:?} found: {:?}", remote_key, conn);
        if let Some(remote_addr) = conn {
            debug!("Setting up endpoint...");
            let remote_addr_ipv6 = as_ipv6(&remote_addr);
            if !inet2wg.borrow().contains_key(&remote_addr_ipv6) {
                let (bind_addr, sink) = new_loopback_socket(&handle, remote_addr, outbound.clone())?;
                inet2wg.borrow_mut().insert(remote_addr_ipv6, sink);
                mappings.borrow_mut().insert(remote_addr_ipv6, bind_addr);
            }

            let b = mappings.borrow().get(&remote_addr_ipv6).cloned();
            if let Some(local_addr) = b {
                await!(WireguardCommand::set_endpoint(handle.clone(), dev.clone(),
                    peer_key, local_addr))?;
                info!("Endpoint {} <-> {} set sucessfully for {:?}.", remote_addr, local_addr, remote_key);
            }
        }
    }

    unreachable!();

    Ok(())
}

#[async]
fn dispatch_outbound<S>(udp_sink: S, receiver: Receiver<(SocketAddr, Vec<u8>)>)
    -> Result<()>
    where S: Sink<SinkItem=(SocketAddr, Vec<u8>), SinkError=io::Error> + 'static
{
    let receiver = receiver.map_err(|()| io::Error::new(ErrorKind::Other, "oh no!"));
    await!(receiver.forward(udp_sink))?;

    unreachable!();

    Ok(())
}

fn new_loopback_socket(handle: &Handle, dst: SocketAddr, outbound: Sender<(SocketAddr, Vec<u8>)>)
    -> Result<(SocketAddr, Sender<(SocketAddr, Vec<u8>)>)>
{
    let ip = Ipv6Addr::localhost();
    let bind_addr = (ip, 0).into();

    let udp = UdpSocket::bind(&bind_addr, handle)?;
    let bind_addr = udp.local_addr()?;
    let udp = udp.framed(RawCodec);
    let (sink, stream) = udp.split();

    let outbound = outbound.sink_map_err(|_| io::Error::new(ErrorKind::Other, "oh no!"));
    let stream = stream.map(move |(src, msg)| {
        debug!("Forwarding {} outgoing bytes from {} via {} to {}", msg.len(), src, bind_addr, dst);
        (dst, msg)
    });
    let f = stream.forward(outbound);

    let f = f.map(|_| warn!("stream.forward(outbound) done"));
    let f = f.map_err(|e| error!("stream.forward(outbound) {:?}", e));
    handle.spawn(f);

    let (tx, rx) = futures::unsync::mpsc::channel(1024);
    let rx = rx.map_err(|_| io::Error::new(ErrorKind::Other, "oh no!"));
    let f = rx.forward(sink);

    let f = f.map(|_| warn!("rx.forward(sink) done"));
    let f = f.map_err(|e| error!("rx.forward(sink) {:?}", e));
    handle.spawn(f);

    Ok((bind_addr, tx))
}

#[async]
fn dispatch_inbound<I,O>(handle: Handle,
                         inbound: I,
                         outbound: Sender<(SocketAddr, Vec<u8>)>,
                         mut stun_sink: O,
                         inet2wg: Rc<RefCell<HashMap<SocketAddrV6, Sender<(SocketAddr, Vec<u8>)>>>>,
                         mappings: Rc<RefCell<HashMap<SocketAddrV6,SocketAddr>>>,
                         stun_running: Rc<RefCell<bool>>,
                         wg_port: u16)
    -> Result<()>
    where I: Stream<Item=(SocketAddr, Vec<u8>), Error=io::Error> + 'static,
          O: Sink<SinkItem=(SocketAddr, Vec<u8>), SinkError=SendError<(SocketAddr, Vec<u8>)>> + Clone + 'static,
{
    let wg_addr = (Ipv6Addr::localhost(), wg_port).into();

    #[async]
    for (src, msg) in inbound {
        if { *stun_running.borrow() } {
            stun_sink = match await!(stun_sink.send((src, msg.clone()))) {
                Ok(sink) => sink,
                Err(e) => {
                    warn!("ERROR: {:?}", e);
                    Err(io::Error::new(ErrorKind::Other, format!("stun_sink.send() failed: {:?}", e)))?
                }
            };
        }

        // TODO: use sockets.entry().or_insert_with()
        // let s = sockets.entry(src.port()).or_insert_with(new_loopback_socket);
        let src_ipv6 = as_ipv6(&src);
        if !inet2wg.borrow().contains_key(&src_ipv6) {
            let (bind_addr, sink) = new_loopback_socket(&handle, src, outbound.clone())?;
            inet2wg.borrow_mut().insert(src_ipv6, sink);
            mappings.borrow_mut().insert(src_ipv6, bind_addr);
        }

        let local_addr = mappings.borrow().get(&src_ipv6).map(|s| s.clone()).expect("unreachable");
        debug!("Forwarding {} incoming bytes from {} via {} to {}.", msg.len(), src, local_addr, wg_addr);
        let s = inet2wg.borrow().get(&src_ipv6).map(|s| s.clone()).expect("unreachable");
        let f = s.send((wg_addr, msg.clone()));

        let f = f.map(|_| ());
//        let f = f.map_err(|_| io::Error::new(ErrorKind::Other, "oh no!"));
        //let f = f.map_err(|e| error!("{:?}", e));
        await!(f).unwrap();
    }

    unreachable!();

    Ok(())
}

#[async]
/// Program entry point for 'wg-p2p daemon'
pub fn daemon(handle: Handle, cfg_path: String) -> Result<()> {
    let cfg = Ini::read_from(&mut File::open(cfg_path)?)?;
    let sections = cfg.into_iter().filter_map(|(n, peers)| n.map(|n| (n, peers)));

    for (iface, peers) in sections {
        let mappings = Rc::new(RefCell::new(HashMap::new()));
        let inet2wg = Rc::new(RefCell::new(HashMap::new()));
        let stun_running = Rc::new(RefCell::new(false));

        let (outbound_sender, outbound_receiver) = futures::unsync::mpsc::channel(1024);
        let (inet2stun_sink, inet2stun_stream) = futures::unsync::mpsc::channel(1024);
        let (stun2inet_sink, stun2inet_stream) = futures::unsync::mpsc::channel(1024);

        let iface = iface.to_string();
        let cfg = await!(WireguardCommand::interface(handle.clone(), iface.clone()))?;
        let secret_key = cfg.secret_key()?;
        let wg_port = cfg.listen_port()?;
        let listen_port = wg_port + 1; // TODO

        let bind_addr = (Ipv6Addr::unspecified(), listen_port).into();
        let udp_public = UdpSocket::bind(&bind_addr, &handle)?;
        let (public_sink, public_stream) = udp_public.framed(RawCodec).split();
        let public_stream = public_stream.inspect(|&(src, ref msg)| debug!("Received {} inbound bytes from {}.", msg.len(), src));

        handle.spawn(report!(dispatch_outbound(public_sink, outbound_receiver)));

        let f = dispatch_inbound(handle.clone(), public_stream, outbound_sender.clone(),
            inet2stun_sink, inet2wg.clone(), mappings.clone(), stun_running.clone(), wg_port);
        handle.spawn(report!(f));

        handle.spawn(report!(publish_credentials(handle.clone(),
            stun2inet_sink, inet2stun_stream, stun_running, secret_key.clone(), peers.clone())));

        for (_, peer_key) in peers {
            handle.spawn(report!(lookup_credentials(handle.clone(), outbound_sender.clone(),
                iface.clone(), secret_key.clone(), peer_key, inet2wg.clone(), mappings.clone())));
        }

        let outbound_sender = outbound_sender.sink_map_err(|_| ());
        handle.spawn(stun2inet_stream.forward(outbound_sender).map(|(_s,_t)| {
            println!("stun2inet_stream.forward(outbound_sender) done");
        }));
    }

    await!(future::empty())
}

fn str2key(peer_key: &str) -> Result<PublicKey> {
    let peer_key = base64::decode(&peer_key)?;
    PublicKey::from_slice(&peer_key).ok_or("Invalid Peer".into())
}
