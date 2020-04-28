use std::io;
use std::io::Write;
use std::time::Duration;
use std::time::SystemTime;
use std::collections::HashMap;
use std::net::{Ipv4Addr, IpAddr};
use std::net::SocketAddr;

use log::{error, warn, info, debug};
use clap::App;
use rand::Rng;
use rand::SeedableRng;
use bytes::Bytes;
use env_logger::Builder;
use log::LevelFilter;

use async_std::sync;
use async_std::sync::Sender;
use async_std::task;
use async_std::net::UdpSocket;
use async_std::sync::Arc;
use async_std::net::ToSocketAddrs;
use async_std::prelude::FutureExt;
use futures::future;
use futures::stream::StreamExt;
use futures::stream::TryStreamExt;
use futures::channel::mpsc;
use futures::channel::oneshot;

use opendht::OpenDht;
use opendht::InfoHash as DhtHash;
use stun3489::Stun3489;
use stun3489::codec::StunCodec;

//mod wg;
mod utils;
mod crypto;
mod serialize;

use wireguard_tools_rs::Device as WgDevice;
use serialize::serialize;
use serialize::deserialize;
use crypto::PublicKey;
use crypto::PrecomputedKey;
use crypto::encrypt;
use crypto::decrypt;
use utils::OrTryInsertWithAsync;
use utils::AsBase64;
use utils::SendErrorAsIoError;
use utils::UdpSocketToStream;
use utils::UdpSocketSplit;

use ansi_term::Colour;

async fn create_new_lo_socket(inet_tx: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
                              wg_peer: SocketAddr,
                              inet_peer: SocketAddr)
                              -> io::Result<Arc<UdpSocket>>
{
    let port = inet_peer.port();
    let mut try_ports = vec![port,
                             port.saturating_add(10000),
                             port.saturating_add(20000),
                             port.saturating_add(30000),
                             port.saturating_add(40000),
                             port.saturating_add(50000),
                             port.rotate_left(8)].into_iter();

    let lo_sock = loop {
        let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let port: u16 = try_ports.next().unwrap_or(0);

        let sock = UdpSocket::bind((ip, port)).await;
        if let Err(ref e) = sock {
            if e.kind() == io::ErrorKind::AddrInUse {
                continue
            }
        }
        break sock?
    };
    lo_sock.connect(wg_peer).await?;

    let lo_sock = Arc::new(lo_sock);
    let lo_sock2 = lo_sock.clone();

    let inet_tx = inet_tx.map_err_as_io();
    let f = lo_sock2.into_stream()
        .map_ok(move |(buf, _)| (buf, inet_peer.clone()))
        .forward(inet_tx);
    task::spawn(f);

    Ok(lo_sock)
}

async fn lookup_peers(dht: Arc<OpenDht>,
                      wg: Arc<WgDevice>,
                      new_dht_peer_tx: Sender<(SocketAddr, oneshot::Sender<SocketAddr>)>,
                      remote_peer_keys: Vec<(PublicKey, DhtHash, DhtHash, PrecomputedKey)>,
    ) {
    // TODO: StreamExt::throttle()

    for (pubkey, _publish_dht_key, lookup_key, key) in remote_peer_keys {
        let wg = wg.clone();
        let tx = new_dht_peer_tx.clone();

        let rx = dht.listen(lookup_key);
        let mut rx = rx.filter_map(move |value| future::ready(decrypt(&key, value).ok().and_then(deserialize)));

        task::spawn(async move {
            let mut max_time = SystemTime::UNIX_EPOCH;
            while let Some((time, peer_addr)) = rx.next().await {
                debug!("DHT found a value: {}", peer_addr);

                if time > max_time {
                    max_time = time;

                    let (ttx, rrx) = oneshot::channel();
                    tx.send((peer_addr, ttx)).await;
                    let lo_addr = rrx.await.expect("We did not get an answer");

                    if let Some(mut wg_peer) = wg.get_peer(&pubkey) {
                        wg_peer.set_endpoint(&lo_addr);
                        if let Err(e) = wg.apply() {
                            error!("Error while setting endpoint {} to {} ({}): {}",
                                     pubkey.as_b64(), lo_addr, peer_addr, e);
                        }

                        info!("Set endpoint {} to {} ({})", pubkey.as_b64(), lo_addr, peer_addr);
                    } else {
                        error!("Endpoint {} vanished.", pubkey.as_b64());
                        break
                    }
                }
            };
        });
    }
}

async fn publish_peers(stun_server: SocketAddr,
                       inet_tx: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
                       inet_rx: mpsc::UnboundedReceiver<(Bytes, SocketAddr)>,
                       wg: Arc<WgDevice>,
                       remote_peer_keys: Vec<(PublicKey, DhtHash, DhtHash, PrecomputedKey)>,
                       dht: Arc<OpenDht>) {
    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

    let inet_tx = inet_tx.map_err_as_io();
    let inet_tx = StunCodec::encode_sink(inet_tx);
    let inet_rx = StunCodec::decode_stream(inet_rx);

    let mut stun = Stun3489::new(inet_tx, inet_rx);
    let mut connectivity;

    loop {
        connectivity = stun.check(bind_addr, stun_server).await;
        dbg!(&connectivity);

        let connectivity = connectivity.unwrap();
        for (_, publish_dht_key, _lookup_key, key) in remote_peer_keys.iter() {
            let value = serialize(connectivity.into());
            let value = encrypt(&key, value);

            if let Err(e) = dht.put(publish_dht_key.clone(), &value).await {
                error!("Failed to put our public address to dht: {}", e);
            }
        }

        loop {
            let wait = wg.next_handshake().unwrap_or(Duration::from_secs(15));

            // TODO: drain inet_rx while delaying
            futures::future::ready(()).delay(wait).await;

            match wg.next_handshake() {
                None => break,
                Some(hs) if hs <= Duration::from_secs(0) => break,
                _ => (),
            }
        }
    }
}

async fn handle_device(stun_server: SocketAddr,
                       inet_sock: UdpSocket,
                       dht: Arc<OpenDht>,
                       wg: WgDevice,
                       wg_listen_port: u16,
                       remote_peer_keys: Vec<(PublicKey, DhtHash, DhtHash, PrecomputedKey)>,
        ) -> io::Result<()> {
    let mut map = HashMap::new();

    let (inet_tx, (mut inet_rx1, inet_rx2)) = inet_sock.split();
    let (new_dht_peer_tx, new_dht_peer_rx) = sync::channel(1024);

    let wg_peer = (Ipv4Addr::LOCALHOST, wg_listen_port).into();
    let wg = Arc::new(wg);

    task::spawn(lookup_peers(dht.clone(), wg.clone(), new_dht_peer_tx, remote_peer_keys.clone()));
    task::spawn(publish_peers(stun_server, inet_tx.clone(), inet_rx2, wg, remote_peer_keys, dht.clone()));

    enum Either<A, B> {
        InetPacket(A),
        NewDhtPeer(B),
    }

    loop {
        let f1 = async { Either::NewDhtPeer(new_dht_peer_rx.recv().await) };
        let f2 = async { Either::InetPacket(inet_rx1.next().await) };

        match f1.race(f2).await { // TODO: order?
            Either::NewDhtPeer(None) => {
                warn!("No peer in list?");
                break Ok(());
            }
            Either::InetPacket(None) => {
                panic!("inet closed");
            }
            Either::NewDhtPeer(Some((inet_peer, tx))) => {
                let create = create_new_lo_socket(inet_tx.clone(), wg_peer, inet_peer);
                let lo_sock = map.entry(inet_peer).or_try_insert_with_async(create).await?;

                if tx.send(lo_sock.local_addr()?).is_err() {
                    error!("{} Send new lo addr failed: receiver dropped.", Colour::Red.paint("HDL"));
                }
            }
            Either::InetPacket(Some((buf, inet_peer))) => {
                //debug!("{} received {} bytes from {}", Colour::White.dimmed().paint("HDL"), buf.len(), inet_peer);
                let create = create_new_lo_socket(inet_tx.clone(), wg_peer, inet_peer);
                let res = map.entry(inet_peer).or_try_insert_with_async(create).await;
                match res {
                    Err(e) => error!("{} Failed to open lo socket for {}: {}. Dropping {} bytes.", Colour::Red.paint("HDL"), wg_peer, e, buf.len()),
                    Ok(lo_sock) => {
                        let _sent = lo_sock.send_to(&buf, &wg_peer).await?;
                        //debug!("Sent {} out of {} bytes to {}", sent, buf.len(), wg_peer);
                    }
                }
            }
        }
    }
}

async fn bind_inet_socket(seed: &PublicKey) -> io::Result<UdpSocket> {
    let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let mut rnd = rand::rngs::StdRng::from_seed(seed.0);

    let inet_sock = loop {
        let port: u16 = rnd.gen();

        let sock = UdpSocket::bind((ip, port)).await;
        if let Err(ref e) = sock {
            if e.kind() == io::ErrorKind::AddrInUse {
                continue
            }
        }
        break sock?
    };

    info!("Listening on {}", inet_sock.local_addr()?);

    Ok(inet_sock)
}

#[async_std::main]
async fn main() -> io::Result<()> {
    sudo::escalate_if_needed().map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to become root {}", e)))?;

    let matches = App::new("wireguard-p2p")
        .version("0.2")
        .author("Manuel Schölling <manuel.schoelling@posteo.de>")
        .arg(clap::Arg::with_name("interface")
            .short("i")
            .value_name("INTERFACE")
            .help("The interface to handle by wg-p2p")
            .takes_value(true)
            .required(true))
        .arg(clap::Arg::with_name("dht-node")
            .long("dht-node")
            .value_name("DHT_NODE")
            .help("OpenDHT bootstrapping node address")
            .takes_value(true)
            .default_value("bootstrap.ring.cx:4222"))
        .arg(clap::Arg::with_name("stun-server")
            .long("stun-server")
            .value_name("STUN_SERVER")
            .help("STUN3489 server to receive the public IP and port from")
            .takes_value(true)
            .default_value("stun.wtfismyip.com:3478"))
        .arg(clap::Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .get_matches();

    Builder::new()
        .format(|buf, record| {
            writeln!(buf,
                     "[{}] {}",
                     record.level(),
                     record.args()
            )
        })
        .filter(None, if matches.occurrences_of("v") == 0 {
            LevelFilter::Info
        } else {
            LevelFilter::Debug
        })
        .init();

    sodiumoxide::init().or_else(|_| Err(io::Error::new(io::ErrorKind::Other, "Failed to initialize sodiumoxide")))?;

    let addrs: Vec<_> = matches.value_of("dht-node").unwrap_or("").to_socket_addrs().await?.collect();
    let dht = OpenDht::new(4222).expect("Failed to initialize OpenDht");
    let dht = Arc::new(dht);
    dht.bootstrap(&addrs).await.expect("failed to bootstrap DHT");

    let ifname = matches.value_of("interface").unwrap_or("").to_string();
    let wg = WgDevice::get(&ifname[..])?;
    let err = || io::Error::new(io::ErrorKind::InvalidData, "Wireguard device has no listen port");
    let wg_listen_port = wg.listen_port().ok_or_else(err)?;
    dbg!(&wg);

    let dht2 = dht.clone();
    task::spawn(async move {
        while let Some(next) = dht2.tick() {
            async_std::future::ready(()).delay(next).await;
        }
    });

    let stun_server = matches.value_of("stun-server").unwrap_or("").to_string();
    let mut stun_server = stun_server.to_socket_addrs().await?;
    let stun_server = stun_server.next().ok_or_else(|| io::Error::from_raw_os_error(libc::EDESTADDRREQ))?;

    let secret_key = wg.secret_key();
    let secret_key = secret_key.expect(&format!("Device {} has no private key", &ifname));
    let our_pkey = secret_key.public_key();

    let remote_peer_keys = wg.peers().iter().filter_map(|p| {
        let remote_pkey = p.public_key()?;

        let publish_dht_key = [our_pkey.0, remote_pkey.0].concat();
        let publish_dht_key  = DhtHash::new(publish_dht_key);
        let lookup_dht_key = [remote_pkey.0, our_pkey.0].concat();
        let lookup_dht_key  = DhtHash::new(lookup_dht_key);

        let key = crypto::precompute(&remote_pkey, &secret_key);
        Some((remote_pkey, publish_dht_key, lookup_dht_key, key))
    }).collect();

    let seed = our_pkey;
    let inet_sock = bind_inet_socket(&seed).await?;

    handle_device(stun_server, inet_sock, dht, wg, wg_listen_port, remote_peer_keys).await
}
