#![allow(unreachable_code)]
#![allow(unused_variables)]

mod api;
mod fake;
mod utils;
mod message;
mod wg_device;
mod crypto;
mod stun;
mod config;
mod dht;

use std::sync::Arc;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::time::Duration;
use std::time::SystemTime;

use async_std::sync::RwLock;
use async_std::sync::Mutex;
use async_std::sync::Condvar;
use async_std::net::UdpSocket;
use async_std::net::ToSocketAddrs;
use anyhow::{bail, anyhow, Context};

use slog::Drain;
use slog::{debug, info, error, crit};

use api::*;
use utils::*;
use crypto::*;
use dht::OpenDht;
use message::Message;
use utils::{UdpSender, UdpReceiver};
use config::Config;
use futures::stream::StreamExt;

type RwConnectionsMap = RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>;

/// Creates a new local socket and forwards all incoming data (outbound wireguard traffic) to the internet
/// The returned local socket can be used to forward inbound wireguard traffic from this peer_addr
/// to the wireguard interface at wg_lo_port (typically done in forward_incoming_traffic() via the connections map)
///
/// public_socket: public internet socket
async fn new_local_socket(parent_log: &slog::Logger,
                          to_inet_tx: UdpSender,
                          remote_peer_addr: SocketAddr) -> anyhow::Result<Arc<UdpSocket>> {
    info!(parent_log, "Setting up new local address"; slog::o!("remote_addr" => remote_peer_addr));
    let lo_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let lo_socket = Arc::new(lo_socket);

    let lo_sock = lo_socket.clone();
    let local_addr = lo_socket.local_addr()?;
    let mut buf = vec![0u8; 64 * 1024];

    let log_out = parent_log.new(slog::o!("direction" => "outbound"));
    let handle = spawn(async move {
        // forward data from local socket (outbound wireguard) to the internet
        loop {
            let (n, lo_peer_addr) = lo_sock.recv_from(&mut buf).await?;
            debug!(log_out, "Forwarding outbound packet..."; slog::o!("src" => lo_peer_addr, "via_lo" => local_addr, "dst" => remote_peer_addr, "bytes" => n));
            // lo_peer_addr must be wireguard on localhost
            to_inet_tx.send((buf[..n].to_vec(), remote_peer_addr)).await?;
            debug!(log_out, "Outbound packet forwarded"; slog::o!("src" => lo_peer_addr, "via_lo" => local_addr, "dst" => remote_peer_addr, "bytes" => n));
        }
        Ok(())
    });

    Ok(lo_socket)
}

async fn dht_get<W: WireguardDevice + ?Sized + 'static>(log_get: slog::Logger,
                     dht: OpenDht,
                     wg_dev: Arc<Box<W>>,
                     remote_pkey: PublicKey,
                     to_inet_tx: UdpSender,
                     connections: Arc<RwConnectionsMap>) -> anyhow::Result<()> {
    let secret_key = wg_dev.get_secret_key().await?;
    let secret_key = secret_key.ok_or(anyhow!("Wireguard device {:?} has no secret key!", wg_dev.get_name().await))?;
    let local_pkey = secret_key.public_key();
    let crypto = Sodiumoxide::new(&remote_pkey, &secret_key);

    let key = [remote_pkey.0.0, local_pkey.0.0].concat();
    debug!(log_get, "Waiting for remote peer to publish IP in DHT..."; slog::o!("dht_key" => base64::encode(&key)));

        // TODO: if not found within X seconds, repeat

    let mut last_timestamp: Option<SystemTime> = None;

    let listen = batches(dht.listen(key.clone()));
    futures::pin_mut!(listen);
    while let Some(batch) = listen.next().await {
        // TODO: need secret key for PublicKeyCrypto
        let batch: Vec<_> = batch.collect();
        dbg!(batch.len());
        let batch = batch.into_iter();

        let batch = batch.map(|value| crypto.decrypt(&value[..]))
                         .filter_map(|value| {if value.is_none() { debug!(log_get, "Decryption failed") }; value });

        let batch: Vec<_> = batch.collect();
        dbg!(batch.len());
        let batch = batch.into_iter();

        let batch = batch.map(|value| serde_json::from_slice::<Message>(&value[..]))
                         .filter_map(|value| {if value.is_err() { info!(log_get, "Deserialization failed") }; value.ok() });
        let batch: Vec<_> = batch.collect();
        dbg!(batch.len());
        let batch = batch.into_iter();

        let msg = batch.max_by_key(|m| m.timestamp);

        dbg!(&msg);

        let a = msg.as_ref().and_then(|m| m.timestamp.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).ok());
        let b = last_timestamp.as_ref().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).ok());
        debug!(log_get, "msg_ts < last_ts?"; slog::o!("msg_ts" => a, "last_ts" => b));
        if msg.as_ref().map(|m| m.timestamp) < last_timestamp {
            debug!(log_get, "skipping"; slog::o!("msg_ts" => a, "last_ts" => b));
            continue
        }
        last_timestamp = msg.as_ref().map(|m| m.timestamp);
        let ip_addr_list = msg.map(|m| m.ip_addr_list).unwrap_or(vec![]);

        for remote_peer_addr in ip_addr_list {
            // TODO: check remote_peer_addr ip type
            info!(log_get, "Found new remote peer address"; slog::o!("addr" => remote_peer_addr, "dht_key" => base64::encode(&key)));

            let mut write_map = connections.write().await;

            let insertion = new_local_socket(&log_get, to_inet_tx.clone(), remote_peer_addr);
            let local_peer_addr = match write_map.entry(remote_peer_addr) {
                Entry::Vacant(vacant) => vacant.try_insert_with_async(insertion).await?.local_addr()?,
                Entry::Occupied(value) => value.get().local_addr()?,
            };

            wg_dev.set_endpoint(&remote_pkey, &local_peer_addr).await?;
            debug!(log_get, "Wireguard endpoint set"; slog::o!("fwd_addr" => local_peer_addr, "remote_addr" => remote_peer_addr));
            // TODO: sleep for a short time
        }
        debug!(log_get, "Waiting for remote peer to publish a new IP in DHT..."; slog::o!("dht_key" => base64::encode(&key)));
    }

    Ok(())
}

async fn dht_put<W: WireguardDevice + ?Sized + 'static>(log_put: slog::Logger,
                 dht: OpenDht,
                 wg_dev: Arc<Box<W>>,
                 remote_pkey: PublicKey,
                 public_address: Arc<(Mutex<stun::Connectivity>, Condvar)>) -> anyhow::Result<()> {
    let (lock, cvar) = &*public_address;

    let secret_key = wg_dev.get_secret_key().await?;
    let secret_key = secret_key.ok_or(anyhow!("Wireguard device {:?} has no secret key!", wg_dev.get_name().await))?;
    let local_pkey = secret_key.public_key();
    let crypto = Sodiumoxide::new(&remote_pkey, &secret_key);

    let mut guard = cvar.wait_until(lock.lock().await, |addr| {
        let addr = Into::<Option<SocketAddr>>::into(*addr);
        addr.map(|a| !a.ip().is_unspecified()).unwrap_or(false)
    }).await;

    loop {
        let public_addr: Option<SocketAddr> = (*guard).into();
        debug!(log_put, "Got myown a new public address"; slog::o!("addr" => format!("{:?}", public_addr)));
        drop(guard);

        let msg = Message {
            timestamp: std::time::SystemTime::now(),
            ip_addr_list: public_addr.map(|a| vec![a]).unwrap_or(vec![]),
        };

        let value = serde_json::to_vec(&msg)?;
        let value = crypto.encrypt(&value[..])?;
        let key = if let Some(local_pkey) = wg_dev.get_public_key().await? {
            [local_pkey.0.0, remote_pkey.0.0].concat()
        } else {
            bail!("Wireguard device {:?} has no public key!", wg_dev.get_name().await);
        };


        let res = dht.put(&key[..], &value[..]).await;
        info!(log_put, "Published own public address on DHT"; slog::o!("dht_key" => base64::encode(key), "addr" => public_addr));

        let (g, res) = cvar.wait_timeout(lock.lock().await, Duration::from_secs(60)).await;
        guard = g;

        if res.timed_out() {
            debug!(log_put, "Republishing old address..."; slog::o!("addr" => public_addr));
        }
    }
    Ok(())
}

async fn forward_inbound_traffic(log_fwd: slog::Logger,
                                 to_inet_tx: UdpSender,
                                 mut from_inet_rx: UdpReceiver,
                                 connections: Arc<RwConnectionsMap>, wg_lo_port: u16) -> anyhow::Result<()> {
    let wg_lo_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), wg_lo_port);

    while let Some((buf, remote_peer_addr)) = from_inet_rx.next().await {
        debug!(log_fwd, "Received inbound packet"; slog::o!("src" => remote_peer_addr, "dst" => wg_lo_addr, "bytes" => buf.len()));

        // TODO: if remote_peer_addr is the same as in previous iteration, just cache lo_socket

        let lo_socket = {
            let read_map = connections.read().await;
            if let Some(lo_sock) = read_map.get(&remote_peer_addr) {
                lo_sock.clone()
            } else {
                drop(read_map);
                let mut write_map = connections.write().await;
                let insertion = new_local_socket(&log_fwd, to_inet_tx.clone(), remote_peer_addr);
                write_map.entry(remote_peer_addr).or_try_insert_with_async(insertion).await?.clone()
            }
        };

        lo_socket.send_to(&buf, &wg_lo_addr).await?;
        debug!(log_fwd, "Forwarded inbound packet"; slog::o!("remote_addr" => remote_peer_addr, "bytes" => buf.len(), "wg_addr" => wg_lo_addr));
    }

    Ok(())
}

async fn lookup_public_address(log: slog::Logger,
                               stun_server: SocketAddr,
                               mut to_inet_tx: UdpSender,
                               mut from_inet_rx: UdpReceiver,
                               public_address: Arc<(Mutex<stun::Connectivity>, Condvar)>) -> anyhow::Result<()> {
    let stun = stun::Stun;
    loop {
        match stun.lookup_public_address(&log, &mut to_inet_tx, &mut from_inet_rx, stun_server).await {
            Ok(new_address) => {
                let addr: Option<SocketAddr> = new_address.into();
                debug!(log, "STUN succeeded"; slog::o!("addr" => addr));
                let old_address = *public_address.0.lock().await;
                if new_address != old_address {
                    info!(log, "STUN found new address"; slog::o!("addr" => addr));
                    let mut lock = public_address.0.lock().await;
                    *lock = new_address;
                    public_address.1.notify_all();
                    debug!(log, "STUN all tasks notified"; slog::o!("addr" => addr));
                }
                async_std::task::sleep(Duration::from_secs(60)).await;
            }
            Err(err) => {
                error!(log, "STUN failed"; slog::o!("error" => format!("{:?}", err)));
                async_std::task::sleep(Duration::from_secs(15)).await;
            }
        }
    }
}

async fn handle_device(log_dev: slog::Logger,
                       dht: OpenDht,
                       cfg: Arc<DeviceConfig>, wg_dev: Box<dyn WireguardDevice>) -> anyhow::Result<()> {
    let wg_lo_port = wg_dev.get_listen_port().await?;
    debug!(log_dev, "Wireguard device port found"; "port" => wg_lo_port);

    let connections: Arc<RwConnectionsMap>;
    connections = Arc::new(RwLock::new(HashMap::new()));

    let public_socket = UdpSocket::bind("[::]:0").await?;
    info!(log_dev, "Listening on public address"; "address" => public_socket.local_addr()?);

    let (to_inet_tx, from_inet_rx) = split_udp_socket(public_socket);
    let (from_inet_rx1, from_inet_rx2) = cloned_rx(from_inet_rx);

    let log_fwd = log_dev.new(slog::o!("traffic" => "inbound"));
    spawn(forward_inbound_traffic(log_fwd, to_inet_tx.clone(), from_inet_rx1, connections.clone(), wg_lo_port));

    let log_stun = log_dev.new(slog::o!("traffic" => "stun"));
    // TODO: resolve ip later
    let stun_server = "stun.wtfismyip.com:3478".to_socket_addrs().await?.next().unwrap();
    let public_address = Arc::new((Mutex::new(stun::Connectivity::SymmetricNat), Condvar::new()));
    spawn(lookup_public_address(log_stun, stun_server, to_inet_tx.clone(), from_inet_rx2, public_address.clone()));

    // TODO: drop last public_socket
//    todo!();

    let mut peers = cfg.get_peers(wg_dev.as_ref()).await?;
    let wg_dev = Arc::new(wg_dev);

    while let Some(peer) = peers.next().await {
        let remote_pkey = peer.get_public_key();

        let log_peer = log_dev.new(slog::o!("peer" => format!("{:}", remote_pkey)));
        let log_put = log_peer.new(slog::o!("dht" => "put"));
        let log_get = log_peer.new(slog::o!("dht" => "get"));

        spawn(dht_put(log_put, dht.clone(), wg_dev.clone(), remote_pkey.clone(), public_address.clone().into()));
        spawn(dht_get(log_get, dht.clone(), wg_dev.clone(), remote_pkey, to_inet_tx.clone(), connections.clone()));
    }

    Ok(())
}

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    if let Err(()) = sodiumoxide::init() {
        bail!("Initializing sodiumoxide failed");
    }

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!());

    let cfg = Arc::new(Config::new(log.clone())?);

    // [x] stun
    // [ ] cli
    // [ ] config
    // [ ] dynamic config

    let mut stream = cfg.get_wireguard_devices()?;

    // TODO: use another port or the same opendht instance for all wg devices
    let dht_log = log.new(slog::o!("task" => "dht"));
    let dht = OpenDht::new(dht_log, cfg.opendht_port, "bootstrap.ring.cx:4222").await.context("Initializing DHT failed")?;

    let mut futures = vec![];
    while let Some((wg_dev, dev_cfg)) = stream.next().await {
        debug!(log, "Getting device name...");
        let dev_name = wg_dev.get_name().await?;
        let log_dev = log.new(slog::o!("dev" => dev_name.to_string()));
        debug!(log_dev, "Handling device");
        futures.push(handle_device(log_dev, dht.clone(), Arc::new(dev_cfg), wg_dev));
    }

    let results = futures::future::join_all(futures).await;
    if results.len() == 0 {
        crit!(log, "No wireguard devices found!");
    } else {
        results.into_iter().collect::<anyhow::Result<()>>()?;
        async_std::future::pending::<()>().await;
    }

    Ok(())
}
