#![feature(pin)]
#![feature(await_macro, async_await, futures_api)]
#![feature(try_blocks)]
#![feature(custom_attribute)]

#[macro_use] extern crate tokio;
extern crate futures;
extern crate bytes;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate base64;
extern crate sodiumoxide;
#[macro_use] extern crate clap;

extern crate stun3489;
extern crate opendht;

macro_rules! log_err {
    ($expr: expr) => ({
        log_err!($expr, "{:?}")
    });
    ($expr: expr, $msg: expr) => ({
        if let Err(err) = $expr {
            error!($msg, err);
        }
    });
}

use std::io::Error;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use tokio::prelude::*;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::PublicKey;
use sodiumoxide::crypto::box_::SecretKey;

mod wg;
mod dht;
mod args;
mod stun;
mod utils;
mod crypto;
mod traffic;
mod dht_encoding;

use crate::utils::CloneSink;
use crate::utils::CloneStream;
use crate::utils::tokio_try_async;

fn inject<T>(mut stream: impl Stream<Item=T, Error=impl std::fmt::Debug + Send> + std::marker::Unpin + Send + 'static)
    -> (impl Sink<SinkItem=T, SinkError=impl std::fmt::Debug> + Clone, impl Stream<Item=T, Error=impl std::fmt::Debug>)
    where T: Send + 'static
{
    let (tx, rx) = futures::sync::mpsc::unbounded();
    let mut ttx = tx.clone();
    tokio::spawn_async(async move {
        while let Some(res) = await!(stream.next()) {
            match res {
                Ok(data) => { await!(ttx.send_async(data)).unwrap(); },
                Err(err) => warn!("{:?}", err),
            }
        }
    });

    (tx, rx)
}

fn main() -> Result<(), Error> {
    let args = crate::args::CmdArgs::parse();
    
    if args.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    } else {
        log::set_max_level(log::LevelFilter::Info);
    }

    env_logger::init();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let stun_server = args.stun_server.clone();

    let dht_port = args.dht_port;
    let bootstrap_addrs: Vec<_> = args.bootstrap_addrs.to_socket_addrs()?.collect();

    tokio_try_async(async move {
        let dht = await!(dht::Dht::new(&bootstrap_addrs, dht_port))?;

        let family = await!(crate::wg::Interface::get_family("wireguard"))?;
        let family = family.unwrap_or_else(|| panic!("Wireguard kernel module not loaded"));

        let mut all_ifaces = await!(crate::wg::Interface::get_wg_interfaces(args.default_netns.clone()))?;

        let ifaces: Vec<_> = if let Some(ifargs) = args.interfaces {
            let ifaces: Vec<_> = ifargs.iter().map(|iface| {
                let (j, _) = all_ifaces.iter().enumerate().filter(|(_k, i)| i.ifname == iface.ifname)
                    .next().unwrap_or_else(|| panic!("network interface {} unknown", iface.ifname));
                all_ifaces.remove(j)
            }).collect();
            ifaces.into_iter().zip(ifargs.into_iter()).collect()
        } else {
            let ifargs: Vec<_> = all_ifaces.iter().map(|iface| {
                crate::args::InterfaceArgs {
                    ifname: iface.ifname.clone(),
                    netns: args.default_netns.clone(),
                    peers: None,
                }
            }).collect();
            all_ifaces.into_iter().zip(ifargs.into_iter()).collect()
        };

        let mut pairs: Vec<(_, Vec<_>)> = vec![];
        for (iface, args) in ifaces {
            // this has to run first in the tokio loop, because it switches the
            // network namespace back and forth
            let mut wg_iface = crate::wg::Interface::new(family, args.netns.clone(), iface.ifindex)?;
            let wg_cfg = await!(wg_iface.get_config())?;

            let peer_list = if let Some(ref peer_list) = args.peers {
                peer_list.iter().map(|s| {
                    let p = PublicKey::from_slice(&s).unwrap();
                    let wg_iface = crate::wg::Interface::new(family, args.netns.clone(), iface.ifindex).unwrap();
                    (wg_iface, p)
                }).collect()
            } else {
                wg_cfg.peers().map(|s| {
                    let p = PublicKey::from_slice(s.public_key()).unwrap();
                    let wg_iface = crate::wg::Interface::new(family, args.netns.clone(), iface.ifindex).unwrap();
                    (wg_iface, p)
                }).collect()
            };

            pairs.push((wg_cfg, peer_list));
        };

        for (wg_cfg, peer_list) in pairs.into_iter() {
            let sock = tokio::net::UdpSocket::bind(&addr)?;
            let codec = tokio::codec::BytesCodec::new();
            let (udp_tx, udp_rx) = tokio::net::UdpFramed::new(sock, codec).split();

            let (inet2stun_tx,     inet2stun_rx)         = futures::sync::mpsc::unbounded();
            let (public_addr_tx,   mut public_addr_rx)   = futures::sync::mpsc::unbounded();
            let (new_endpoints_tx, mut new_endpoints_rx) = futures::sync::mpsc::unbounded();

            let (dht2wg_tx, udp_rx) = inject(udp_rx);
            let (udp_tx, stun2inet_tx) = udp_tx.clone_sink();

            let secret_key = wg_cfg.private_key();
            let secret_key = SecretKey::from_slice(secret_key).unwrap();
            let local_public_key = secret_key.public_key();

            let wg_port = wg_cfg.listen_port();
            debug!("Wireguard Port {}", wg_port);

            tokio::spawn_async(traffic::forward_inbound(new_endpoints_tx, udp_rx, inet2stun_tx, udp_tx, wg_port));
            tokio::spawn_async(stun::run(inet2stun_rx, stun2inet_tx, bind_addr, stun_server.clone(), public_addr_tx));

            for (wg_iface, remote_public_key) in peer_list.into_iter() {
                info!("Managing peer {} on interface #{}.", base64::encode(&remote_public_key[..]), wg_iface.ifindex);

                let (dht_address_tx, dht_address_rx) = futures::sync::mpsc::unbounded();

                let (public_addr_rrx, rx) = public_addr_rx.clone_stream();
                public_addr_rx = rx;

                let (rx, new_endpoints_rrx) = new_endpoints_rx.clone_stream();
                new_endpoints_rx = rx;
                
                let shared_key = box_::precompute(&remote_public_key, &secret_key);
                let dht_put_key = dht_encoding::encode_public_keys(&local_public_key, &remote_public_key);
                let dht_get_key = dht_encoding::encode_public_keys(&remote_public_key, &local_public_key);

                tokio::spawn_async(traffic::set_endpoint(wg_iface, remote_public_key, new_endpoints_rrx, dht_address_rx));

                let dht2 = dht.clone();
                let shared_key2 = shared_key.clone();
                tokio::spawn_async(async move {
                    await!(dht2.put_addr_loop(shared_key2, dht_put_key, public_addr_rrx))
                });

                let dht2 = dht.clone();
                let dht2wg_ttx = dht2wg_tx.clone();
                tokio::spawn_async(async move {
                    await!(dht2.get_addr_loop(shared_key, dht_get_key, dht_address_tx, dht2wg_ttx));
                });
            }

            tokio::spawn_async(async move {
                while let Some(_) = await!(new_endpoints_rx.next()) {
                    // noop
                }
            });

            tokio::spawn_async(async move {
                while let Some(_) = await!(public_addr_rx.next()) {
                    // noop
                }
            });
        }

        Ok(()) as Result<(), std::io::Error>
    });

    Ok(())
}
