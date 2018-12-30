#![feature(pin)]
#![feature(await_macro, async_await, futures_api)]
#![feature(try_blocks)]
#![feature(custom_attribute)]

#[macro_use] extern crate tokio;
extern crate futures;
extern crate tokio_process;
extern crate bytes;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate base64;
extern crate structopt;
extern crate clap;
extern crate regex;
extern crate sodiumoxide;

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

use structopt::StructOpt;

mod wg;
mod dht;
mod stun;
mod utils;
mod crypto;
mod traffic;
mod dht_encoding;

use crate::utils::CloneSink;
use crate::utils::CloneStream;

#[derive(Debug, StructOpt)]
#[structopt(name = "wg-p2p", about = "A peer-to-peer daemon for wireguard.")]
struct CmdOpt {
    #[structopt(short = "v", long = "verbose")]
    verbose: bool,

    #[structopt(short = "n", long = "netns")]
    netns: Option<String>,

    #[structopt(short = "p", long = "peer")]
    peer: Option<String>,

    #[structopt(long = "stun", default_value = "stun.wtfismyip.com:3478")]
    stun_server: String,

    #[structopt(long = "dht-port", default_value = "4222")]
    dht_port: u16,

    #[structopt(long = "bootstrap", default_value = "bootstrap.ring.cx:4222")]
    bootstrap_addrs: String,
}

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
    let opt = CmdOpt::from_args();

    if opt.verbose {
        log::set_max_level(log::LevelFilter::Debug);
    } else {
        log::set_max_level(log::LevelFilter::Info);
    }

    env_logger::init();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let stun_server = opt.stun_server;

    let netns = opt.netns;
    let dht_port = opt.dht_port;
    let bootstrap_addrs: Vec<_> = opt.bootstrap_addrs.to_socket_addrs().unwrap().collect();

    tokio::run_async(async move {
        let family = await!(crate::wg::Interface::get_family("wireguard")).unwrap();
        let family = family.unwrap_or_else(|| panic!("Wireguard kernel module not loaded"));
        let ifaces = await!(crate::wg::Interface::get_wg_interfaces(netns.clone())).unwrap();

        let mut pairs = vec![];
        for i in ifaces {
            // this has to run first in the tokio loop, because it switches the
            // network namespace back and forth
            let mut wg_iface = crate::wg::Interface::new(family, netns.clone(), i.ifindex).unwrap();
            let wg_cfg = await!(wg_iface.get_config()).unwrap();

            let peer_list: Vec<_> = wg_cfg.peers().map(|p| {
                let wg_iface = crate::wg::Interface::new(family, netns.clone(), i.ifindex).unwrap();
                (wg_iface, *p.public_key())
            }).collect();

            pairs.push((wg_cfg, peer_list));
        }

        let dht = await!(dht::Dht::new(&bootstrap_addrs, dht_port));

        for (wg_cfg, peer_list) in pairs.into_iter() {
            let (public_addr_tx, mut public_addr_rx) = futures::sync::mpsc::unbounded();

            let sock = tokio::net::UdpSocket::bind(&addr).unwrap();
            let codec = tokio::codec::BytesCodec::new();
            let (udp_tx, udp_rx) = tokio::net::UdpFramed::new(sock, codec).split();

            let wg_port = wg_cfg.listen_port();
            debug!("Wireguard Port {}", wg_port);

            let (inet2stun_tx, inet2stun_rx) = futures::sync::mpsc::unbounded();
            let (udp_tx, stun2inet_tx) = udp_tx.clone_sink();

            let (new_endpoints_tx, mut new_endpoints_rx) = futures::sync::mpsc::unbounded();

            let (dht2wg_tx, udp_rx) = inject(udp_rx);
            tokio::spawn_async(traffic::forward_inbound(new_endpoints_tx, udp_rx, inet2stun_tx, udp_tx, wg_port));
            tokio::spawn_async(stun::run(inet2stun_rx, stun2inet_tx, bind_addr, stun_server.clone(), public_addr_tx));

            let local_secret_key = wg_cfg.private_key();
            let local_public_key = wg_cfg.public_key();

            for (wg_iface, remote_public_key) in peer_list.into_iter() {
                info!("Managing peer {} on interface #{}.", base64::encode(&remote_public_key[..]), wg_iface.ifindex);
                let secret_key = SecretKey::from_slice(&local_secret_key[..]).unwrap();
                let public_key = PublicKey::from_slice(&remote_public_key[..]).unwrap();
                let shared_key = box_::precompute(&public_key, &secret_key);

                let (public_addr_rrx, addr_rx) = public_addr_rx.clone_stream();
                public_addr_rx = addr_rx;

                let (rx, new_endpoints_rrx) = new_endpoints_rx.clone_stream();
                new_endpoints_rx = rx;
                
                let dht2 = dht.clone();
                let shared_key2 = shared_key.clone();
                let dht_key = dht_encoding::encode_key(&local_public_key[..], &remote_public_key[..]);
                tokio::spawn_async(async move {
                    await!(dht2.put_loop(shared_key2, dht_key, public_addr_rrx))
                });

                let (dht_address_tx, dht_address_rx) = futures::sync::mpsc::unbounded();

                tokio::spawn_async(async move {
                    await!(traffic::set_endpoint(wg_iface, remote_public_key, new_endpoints_rrx, dht_address_rx))
                });

                let dht2 = dht.clone();
                let dht2wg_ttx = dht2wg_tx.clone();
                let dht_key = dht_encoding::encode_key(&remote_public_key[..], &local_public_key[..]);
                tokio::spawn_async(async move {
                    await!(dht2.get_loop(shared_key, dht_key, dht_address_tx, dht2wg_ttx));
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
    });

    Ok(())
}
