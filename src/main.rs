#![feature(pin)]
#![feature(await_macro, async_await, futures_api)]
#![feature(try_blocks)]

#[macro_use] extern crate tokio;
extern crate futures;
extern crate tokio_process;
extern crate bytes;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate base64;

extern crate stun3489;
extern crate opendht;

use std::io::Error;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;

use tokio::prelude::*;

mod wg;
mod dht;
mod stun;
mod traffic;
mod dht_encoding;

fn main() -> Result<(), Error> {
    env_logger::init();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let sock = tokio::net::UdpSocket::bind(&addr)?;
    let codec = tokio::codec::BytesCodec::new();
    let (inet_send, inet_recv) = tokio::net::UdpFramed::new(sock, codec).split();

    let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
    let stun_server = "stun.wtfismyip.com:3478".to_string();

    let wg_port = 0xDEAD;
    let wg_iface = "shift4".to_string();

    let public_addr = Arc::new(Mutex::new(None)); // TODO: use stream instead of mutex
    let local_public_key = vec![];
    let remote_public_key = vec![];

    debug!("Wireguard Port {}", wg_port);

    tokio::run_async(async move {
        let (inet_tx, inet_rx) = futures::sync::mpsc::unbounded();
        let (inet2stun_tx, inet2stun_rx) = futures::sync::mpsc::unbounded();
        let stun2inet_tx = inet_tx.clone();

        tokio::spawn_async(traffic::forward_outbound(inet_rx, inet_send));

        tokio::spawn_async(traffic::forward_inbound(inet_recv, inet2stun_tx, inet_tx, wg_port));

        tokio::spawn_async(dht::run(public_addr.clone(), local_public_key.clone(), remote_public_key.clone(), wg_iface));

        tokio::spawn_async(stun::run(inet2stun_rx, stun2inet_tx, bind_addr, stun_server, public_addr));
    });

    Ok(())
}
