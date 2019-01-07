use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::io;

use bytes::Bytes;
use bytes::BytesMut;
use tokio::prelude::*;
use tokio::prelude::stream::SplitSink;
use tokio::codec::BytesCodec;
use tokio::net::UdpFramed;
use futures::sync::mpsc::UnboundedSender;
use futures::sync::mpsc::UnboundedReceiver;
use futures::sync::mpsc;
use sodiumoxide::crypto::box_::PublicKey;

type UdpSink = SplitSink<UdpFramed<BytesCodec>>;

/// Create a new loopback socket for a new peer to forward packets between the
/// public socket and the loopback wireguard socket
fn create_internal_socket(remote_addr: SocketAddr,
    mut outbound: mpsc::UnboundedSender<(Bytes, SocketAddr)>)
    -> io::Result<(UdpSink, u16)>
{
    let loop_addr = SocketAddr::new([127, 0, 0, 1].into(), 0);
    let sock = tokio::net::UdpSocket::bind(&loop_addr)?;
    let port = sock.local_addr()?.port();

    let codec = BytesCodec::new();
    let (send, mut recv) = UdpFramed::new(sock, codec).split();

    // forward packets from the new loopback socket to the remote peer
    tokio::spawn_async(async move {
        while let Some(Ok((pkt, _wg_addr))) = await!(recv.next()) {
            let pkt = pkt.freeze();
//            debug!("LO2OUT {} bytes from {} via lo port {} to {}", pkt.len(), wg_addr, port, remote_addr);

            log_err!(await!(outbound.send_async((pkt, remote_addr))));
        }
        unreachable!("create_internal_socket");
    });

    Ok((send, port))
}

pub async fn forward_inbound(
    mut new_endpoints_tx: UnboundedSender<(SocketAddr, u16)>,
    mut udp_rx: impl Stream<Item=(BytesMut, SocketAddr), Error=impl std::fmt::Debug> + std::marker::Unpin,
    mut inet2stun_tx: impl Sink<SinkItem=(BytesMut, SocketAddr), SinkError=impl std::fmt::Debug> + std::marker::Unpin,
    udp_tx: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
    wg_port: u16)
{
    let mut connections = HashMap::new();
    let dst = SocketAddr::new([127, 0, 0, 1].into(), wg_port);

    while let Some(Ok((pkt, remote_addr))) = await!(udp_rx.next()) {
        let mut is_new = false;
        let (via_sock, via_port) = connections
            .entry(remote_addr)
            .or_insert_with(|| {
                is_new = true;
                create_internal_socket(remote_addr, udp_tx.clone()).unwrap()
            });

        if is_new {
            log_err!(await!(new_endpoints_tx.send_async((remote_addr, *via_port))),
                "New Endpoint Send Error: {:?}");
        }

//        debug!("IN2LO {} bytes from {} via lo port {} to wg port {}",
//            pkt.len(), remote_addr, via_port, dst.port());

        let pkt2 = pkt.clone();
        let buf = pkt.freeze();
        log_err!(await!(via_sock.send_async((buf, dst))));
        log_err!(await!(inet2stun_tx.send_async((pkt2, dst))));
    }

    unreachable!("forward_inbound");
}

enum WgSetEndpoint {
    Endpoint((SocketAddr, u16)),
    DhtAddress(SocketAddr),
}

pub async fn set_endpoint(
    mut wg_iface: crate::wg::Interface,
    remote_public_key: PublicKey,
    new_endpoints: UnboundedReceiver<(SocketAddr, u16)>,
    dht_address_rx: UnboundedReceiver<SocketAddr>,
) {
    let lo_ip: IpAddr = [127, 0, 0, 1].into();

    let mut dht_addresses = HashSet::new();
    let mut set_endpoints = HashMap::new();

    let new_endpoints = new_endpoints.map(WgSetEndpoint::Endpoint);
    let dht_address_rx = dht_address_rx.map(WgSetEndpoint::DhtAddress);

    let mut stream = new_endpoints.select(dht_address_rx);
    while let Some(Ok(item)) = await!(stream.next()) {
        // Err should never happen, because Receiver should never fail
        let addr = match item {
            WgSetEndpoint::DhtAddress(addr) => {
                dht_addresses.insert(addr);
                addr
            },
            WgSetEndpoint::Endpoint((addr, port)) => {
                set_endpoints.insert(addr, port);
                addr
            },
        };

        if dht_addresses.contains(&addr) {
            if let Some(lo_port) = set_endpoints.get(&addr) {
                debug!("Mapping {} to local port {}", addr, lo_port);
                log_err!(await!(wg_iface.set_endpoint(&remote_public_key[..32], (lo_ip, *lo_port).into())));
            }
        }
    }

    unreachable!("set_endpoint");
}