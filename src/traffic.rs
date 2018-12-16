use std::io;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use tokio::prelude::*;
use futures::sync::mpsc;
use bytes::Bytes;
use bytes::BytesMut;

type UdpStream = tokio::prelude::stream::SplitStream<tokio::net::UdpFramed<tokio::codec::BytesCodec>>;
type UdpSink = tokio::prelude::stream::SplitSink<tokio::net::UdpFramed<tokio::codec::BytesCodec>>;

// forward outbound data to udp socket
pub async fn forward_outbound(
        rx: impl Stream<Item=(Bytes, SocketAddr)>,
        inet_send: UdpSink)
{
    let rx = rx.map_err(|_| io::Error::new(io::ErrorKind::Other, "TODO"));
    let rx = rx.inspect(|(pkt, dst)| debug!("<< {} bytes to {}", pkt.len(), dst));

    await!(rx.forward(inet_send)).unwrap();
}

/// Create a new loopback socket for a new peer to forward packets between the
/// public socket and the loopback wireguard socket
fn create_internal_socket(remote_addr: SocketAddr,
    mut outbound: mpsc::UnboundedSender<(Bytes, SocketAddr)>)
    -> std::io::Result<(UdpSink, u16)>
{
    let loop_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let sock = tokio::net::UdpSocket::bind(&loop_addr)?;
    let port = sock.local_addr()?.port();
    
    let codec = tokio::codec::BytesCodec::new();
    let (send, mut recv) = tokio::net::UdpFramed::new(sock, codec).split();

    // forward packets from the new loopback socket to the remote peer
    tokio::spawn_async(async move {
        while let Some(res) = await!(recv.next()) {
            match res {
                Err(e) => error!("{:?}", e),
                Ok((pkt, _wg_addr)) => {
                    let pkt = Bytes::from(pkt);
                    debug!("<< {} bytes via {} to {}", pkt.len(), port, remote_addr);

                    await!(outbound.send_async((pkt, remote_addr))).unwrap();
                }
            }
        }
    });

    Ok((send, port))
}

pub async fn forward_inbound(
    mut inbound: UdpStream,
    mut stun: impl Sink<SinkItem=(BytesMut, SocketAddr), SinkError=impl std::fmt::Debug> + std::marker::Unpin,
    outbound: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
    wg_port: u16)
{
    let mut connections = HashMap::new();
    let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), wg_port);

    // TODO: on new remote peer from dht:
    //       1) insert remote peer into connections
    //       2) set wireguard peer to remote peer
    // PLAN: use UnboundedReceiver instead of UdpStream,
    //       forward UdpStream to UnboundedSender,
    //       clone UnboundedSender and let Dht send empty packets

    while let Some(res) = await!(inbound.next()) {
        match res {
            Err(e) => error!("{:?}", e),
            Ok((pkt, remote_addr)) => {
                await!(stun.send_async((pkt.clone(), dst))).unwrap();

                // TODO: cache this lookup?
                let (via_sock, via_port) = connections
                    .entry(remote_addr)
                    .or_insert_with(|| {
                        create_internal_socket(remote_addr, outbound.clone()).unwrap()
                    });

                debug!(">> {} bytes from {} via port {} to port {}",
                    pkt.len(), remote_addr, via_port, dst.port());

                let pkt = Bytes::from(pkt);
                await!(via_sock.send_async((pkt, dst))).unwrap();
            }
        }
    }
}
