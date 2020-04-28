use std::io;
use std::future::Future;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::collections::hash_map::Entry;
use std::pin::Pin;

use bytes::Bytes;
use futures::StreamExt;
use futures::sink::SinkExt;
use futures::sink::SinkMapErr;
use futures::channel::mpsc;
use futures::stream::TryUnfold;
use async_trait::async_trait;
use async_std::net::UdpSocket;
use async_std::sync::Arc;
use async_std::task;

use ansi_term::Colour;
use crate::crypto::PublicKey;
use futures::channel::mpsc::SendError;

#[async_trait]
pub trait OrTryInsertWithAsync<'a, V: Send> {
    async fn or_try_insert_with_async<E, F>(self, default: F) -> Result<&'a mut V, E>
        where F: Send + Future<Output=Result<V, E>>;
}

#[async_trait]
impl<'a, K: Send, V: Send> OrTryInsertWithAsync<'a, V> for Entry<'a, K, V> {
    async fn or_try_insert_with_async<E, F>(self, default: F) -> Result<&'a mut V, E>
        where F: Send + Future<Output=Result<V, E>>
    {
        match self {
            Entry::Occupied(v) => Ok(v.into_mut()),
            Entry::Vacant(o) => {
                let v = default.await?;
                let v = o.insert(v);
                Ok(v)
            }
        }
    }
}

pub trait IntoIpv6 {
    fn into_ipv6(self) -> SocketAddrV6;
}

impl IntoIpv6 for SocketAddr {
    fn into_ipv6(self) -> SocketAddrV6 {
        match self {
            SocketAddr::V6(sock) => sock,
            SocketAddr::V4(sock) => {
                let ipv6 = sock.ip().to_ipv6_mapped();
                SocketAddrV6::new(ipv6, sock.port(), 0, 0)
            }
        }
    }
}

pub trait MaybeIntoIpv4 {
    fn maybe_into_ipv4(self) -> SocketAddr;
}

impl MaybeIntoIpv4 for SocketAddrV6 {
    fn maybe_into_ipv4(self) -> SocketAddr {
        let ipv6 = *self.ip();
        if let Some(ipv4) = ipv6.to_ipv4() {
            (ipv4, self.port()).into()
        } else {
            self.into()
        }
    }
}

pub trait UdpSink {
    fn into_sink(self) -> mpsc::UnboundedSender<(bytes::Bytes, std::net::SocketAddr)>;
}

impl UdpSink for Arc<UdpSocket> {
    fn into_sink(self) -> mpsc::UnboundedSender<(bytes::Bytes, std::net::SocketAddr)> {
        let (inet_tx, mut rx) = mpsc::unbounded::<(bytes::Bytes, SocketAddr)>();

        async_std::task::spawn(async move {
            while let Some((pkt, peer)) = rx.next().await {
                //println!("{} fwd out {} bytes to {}", Colour::White.dimmed().paint("FWD"), pkt.len(), peer);
                // TODO network unreachable
                if let Err(e) = self.as_ref().send_to(&pkt[..], peer).await {
                    eprintln!("{} inet send failed {} bytes to {}: {}", Colour::Red.paint("FWD"), pkt.len(), peer, e);
                }
            }
            panic!("fwd out failed");
        });

        inet_tx
    }
}

pub trait UdpSocketSplit {
    type Item;
    type Sender;
    type Receiver;

    fn split(self) -> (Self::Sender, (Self::Receiver, Self::Receiver));
}

impl UdpSocketSplit for UdpSocket {
    type Item = (Bytes, SocketAddr);
    type Sender = mpsc::UnboundedSender<Self::Item>;
    type Receiver = mpsc::UnboundedReceiver<Self::Item>;

    fn split(self) -> (Self::Sender, (Self::Receiver, Self::Receiver))
    {
        let inet_sock1 = Arc::new(self);
        let inet_sock2 = inet_sock1.clone();

        let inet_rx = inet_sock1.into_stream();
        let (tx1, inet_rx1) = mpsc::unbounded();
        let (tx2, inet_rx2) = mpsc::unbounded();

        let tx = tx1.fanout(tx2).map_err_as_io();
        task::spawn(inet_rx.forward(tx));

        let inet_tx = inet_sock2.into_sink();

        (inet_tx, (inet_rx1, inet_rx2))
    }
}



pub trait UdpSocketToStream {
    type Ok;
    type ReturnValue;

    fn into_stream(self) ->
        TryUnfold<
            Self,
            Box<dyn Send + FnMut(Self) -> Self::ReturnValue>,
            Self::ReturnValue
        >
        where Self: Sized;
}

impl UdpSocketToStream for Arc<UdpSocket> {
    type Ok = Option<((Bytes, SocketAddr), Self)>;
    type ReturnValue = Pin<Box<dyn Send + Future<Output=io::Result<Self::Ok>>>>;

    fn into_stream(self) ->
        TryUnfold<Self,
            Box<dyn Send + FnMut(Self) -> Self::ReturnValue>,
            Self::ReturnValue
            >
    {
        let func = |sock: Self| -> Self::ReturnValue {
           Box::pin(async move {
                let mut buf = [0u8; 4096];

                let res = sock.recv_from(&mut buf).await;
                // TODO: when return None?
                res.map(|(n, peer)| Some(((buf[..n].to_vec().into(), peer), sock)))
            })
        };
        let func = Box::new(func);
        futures::stream::try_unfold(self, func)
    }
}

pub trait AsBase64 {
    fn as_b64(&self) -> String;
}

impl AsBase64 for PublicKey {
    fn as_b64(&self) -> String {
        base64::encode(&self.0)
    }
}

pub trait SendErrorAsIoError<T, M> {
    fn map_err_as_io(self) -> M;
}

impl<T, S> SendErrorAsIoError<T, SinkMapErr<Self, Box<dyn Send + Fn(SendError) -> io::Error>>>
    for S where S: futures::Sink<T, Error=mpsc::SendError>
{
    /// converts a Sink<Error=SendError> to a Sink<Error=io::Error>
    fn map_err_as_io(self) -> SinkMapErr<Self, Box<dyn Send + Fn(SendError) -> io::Error>> {
        let mapper = |e: SendError| {
            assert!(e.is_full() || e.is_disconnected());
            if e.is_disconnected() {
                io::ErrorKind::ConnectionAborted.into()
            } else {
                io::ErrorKind::WouldBlock.into()
            }
        };
        self.sink_map_err(Box::new(mapper))
    }
}
