use std::future::Future;
use std::collections::hash_map::Entry;
use std::collections::hash_map::VacantEntry;
use std::net::SocketAddr;
use std::sync::Arc;
use std::result::Result;

use async_std::prelude::*;
use async_std::channel::{Sender, Receiver};

#[async_trait::async_trait]
pub trait TryInsertWithAsync<'a, V: Send> {
    async fn try_insert_with_async<E, F>(self, default: F) -> Result<&'a mut V, E>
        where F: Send + Future<Output=Result<V, E>>;
}

#[async_trait::async_trait]
impl<'a, K: Send, V: Send> TryInsertWithAsync<'a, V> for VacantEntry<'a, K, V> {
    async fn try_insert_with_async<E, F>(self, default: F) -> Result<&'a mut V, E>
        where F: Send + Future<Output=Result<V, E>>
    {
        let v = default.await?;
        let v = self.insert(v);
        Ok(v)
    }
}

#[async_trait::async_trait]
pub trait OrTryInsertWithAsync<'a, V: Send> {
    async fn or_try_insert_with_async<E, F>(self, default: F) -> Result<&'a mut V, E>
        where F: Send + Future<Output=Result<V, E>>;
}

#[async_trait::async_trait]
impl<'a, K: Send, V: Send> OrTryInsertWithAsync<'a, V> for Entry<'a, K, V> {
    async fn or_try_insert_with_async<E, F>(self, default: F) -> Result<&'a mut V, E>
        where F: Send + Future<Output=Result<V, E>>
    {
        match self {
            Entry::Occupied(v) => Ok(v.into_mut()),
            Entry::Vacant(o) => Ok(o.try_insert_with_async(default).await?)
        }
    }
}

pub fn spawn<F>(future: F) where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let handle = async_std::task::spawn(async {
        if let Err(e) = future.await {
            unimplemented!("Task failed: {:?}", e);
//            todo!() //error!("Task failed: {:?}", e);
        }
    });
    // TODO: what to do with handle?
}

pub fn batches<T: Unpin, S: futures::Stream<Item=T> + Unpin>(mut stream: S)
                                                             -> impl futures::Stream<Item=impl Iterator<Item=T>> {
    async_stream::stream! {
        loop {
            while let Some(res) = stream.next().await {
                yield vec![res].into_iter();
            }
        }
    }
}

/*
TODO:
pub fn batches<T: Unpin, S: futures::Stream<Item=T> + Unpin>(mut stream: S)
    -> impl futures::Stream<Item=impl Iterator<Item=T>>
{
    async_stream::stream! {
        loop {
            let mut items = vec![];
            while let Ok(res) = stream.next().timeout(Duration::from_secs(0)).await {
                if let Some(item) = res {
                    items.push(item)
                } else {
                    yield items.into_iter();
                    return;
                }
            }
            if !items.is_empty() {
                yield items.into_iter();
            }
        }
    }
}
*/

pub type UdpSender = Sender<(Vec<u8>, SocketAddr)>;
pub type UdpReceiver = Receiver<(bytes::Bytes, SocketAddr)>;

pub fn split_udp_socket(sock: async_std::net::UdpSocket) -> (UdpSender, UdpReceiver) {
    let (tx1, rx2) = async_std::channel::unbounded();
    let (tx2, rx1) = async_std::channel::unbounded();

    let sock = Arc::new(sock);
    let sock1 = sock.clone();

    spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await?;
            let b = bytes::Bytes::copy_from_slice(&buf[..n]);
            tx2.send((b, peer)).await?
        }
    });

    spawn(async move {
        loop {
            let (buf, dst): (Vec<u8>, SocketAddr) = rx2.recv().await?;
            let n = sock1.send_to(&buf[..], dst).await?;
            assert_eq!(buf.len(), n);
        }
    });


    (tx1, rx1)
}

pub fn cloned_rx(rx: UdpReceiver) -> (UdpReceiver, UdpReceiver) {
    let (tx1, rx1) = async_std::channel::unbounded();
    let (tx2, rx2) = async_std::channel::unbounded();

    spawn(async move {
        loop {
            let (buf, dst) = rx.recv().await?;
            tx1.send((buf.clone(), dst.clone())).await?;
            tx2.send((buf, dst)).await?;
        }
    });

    (rx1, rx2)
}
