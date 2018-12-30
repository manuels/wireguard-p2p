use std::time::Duration;
use std::time::SystemTime;
use std::net::SocketAddr;

use tokio::prelude::*;
use futures::sync::mpsc::UnboundedSender;
use bytes::Bytes;
use bytes::BytesMut;

use opendht::OpenDht;

use crate::crypto::Decrypt;
use crate::crypto::Encrypt;
use crate::crypto::PrecomputedKey;
use crate::dht_encoding;

#[derive(Clone)]
pub struct Dht(OpenDht);

impl Dht {
    pub async fn new(bootstrap_addrs: &[SocketAddr], port: u16) -> Dht {
        let dht = OpenDht::new(port);

        let dht2 = dht.clone();
        tokio::spawn_async(async move {
            while let Some(next) = dht2.tick() {
                log_err!(await!(tokio::timer::Delay::new(next)));
            }
            unreachable!("DHT tick loop");
        });

        let f = dht.bootstrap(bootstrap_addrs);
        log_err!(await!(f), "DHT Bootstrap error: {:?}");

        Dht(dht)
    }

    pub async fn put_loop(&self,
        shared_key: PrecomputedKey,
        dht_key: Bytes,
        stun_addr_rx: impl Stream<Item=SocketAddr> + std::marker::Unpin + 'static,
    ) {
        let mut stun_addr_rx = stun_addr_rx.timeout(Duration::from_secs(2 * 60));

        let mut addr = None;
        while let Some(new_addr) = await!(stun_addr_rx.next()) {
            // We can ignore errors on res here the receiver cannot fail,
            // so it must be a timeout.
            addr = new_addr.ok().or(addr);

            if let Some(addr) = addr {
                let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                let value = dht_encoding::encode_value(now, addr);
                let ciphertext = value.encrypt(&shared_key);

                log_err!(await!(self.0.put(&dht_key[..], &ciphertext)));
            }
        }
    }

    pub async fn get_loop<'a>(&'a self,
        shared_key: PrecomputedKey,
        dht_key: Bytes,
        mut dht_address_tx: UnboundedSender<SocketAddr>,
        mut dht2wg_tx: impl Sink<SinkItem=(BytesMut, SocketAddr), SinkError=impl std::fmt::Debug> + std::marker::Unpin + 'static,
    ) {
        let mut last_time = None;
        let mut stream = self.0.listen(&dht_key[..]);
        while let Some(res) = await!(stream.next()) {
            match res {
                Ok(ciphertext) => {
                    let dht_value = ciphertext.decrypt(&shared_key).ok()
                        .and_then(|v| dht_encoding::decode_value(&v).ok());

                    if let Some((time, addr)) = dht_value {
                        if last_time < Some(time) {
                            last_time = Some(time);
                            debug!("Found DHT value: {:?}", addr);

                            log_err!(await!(dht_address_tx.send_async(addr)));

                            // here we fake a packet from the internet to the wg-p2p daemon
                            // so a new connection for 'addr' is created and real packages
                            // will be forwarded to wireguard correctly.
                            await!(dht2wg_tx.send_async((BytesMut::new(), addr))).unwrap();
                        }
                    } else {
                        warn!("Found invalid value in DHT");
                    }
                }
                Err(e) => error!("get loop {:?}", e),
            }
        }
    
        unreachable!("DHT listen() should never end!")
    }
}
