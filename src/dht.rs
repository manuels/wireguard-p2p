use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use tokio::prelude::*;
use tokio::timer::Interval;
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
    pub async fn new(bootstrap_addrs: &[SocketAddr], port: u16) -> std::io::Result<Dht> {
        let dht = OpenDht::new(port)?;

        let dht2 = dht.clone();
        tokio::spawn_async(async move {
            while let Some(next) = dht2.tick() {
                log_err!(await!(tokio::timer::Delay::new(next)));
            }
            unreachable!("DHT tick loop");
        });

        let f = dht.bootstrap(bootstrap_addrs);
        log_err!(await!(f), "DHT Bootstrap error: {:?}");

        Ok(Dht(dht))
    }

    pub async fn put_addr_loop(&self,
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
                let value = dht_encoding::encode_addr(now, addr);
                let ciphertext = value.encrypt(&shared_key);

                log_err!(await!(self.0.put(&dht_key[..], &ciphertext)));
            }
        }
    }

    pub async fn get_addr_loop<'a>(&'a self,
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
                        .and_then(|v| dht_encoding::decode_addr(&v).ok());

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

    pub async fn put_key_loop<'a>(&'a self,
        key: &'a [u8],
        value: &'a [u8])
    {
        let mut interval = Interval::new(Instant::now(), Duration::from_secs(60));

        while let Some(Ok(_)) = await!(interval.next()) {
            log_err!(await!(self.0.put(key, &value)));
        }
    }

    pub fn listen<'a>(&'a self, dht_key: &'a [u8])
        -> impl Stream<Item=Vec<u8>>
    {
        self.0.listen(dht_key)
    }
}
