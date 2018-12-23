use std::net::SocketAddr;
use std::time::SystemTime;

use tokio::prelude::*;
use futures::sync::mpsc::UnboundedReceiver;
use bytes::BytesMut;

use opendht::OpenDht;

use crate::wg;
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
                log_err!(await!(tokio::timer::Delay::new(next)), "{:?}");
            }
            unreachable!("DHT tick loop");
        });

        let f = dht.bootstrap(bootstrap_addrs);
        log_err!(await!(f), "DHT Bootstrap error: {:?}");

        Dht(dht)
    }

    pub async fn put_loop(&self,
        shared_key: PrecomputedKey,
        mut stun_addr_rx: impl Stream<Item=SocketAddr, Error=impl std::fmt::Debug> + std::marker::Unpin + 'static,
        local_public_key: Vec<u8>,
        remote_public_key: Vec<u8>,
    ) {
        let key = dht_encoding::encode_key(&local_public_key, &remote_public_key);

        while let Some(res) = await!(stun_addr_rx.next()) {
            match res {
                Ok(addr) => {
                    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                    let value = dht_encoding::encode_value(now, addr);
                    let ciphertext = value.encrypt(&shared_key);

                    await!(self.0.put(&key[..], &ciphertext)).unwrap();
                }
                Err(err) => error!("{:?}", err)
            }
        }
    }

    pub async fn get_loop<'a>(&'a self,
        shared_key: PrecomputedKey,
        netns: Option<String>,
        mut new_endpoints: UnboundedReceiver<(SocketAddr, u16)>,
        local_public_key: Vec<u8>,
        remote_public_key: Vec<u8>,
        wg_iface: &'a str,
        mut dht2wg_tx: impl Sink<SinkItem=(BytesMut, SocketAddr), SinkError=impl std::fmt::Debug> + std::marker::Unpin + 'static,
    ) {
        let key = dht_encoding::encode_key(&remote_public_key, &local_public_key);

        use std::net::IpAddr;
        let lo_ip: IpAddr = [127, 0, 0, 1].into();

        let iface = wg_iface.to_string();
        let pubkey = remote_public_key.clone();
        let ns = netns.clone();
        tokio::spawn_async(async move {
            while let Some(res) = await!(new_endpoints.next()) {
                match res {
                    Ok((remote_addr, lo_port)) => {
                        debug!("Mapping {} to local port {}", remote_addr, lo_port);
                        await!(wg::set_endpoint(ns.clone(), &iface, &pubkey, (lo_ip, lo_port).into())).unwrap();
                    },
                    Err(err) => error!("Error: {:?}", err),
                }
            }
        });

        let mut last_time = None;
        let mut stream = self.0.listen(&key[..]);
        while let Some(res) = await!(stream.next()) {
            match res {
                Ok(ciphertext) => {
                    if let Ok(value) = ciphertext.decrypt(&shared_key) {
                        if let Ok((time, addr)) = dht_encoding::decode_value(&value) {
                            if last_time.map(|t| t < time).unwrap_or(true) {
                                last_time = Some(time);

                                debug!("found DHT value: {:?}", addr);

                                // here we fake a packet from the internet to the wg-p2p daemon
                                // so a new connection for 'addr' is created and real packages
                                // will be forwarded to wireguard correctly.
                                await!(dht2wg_tx.send_async((BytesMut::new(), addr))).unwrap();
                                //await!(Delay::new(Instant::now() + Duration::from_secs(5))).unwrap();
                            }
                        } else {
                            warn!("Found invalid value");
                        }
                    }
                }
                Err(e) => error!("get loop {:?}", e),
            }
        }
    
        unreachable!("DHT listen() should never end!")
    }
}
