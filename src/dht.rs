use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use std::time::Duration;
use std::time::SystemTime;
use std::net::ToSocketAddrs;

use tokio::timer::Delay;
use tokio::prelude::*;
use futures::stream::MergedItem;
use futures::sync::mpsc::UnboundedReceiver;
use bytes::BytesMut;

use opendht::OpenDht;

use crate::wg;
use crate::dht_encoding;

#[derive(Clone)]
pub struct Dht(OpenDht);

impl Dht {
    pub async fn new(port: u16) -> Dht {
        let dht = OpenDht::new(port);

        let dht2 = dht.clone();
        tokio::spawn_async(async move {
            while let Some(next) = dht2.tick() {
                let f = tokio::timer::Delay::new(next);
                let _ = await!(f);
            }
            unreachable!("DHT tick loop");
        });

        let addrs: Vec<_> = "bootstrap.ring.cx:4222".to_socket_addrs().unwrap().collect();
        let f = dht.bootstrap(&addrs);
        log_err!(await!(f), "DHT Bootstrap error: {:?}");

        Dht(dht)
    }

    pub async fn put_loop(&self,
        stun_addr: Arc<Mutex<Option<SocketAddr>>>,
        local_public_key: Vec<u8>,
        remote_public_key: Vec<u8>,
    ) {
        let key = dht_encoding::encode_key(&local_public_key, &remote_public_key);

        let mut public_addr = None;
        loop {
            public_addr = { (*stun_addr.lock().unwrap()).or(public_addr) };
            let delay = if let Some(addr) = public_addr {
                debug!("Putting public_addr: {:?}", public_addr);
                let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                let value = dht_encoding::encode_value(now, addr);

                // TODO: encrypt
                await!(self.0.put(&key[..], &value)).unwrap();

                Duration::from_secs(60)
            } else {
                Duration::from_secs(5)
            };

            await!(Delay::new(Instant::now() + delay)).unwrap();
        }
    }

    pub async fn get_loop<'a>(&'a self,
        netns: Option<String>,
        new_endpoints: UnboundedReceiver<(SocketAddr, u16)>,
        local_public_key: Vec<u8>,
        remote_public_key: Vec<u8>,
        wg_iface: &'a str,
        mut dht2wg_tx: impl Sink<SinkItem=(BytesMut, SocketAddr), SinkError=impl std::fmt::Debug> + std::marker::Unpin + 'static,
    ) {
        let key = dht_encoding::encode_key(&remote_public_key, &local_public_key);

        use std::net::IpAddr;
        let lo_ip: IpAddr = [127, 0, 0, 1].into();

        log_err!(await!(Delay::new(Instant::now() + Duration::from_secs(10))), "Delay {:?}");
        debug!("Get loop start!");

        let mut last_time = None;
        let mut stream = self.0.listen(&key[..]).merge(new_endpoints);
        while let Some(res) = await!(stream.next()) {
            match res {
                Ok(MergedItem::First(value)) => {
                    if let Ok((time, addr)) = dht_encoding::decode_value(&value) {
                        if last_time.map(|t| t < time).unwrap_or(true) {
                            last_time = Some(time);

                            debug!("found DHT value: {:?}", addr);

                            // here we fake a packet from the internet to the wg-p2p daemon
                            // so a new connection for 'addr' is created and real packages
                            // will be forwarded to wireguard correctly.
                            await!(dht2wg_tx.send_async((BytesMut::new(), addr))).unwrap();

                            await!(Delay::new(Instant::now() + Duration::from_secs(5))).unwrap();
                        }
                    } else {
                        warn!("Found invalid value");
                    }
                }
                Ok(MergedItem::Second((remote_addr, lo_port))) => {
                    // TODO: we must set a loopback endpoint
                    //       for that we must find out the registered loop back device
                    debug!("Mapping {} to local port {}", remote_addr, lo_port);
                    await!(wg::set_endpoint(netns.clone(), &wg_iface, &remote_public_key, (lo_ip, lo_port).into())).unwrap();
                }
                Ok(MergedItem::Both(value, (remote_addr, lo_port))) => {
                    {
                        if let Ok((time, addr)) = dht_encoding::decode_value(&value) {
                            if last_time.map(|t| t < time).unwrap_or(true) {
                                last_time = Some(time);
                                debug!("found addr: {:?}", addr);

                                // here we fake a packet from the internet to the wg-p2p daemon
                                // so a new connection for 'addr' is created and real packages
                                // will be forwarded to wireguard correctly.
                                await!(dht2wg_tx.send_async((BytesMut::new(), addr))).unwrap();

                                await!(Delay::new(Instant::now() + Duration::from_secs(5))).unwrap();
                            }
                        } else {
                            warn!("Found invalid value");
                        }
                    }
                    {
                        debug!("Mapping {} to local port {}", remote_addr, lo_port);
                        await!(wg::set_endpoint(netns.clone(), &wg_iface, &remote_public_key, (lo_ip, lo_port).into())).unwrap();
                    }
                }
                Err(e) => error!("get loop {:?}", e),
            }
        }
    
        unreachable!("DHT listen() should never end!")
    }
}
