use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;
use std::time::Duration;

use tokio::timer::Delay;
use tokio::prelude::{*};

use opendht::OpenDht;

use crate::wg;
use crate::dht_encoding;

pub async fn run(
    stun_addr: Arc<Mutex<Option<SocketAddr>>>,
    local_public_key: Vec<u8>,
    remote_public_key: Vec<u8>,
    wg_iface: String,
) {
    let dht = OpenDht::new(4222);

    let dht2 = dht.clone();
    tokio::spawn_async(async move {
        while let Some(next) = dht2.tick() {
            let f = tokio::timer::Delay::new(next);
            let _ = await!(f);
        }
    });

    let dht2 = dht.clone();
    let local_public_key2 = local_public_key.clone();
    let remote_public_key2 = remote_public_key.clone();

    tokio::spawn_async(async {
        put_loop(dht2, stun_addr, local_public_key2, remote_public_key2);
    });
    await!(get_loop(dht, local_public_key, remote_public_key, wg_iface));
}

pub async fn put_loop(
    dht: OpenDht,
    stun_addr: Arc<Mutex<Option<SocketAddr>>>,
    local_public_key: Vec<u8>,
    remote_public_key: Vec<u8>,
) {
    let key = dht_encoding::encode_key(&local_public_key, &remote_public_key);

    let mut public_addr = None;
    loop {
        public_addr = (*stun_addr.lock().unwrap()).or(public_addr);
        let delay = if let Some(addr) = public_addr {
            let value = dht_encoding::encode_value(addr);

            // TODO: encrypt
            await!(dht.put(&key[..], &value)).unwrap();

            Duration::from_secs(60)
        } else {
            Duration::from_secs(5)
        };

        await!(Delay::new(Instant::now() + delay)).unwrap();
    }
}

pub async fn get_loop(
    dht: OpenDht,
    local_public_key: Vec<u8>,
    remote_public_key: Vec<u8>,
    wg_iface: String,
) {
    let key = dht_encoding::encode_key(&remote_public_key, &local_public_key);

    loop {
        let mut f = dht.get(&key[..]);
        while let Some(res) = await!(f.next()) {
            if let Ok(value) = res {
                if let Ok(addr) = dht_encoding::decode_value(&value) {
                    await!(wg::set_endpoint(&wg_iface, &remote_public_key, addr)).unwrap();

                    await!(Delay::new(Instant::now() + Duration::from_secs(5))).unwrap();
                }
            }
        }

        await!(Delay::new(Instant::now() + Duration::from_secs(30))).unwrap();
    }
}