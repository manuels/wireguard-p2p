use opendht;
use std::sync::Arc;
use async_std::prelude::*;
use async_std::net::ToSocketAddrs;
use std::net::SocketAddr;

use crate::api::DhtApi;

#[derive(Clone)]
pub struct OpenDht {
    dht: Arc<opendht::OpenDht>
}

impl OpenDht {
    pub async fn new(log: slog::Logger, listen_port: u16, bootstrap_servers: impl ToSocketAddrs) -> anyhow::Result<OpenDht> {
        let dht = opendht::OpenDht::new(listen_port)?;
        let dht = Arc::new(dht);

        let servers: Vec<SocketAddr> = bootstrap_servers.to_socket_addrs().await?.collect();
        slog::debug!(log, "OpenDHT bootstrapping...");
        if dht.bootstrap(&servers).await.is_err() {
            anyhow::bail!("Failed to bootstrap using {:?}", servers);
        }
        slog::info!(log, "OpenDHT bootstrapping done");

        let dht2 = dht.clone();
        async_std::task::spawn(async move {
            while let Some(next) = dht2.tick() {
                async_std::task::sleep(next).await;
            }
            slog::crit!(log, "OpenDHT loop ended!");
        });

        Ok(OpenDht { dht })
    }
}

#[async_trait::async_trait]
impl DhtApi for OpenDht {
    fn listen(&self, key: Vec<u8>) -> Box<dyn Stream<Item=Vec<u8>> + Send + Unpin> {
        Box::new(self.dht.listen(&key[..]))
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.dht.put(key, value).await?;
        Ok(())
    }
}
