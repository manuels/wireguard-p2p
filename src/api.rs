use std::net::SocketAddr;

use async_std::prelude::*;
use async_trait::async_trait;

use crate::PublicKey;
use crate::SecretKey;
use crate::stun;
use crate::utils::UdpSender;
use crate::utils::UdpReceiver;


pub struct DeviceConfig {}

impl DeviceConfig {
    pub async fn get_peers(&self, dev: &dyn WireguardDevice) -> anyhow::Result<Box<dyn Stream<Item=Box<dyn Peer>> + Unpin>> {
        dev.get_peers().await
    }
}

#[async_trait]
pub trait Peer {
    fn get_public_key(&self) -> PublicKey;
}

#[async_trait]
pub trait Stun {
    // return not just SocketAddr but also stun state type
    async fn lookup_public_address(&self, stun_log: &slog::Logger,
                                   to_inet_tx: &mut UdpSender,
                                   from_inet_rx: &mut UdpReceiver,
                                   stun_server: SocketAddr, ) -> anyhow::Result<stun::Connectivity>;
}

#[async_trait]
pub trait ConfigApi {
    fn get_wireguard_devices(&self) -> anyhow::Result<Box<dyn Stream<Item=(Box<dyn WireguardDevice>, DeviceConfig)> + Unpin>>;
    async fn get_peers(&self, dev: &dyn WireguardDevice) -> anyhow::Result<Box<dyn Stream<Item=Box<dyn Peer>> + Unpin>>;
}

#[async_trait]
pub trait SecretKeyCrypto {
    async fn encrypt(buf: dyn AsRef<u8>) -> dyn AsRef<u8>;
    async fn decrypt(buf: dyn AsRef<u8>) -> dyn AsRef<u8>;
}

pub trait PublicKeyCrypto {
    fn encrypt(&self, buf: &[u8]) -> anyhow::Result<bytes::Bytes>;
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

#[async_trait]
pub trait DhtApi {
    fn listen(&self, key: Vec<u8>) -> Box<dyn Stream<Item=Vec<u8>> + Send + Unpin>;
    async fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
}

#[async_trait]
pub trait WireguardDevice: Send + Sync {
    async fn get_name(&self) -> anyhow::Result<String>;
    async fn get_listen_port(&self) -> anyhow::Result<u16>;
    async fn get_public_key(&self) -> anyhow::Result<Option<PublicKey>>;
    async fn get_secret_key(&self) -> anyhow::Result<Option<SecretKey>>;
    async fn set_endpoint(&self, remote_pkey: &PublicKey, remote_addr: &SocketAddr) -> anyhow::Result<()>;
    async fn get_peers(&self) -> anyhow::Result<Box<dyn Stream<Item=Box<dyn Peer>> + Unpin>>;
}
