use std::net::SocketAddr;

use async_trait::async_trait;
use async_std::prelude::*;

use crate::PublicKey;
use crate::SecretKey;
use crate::api::*;
use crate::WireguardDevice;
use crate::stun;
use crate::utils::UdpSender;
use crate::utils::UdpReceiver;

pub struct Cfg;

/*
impl Cfg {
    pub fn new() -> Self {
        Cfg
    }
}
*/

#[async_trait]
impl ConfigApi for Cfg {
    fn get_wireguard_devices(&self) -> anyhow::Result<Box<dyn Stream<Item=(Box<dyn WireguardDevice>, DeviceConfig)> + Unpin>> {
        unimplemented!()
    }

    async fn get_peers(&self, dev: &dyn WireguardDevice) -> anyhow::Result<Box<dyn Stream<Item=Box<dyn Peer>> + Unpin>> {
        unimplemented!()
    }
}

pub struct FakeDht;

/*
impl FakeDht {
    pub fn new() -> Self {
        FakeDht
    }
}
*/

#[async_trait]
impl DhtApi for FakeDht {
    fn listen(&self, key: Vec<u8>) -> Box<dyn Stream<Item=Vec<u8>> + Send + Unpin> {
        unimplemented!()
    }

    async fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        todo!()
    }
}

pub struct FakeStun;

#[async_trait]
impl Stun for FakeStun {
    // return not just SocketAddr but also stun state type
    async fn lookup_public_address(&self, stun_log: &slog::Logger,
                                   to_inet_tx: &mut UdpSender,
                                   from_inet_rx: &mut UdpReceiver,
                                   stun_server: SocketAddr) -> anyhow::Result<stun::Connectivity> {
        todo!()
    }
}

pub struct FakeWireguardDevice;

#[async_trait]
impl WireguardDevice for FakeWireguardDevice {
    async fn get_listen_port(&self) -> anyhow::Result<u16> {
        return Ok(9999);
    }

    async fn set_endpoint(&self, remote_pkey: &PublicKey, remote_addr: &SocketAddr) -> anyhow::Result<()> {
        unimplemented!()
    }

    async fn get_name(&self) -> anyhow::Result<String> {
        unimplemented!()
    }

    async fn get_public_key(&self) -> anyhow::Result<Option<PublicKey>> {
        unimplemented!()
    }

    async fn get_secret_key(&self) -> anyhow::Result<Option<SecretKey>> {
        unimplemented!()
    }

    async fn get_peers(&self) -> anyhow::Result<Box<dyn Stream<Item=Box<dyn Peer>> + Unpin>>  {
        unimplemented!()
    }
}

pub struct NoopPublicKeyCrypto;

impl PublicKeyCrypto for NoopPublicKeyCrypto {
    fn encrypt(&self, buf: &[u8]) -> anyhow::Result<bytes::Bytes> {
        return Ok(bytes::Bytes::from(buf.to_vec()));
    }

    fn decrypt(&self, buf: &[u8]) -> Option<Vec<u8>> {
        return Some(buf.to_vec());
    }
}
