use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use async_std::prelude::*;
use async_std::sync::Mutex;
use wireguard_uapi::{DeviceInterface, WgSocket};

use crate::api;
use crate::WireguardDevice;
use crate::PublicKey;
use crate::SecretKey;

#[allow(dead_code)]
pub struct WireguardDev {
    socket: Arc<Mutex<WgSocket>>,
    ifindex: u32,
    ifname: String,
}

impl WireguardDev {
    pub fn new(ifname: String) -> anyhow::Result<Self> {
        let mut socket = WgSocket::connect()?;
        let dev = socket.get_device(DeviceInterface::from_name(&ifname))?;
        let ifindex = dev.ifindex;

        Ok(WireguardDev {
            ifindex, ifname,
            socket: Arc::new(Mutex::new(socket)),
        })
    }

    async fn get_device(&self) -> anyhow::Result<wireguard_uapi::get::Device> {
        let mut sock = self.socket.lock().await;

        let dev = sock.get_device(DeviceInterface::from_index(self.ifindex))?;
        Ok(dev)
    }

    pub fn as_trait(self) -> Box<dyn WireguardDevice> {
        Box::new(self)
    }
}

#[async_trait::async_trait]
impl WireguardDevice for WireguardDev {
    async fn get_listen_port(&self) -> anyhow::Result<u16> {
        let dev = self.get_device().await?;
        return Ok(dev.listen_port);
    }

    async fn set_endpoint(&self, remote_pkey: &PublicKey, remote_addr: &SocketAddr) -> anyhow::Result<()> {
        let dev = self.get_device().await?;
        let peer = dev.peers.iter().filter(|p| p.public_key.eq(&remote_pkey.0.0)).next();
        if let Some(peer) = peer {
            let peer = wireguard_uapi::set::Peer {
                public_key: &peer.public_key,
                flags: Vec::new(),
                preshared_key: Some(&peer.preshared_key),
                endpoint: Some(&remote_addr),
                persistent_keepalive_interval: if peer.persistent_keepalive_interval == 0 { None } else { Some(peer.persistent_keepalive_interval) },
                allowed_ips: Vec::new(),
                protocol_version: if peer.protocol_version == 0 { None } else { Some(peer.protocol_version) },
            };

            let dev = wireguard_uapi::set::Device {
                interface: DeviceInterface::from_index(self.ifindex),
                flags: Vec::new(),
                private_key: dev.private_key.as_ref(),
                listen_port: if dev.listen_port == 0 { None } else { Some(dev.listen_port) },
                fwmark: Some(dev.fwmark),
                peers: vec!(peer)
            };

            let mut sock = self.socket.lock().await;
            sock.set_device(dev)?;
            Ok(())
        } else {
            Err(anyhow!("Failed to find peer {} for wireguard device {} ({})", remote_pkey, self.ifname, self.ifindex))
        }
    }

    async fn get_name(&self) -> anyhow::Result<String> {
        let dev = self.get_device().await?;
        return Ok(dev.ifname);
    }

    async fn get_public_key(&self) -> anyhow::Result<Option<PublicKey>> {
        let dev = self.get_device().await?;
        let pkey = dev.public_key.map(PublicKey::new);
        return Ok(pkey);
    }

    async fn get_secret_key(&self) -> anyhow::Result<Option<SecretKey>> {
        let dev = self.get_device().await?;
        let skey = dev.private_key.map(SecretKey::new);
        return Ok(skey);
    }

    async fn get_peers(&self) -> anyhow::Result<Box<dyn Stream<Item=Box<dyn api::Peer>> + Unpin>> {
        let dev = self.get_device().await?;
        let vec: Vec<Box<dyn api::Peer>> = dev.peers.into_iter().map(|p| Peer(p).as_trait()).collect();
        let stream = futures::stream::iter(vec.into_iter());
        Ok(Box::new(stream))
    }
}

struct Peer(wireguard_uapi::get::Peer);

impl Peer {
    fn as_trait(self) -> Box<dyn api::Peer> {
        Box::new(self)
    }
}

#[async_trait::async_trait]
impl api::Peer for Peer {
    fn get_public_key(&self) -> PublicKey {
        PublicKey::new(self.0.public_key)
    }
}
