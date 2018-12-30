use std::io::Error;
use std::net::SocketAddr;

use netlink::NlSocket;
use netlink::Family;
use netlink::IfaceBy;
use netlink::Protocol;
use netlink::WG_KEY_LEN;

use crate::utils::nix2io;

pub struct Interface {
    pub ifindex: u32,
    sock: NlSocket,
    wg_family: Family,
}

impl Interface {
    pub fn new(wg_family: Family, netns: Option<String>, ifindex: u32) -> std::io::Result<Interface> {
        let sock = if let Some(netns) = netns {
            NlSocket::new_in_netns(netns, Protocol::Generic).map_err(nix2io)?
        } else {
            NlSocket::new(Protocol::Generic).map_err(nix2io)?
        };

        Ok(Interface {
            wg_family,
            ifindex,
            sock
        })
    }

    pub async fn get_family(name: &'static str) -> std::io::Result<Option<Family>> {
        let mut sock = NlSocket::new(Protocol::Generic).map_err(nix2io)?;
        await!(sock.get_family(name))
    }

    pub async fn get_wg_interfaces(netns: Option<String>) -> std::io::Result<Vec<netlink::routes::Interface>> {
        let mut sock = if let Some(netns) = netns {
            NlSocket::new_in_netns(netns, Protocol::Route).map_err(nix2io)?
        } else {
            NlSocket::new(Protocol::Route).map_err(nix2io)?
        };

        let ifaces = await!(sock.get_devices())?;
        
        Ok(ifaces.into_iter().filter(|i| {
            i.link_info == Some("wireguard".to_string())
        }).collect())
    }

    pub async fn set_endpoint<'a>(&'a mut self,
        remote_public_key: &'a [u8; WG_KEY_LEN],
        addr: SocketAddr
    ) -> Result<(), Error>
    {
        await!(self.sock.set_wg_endpoint(&self.wg_family,
            IfaceBy::Index(self.ifindex),
            remote_public_key,
            addr))
    }

    pub async fn get_config(&mut self) -> std::io::Result<netlink::wg::IfConfig> {
        await!(self.sock.get_wg_device(&self.wg_family, IfaceBy::Index(self.ifindex)))
    }
}
