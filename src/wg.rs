use std::io;
use std::io::Error;
use std::net::SocketAddr;

use netlink_wg::NlSocket;
use netlink_wg::Family;
use netlink_wg::IfaceBy;
use netlink_wg::Protocol;
pub use netlink_wg::WG_KEY_LEN;

use crate::utils::nix2io;

pub struct Interface {
    pub ifindex: u32,
    sock: NlSocket,
    wg_family: Family,
}

impl Interface {
    pub fn new(wg_family: Family, netns: Option<String>, ifindex: u32) -> io::Result<Interface> {
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

    pub async fn get_family(name: &'static str) -> io::Result<Option<Family>> {
        let mut sock = NlSocket::new(Protocol::Generic).map_err(nix2io)?;
        await!(sock.get_family(name))
    }

    pub async fn get_wg_interfaces(netns: Option<String>) -> io::Result<Vec<netlink_wg::routes::Interface>> {
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
        remote_public_key: &'a [u8],
        addr: SocketAddr
    ) -> Result<(), Error>
    {
        assert_eq!(remote_public_key.len(), WG_KEY_LEN);
        await!(self.sock.set_wg_endpoint(&self.wg_family,
            IfaceBy::Index(self.ifindex),
            remote_public_key,
            addr))
    }

    pub async fn get_config(&mut self) -> io::Result<netlink_wg::wg::IfConfig> {
        await!(self.sock.get_wg_device(&self.wg_family, IfaceBy::Index(self.ifindex)))
    }
}
