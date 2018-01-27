use std::str;
use errors::Result;
use base64;
use ini::Ini;
use futures::prelude::*;
use tokio_core::reactor::Handle;
use std::process::Command;
use std::net::SocketAddr;
use tokio_process::CommandExt;

use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

pub struct Config {
    ini: Ini,
}

impl Config {
    fn parse(cfg: &str) -> Result<Config> {
        let ini = Ini::load_from_str(cfg)?;

        Ok(Config { ini } )
    }

    pub fn listen_port(&self) -> Result<u16> {
        let err = "Missing Interface::ListenPort in WireGuard configuration!";
        let port = self.ini.get_from(Some("Interface"), "ListenPort").ok_or(err)?;
        Ok(port.parse()?)
    }

    pub fn secret_key(&self) -> Result<SecretKey> {
        let err = "Missing Interface::PrivateKey in WireGuard configuration!";
        let key = self.ini.get_from(Some("Interface"), "PrivateKey").ok_or(err)?;

        let err = "Invalid PrivateKey".into();
        let key = base64::decode(key)?;
        SecretKey::from_slice(&key).ok_or(err)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let secret_key = self.secret_key()?;
        Ok(secret_key.public_key())
    }
}

pub struct WireguardCommand;

impl WireguardCommand {
    #[async]
    pub fn interface(handle: Handle, dev: String) -> Result<Config> {
        let cmd = Command::new("sudo").arg("wg")
                .arg("showconf")
                .arg(dev)
                .output_async(&handle);

        let output = await!(cmd)?;
        if !output.status.success() {
            let msg = str::from_utf8(&output.stderr)?;
            return Err(msg.into());
        }

        let cfg = str::from_utf8(&output.stdout)?;
        Config::parse(cfg)
    }

    #[async]
    pub fn set_endpoint(handle: Handle, dev: String, key: PublicKey, endpoint: SocketAddr) -> Result<()> {
        let cmd = Command::new("sudo").arg("wg")
                .arg("set")
                .arg(dev)
                .arg("peer")
                .arg(base64::encode(&key))
                .arg("endpoint")
                .arg(format!("{}", endpoint))
                .output_async(&handle);

        let output = await!(cmd)?;
        if !output.status.success() {
            let msg = str::from_utf8(&output.stderr)?;
            return Err(msg.into());
        }

        Ok(())
    }
}

/*
[Interface]
ListenPort = 51820
PrivateKey = 4KKLxPrTBd3WALaaVRirjEKX7dLqwdssNagAwT93X0Q=

[Peer]
PublicKey = L33UsFS1bqI914MZ7sHMUTFnLYBtHmaXjOsurWp5AgE=
AllowedIPs = 10.0.100.0/24
Endpoint = 127.0.0.1:51820
PersistentKeepalive = 60
*/

