use std::str;
use std::process::Command;
use std::net::SocketAddr;
use std::io::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use std::time::Duration;
use std::io::ErrorKind;
use std::convert::TryInto;

use base64;
use std::collections::HashMap;
use ansi_term::Colour;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct PublicKey(pub [u8; 32]);
pub struct SecretKey(pub [u8; 32]);

pub struct WgDevice {
    name: String,
    pub listen_port: u16,
    pub secret_key: SecretKey,
    pub peers: Vec<WgPeer>,
}

#[derive(Clone)]
pub struct WgPeer {
    pub public_key: PublicKey,
    //preshared_key:
    pub endpoint: Option<SocketAddr>,
    //allowed-ips
    pub latest_handshakes: Option<SystemTime>,
    // transfer_rx: usize
    // transfer_tx: usize
    pub persistent_keepalive: Option<Duration>,
}

impl WgDevice {
    pub async fn get(name: String) -> std::io::Result<WgDevice> {
        let listen_port = Self::listen_port(&name)?;
        let public_keys = Self::peers(&name)?;
        let mut endpoints = Self::endpoints(&name)?;
        let secret_key = Self::secret_key(&name)?;

        let mut peers = vec![];
        for p in public_keys {
            let endpoint = endpoints.remove(&p).expect("Peer gone?");
            peers.push(WgPeer {
                latest_handshakes: None,
                persistent_keepalive: None,
                public_key: p,
                endpoint,
            })
        }

        Ok(WgDevice {
            name,
            listen_port,
            secret_key,
            peers,
        })
    }

    fn secret_key(name: &str) -> std::io::Result<SecretKey> {
        let output = Command::new("wg")
            .arg("show")
            .arg(name)
            .arg("private-key")
            .output()?;

        if !output.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to run 'wg show private-key'"))
        }

        let s = str::from_utf8(&output.stdout).expect("Failed to parse 'wg show private-key'");
        let key: String = s.trim().parse().expect("");
        let key = base64::decode(&key).expect("");
        let mut k = [0; 32];
        k.copy_from_slice(&key[..32]);
        let key = SecretKey(k);

        Ok(key)
    }


    fn listen_port(name: &str) -> std::io::Result<u16> {
        let output = Command::new("wg")
            .arg("show")
            .arg(name)
            .arg("listen-port")
            .output()?;

        if !output.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to run 'wg show listen-port'"))
        }

        let s = str::from_utf8(&output.stdout).expect("Failed to parse 'wg show listen-port'");
        let port = s.trim().parse().expect("");
        Ok(port)
    }

    fn peers(name: &str) -> std::io::Result<Vec<PublicKey>> {
        let output = Command::new("wg")
            .arg("show")
            .arg(name)
            .arg("peers")
            .output()?;

        if !output.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to run 'wg show peers'"))
        }

        let s = str::from_utf8(&output.stdout).expect("Failed to parse'wg show peers'");

        let mut peers = vec![];
        for l in s.lines() {
            let key = base64::decode(l).expect("wg reported an invalid peer");
            peers.push(PublicKey(key[..].try_into().expect("public_key has incorrect length")));
        }
        Ok(peers)
    }

    fn endpoints(name: &str) -> std::io::Result<HashMap<PublicKey, Option<SocketAddr>>> {
        let output = Command::new("wg")
            .arg("show")
            .arg(name)
            .arg("endpoints")
            .output()?;

        if !output.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to run 'wg show peers'"))
        }

        let s = str::from_utf8(&output.stdout).expect("Failed to parse'wg show peers'");

        let mut peers = HashMap::new();
        for line in s.lines() {

            let data: Vec<_> = line.splitn(2, '\t').collect();
            let (key, endpoint) = (data[0], data[1]);

            let key = base64::decode(key).expect("wg reported an invalid peer");
            let key = PublicKey(key[..].try_into().expect("public_key has incorrect length"));

            let endpoint = if endpoint == "(none)" {
                None
            } else {
                Some(endpoint.parse().expect("invalid endpoint"))
            };

            peers.insert(key, endpoint);
        }
        Ok(peers)
    }

    pub fn set_endpoint(&self, peer: &PublicKey, endpoint: &SocketAddr) -> std::io::Result<()> {
        let output = Command::new("wg")
            .arg("set")
            .arg(&self.name)
            .arg("peer")
            .arg(base64::encode(&peer.0))
            .arg("endpoint")
            .arg(endpoint.to_string())
            .output()?;

        if !output.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to run 'wg set peer endpoint'"))
        }

        return Ok(())
    }

    pub fn latest_handshake(&self) -> std::io::Result<HashMap<PublicKey, Option<SystemTime>>> {
        let output = Command::new("wg")
            .arg("show")
            .arg(&self.name)
            .arg("latest-handshakes")
            .output()?;

        if !output.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to run 'wg show latest_handshake'"))
        }

        let s = str::from_utf8(&output.stdout).expect("Failed to parse'wg show latest_handshake'");

        let mut peers = std::collections::HashMap::new();
        for l in s.lines() {
            let key_time: Vec<&str> = l.splitn(2, '\t').collect();
            let (key, time) = (key_time[0], key_time[1]);

            let key = base64::decode(key).expect("wg reported an invalid peer");
            let key = PublicKey(key[..].try_into().expect("public_key has incorrect length"));

            let ts = time.parse().expect("number expected");
            let ts = if ts == 0 { None } else { Some(SystemTime::UNIX_EPOCH + Duration::from_secs(ts)) };

            peers.insert(key, ts);
        }

        Ok(peers)
    }

    pub fn next_handshake(&self) -> std::io::Result<Option<Duration>> {
        let now = SystemTime::now();
        let latest_handshake = self.latest_handshake()?;
        let persistent_keepalive = self.persistent_keepalive()?;

        let mut min = None;
        for (pkey, hs) in latest_handshake.into_iter() {
            let hs = hs.unwrap_or(UNIX_EPOCH);
            let hs = now.duration_since(hs).unwrap_or_default();
            let diff = persistent_keepalive[&pkey].checked_sub(hs).unwrap_or_default();
            if diff <= min.unwrap_or(diff) {
                min = Some(diff);
            }
        }

        if min.unwrap_or_default() == Duration::default() {
            println!("{} next handshake: {:?}", Colour::Yellow.paint("FWD"), min);
        } else {
            println!("{} next handshake: {:?}", Colour::White.dimmed().paint("FWD"), min);
        }
        Ok(min)
    }

    pub fn persistent_keepalive(&self) -> std::io::Result<HashMap<PublicKey, Duration>> {
        let output = Command::new("wg")
            .arg("show")
            .arg(&self.name)
            .arg("persistent-keepalive")
            .output()?;

        if !output.status.success() {
            return Err(Error::new(ErrorKind::Other, "Failed to run 'wg show persistent-keepalive'"))
        }

        let s = str::from_utf8(&output.stdout).expect("Failed to parse'wg show persistent-keepalive'");

        let mut peers = std::collections::HashMap::new();
        for l in s.lines() {
            let key_time: Vec<&str> = l.splitn(2, '\t').collect();
            let (key, time) = (key_time[0], key_time[1]);

            let key = base64::decode(key).expect("wg reported an invalid peer");
            let key = PublicKey(key[..].try_into().expect("public_key has incorrect length"));

            let ts = time.parse().expect("number expected");
            let ts = Duration::from_secs(ts);

            peers.insert(key, ts);
        }

        Ok(peers)
    }
}
