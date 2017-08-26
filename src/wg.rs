use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::process::Stdio;
use std::process::Command;
use std::iter::FromIterator;

use base64;

use ini::Ini;
use ini::ini::Properties;

pub use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
pub use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

use errors::Result;

pub struct Peer {
    public_key: PublicKey,
    interface: String,
    pub endpoint: Option<SocketAddr>,
}

impl Peer {
    fn parse(interface: String, props: &Properties) -> Result<Peer> {
        let err = || "[Peer] section contains no 'PublicKey'";
        let public_key = props.get("PublicKey").ok_or_else(err)?;

        let public_key = base64::decode(public_key)?;

        let err = || "Invalid PublicKey value";
        let public_key = PublicKey::from_slice(&public_key[..32]).ok_or_else(err)?;

        let endpoint = if let Some(s) = props.get("Endpoint") {
            Some(s.parse()?)
        } else {
            None
        };

        Ok(Peer {
            public_key,
            interface,
            endpoint,
        })
    }

    pub fn set_endpoint(&self, addr: SocketAddr) -> Result<()> {
        let output = Command::new("sudo")
            .arg("/usr/bin/wg")
            .arg("set")
            .arg(&self.interface)
            .arg("peer")
            .arg(base64::encode(&self.public_key[..]))
            .arg("endpoint")
            .arg(format!("{}", addr))
            .output()?;

        ensure!(output.status.success(), "Failed to set enpoint");

        Ok(())
    }
}

pub struct WireGuardConfig {
    pub secret_key: SecretKey,
    pub listen_port: u16,
    pub peers: HashMap<PublicKey, Peer>,
}

impl WireGuardConfig {
    pub fn new(interface: &str) -> Result<WireGuardConfig> {
        let output = Command::new("sudo")
            .arg("/usr/bin/wg")
            .arg("showconf")
            .arg(interface)
            .output()?;

        let msg = String::from_utf8_lossy(&output.stderr);
        ensure!(output.status.success(), "/usr/bin/wg failed: {}", msg);

        let ini = String::from_utf8_lossy(&output.stdout);
        Self::parse(interface, ini.into())
    }

    fn parse(iface: &str, s: String) -> Result<WireGuardConfig> {
        let mut interface = None;
        let mut peer_list = Vec::new();
        let mut peer_hdr = Some("Peer");

        for txt in s.split("[Peer]") {
            let ini = Ini::load_from_str(&txt[..])?;

            if let Some(sect) = ini.section(Some("Interface")) {
                interface = Some(Self::parse_interface(sect)?);
            }

            if let Some(sect) = ini.section(peer_hdr.take()) {
                let iface = iface.to_string();
                peer_list.push(Peer::parse(iface, sect)?);
            }
        }

        let peer_list = peer_list.into_iter().map(|p| (p.public_key, p));
        let peer_list = HashMap::from_iter(peer_list);

        let err = || "No [Interface] section found";
        let interface = interface.ok_or_else(err)?;

        Ok(WireGuardConfig {
            secret_key: interface.0,
            listen_port: interface.1,
            peers: peer_list,
        })
    }

    fn parse_interface(props: &Properties) -> Result<(SecretKey, u16)> {
        let err = || "[Interface] section contains no 'PrivateKey'";
        let secret_key = props.get("PrivateKey").ok_or_else(err)?;

        let secret_key = base64::decode(secret_key)?;

        let err = || "Invalid PrivateKey value";
        let secret_key = SecretKey::from_slice(&secret_key).ok_or_else(err)?;

        let err = || "[Interface] section contains no 'ListenPort'";
        let listen_port = props.get("ListenPort").ok_or_else(err)?;
        let listen_port = listen_port.parse::<u16>()?;

        Ok((secret_key, listen_port))
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let process = Command::new("sudo")
            .arg("/usr/bin/wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let b64_key = base64::encode(&self.secret_key[..]);

        let err = || "wg: Failed to open stdin";
        let mut stdin = process.stdin.ok_or_else(err)?;

        stdin.write_all(b64_key.as_bytes())?;
        drop(stdin);

        let err = || "wg: Failed to open stdout";
        let mut stdout = process.stdout.ok_or_else(err)?;

        let mut buf = [0; 44];
        stdout.read_exact(&mut buf)?;

        let pubkey = base64::decode(&buf[..])?;

        let err = || "Decoding public key failed!";
        let pubkey = PublicKey::from_slice(&pubkey[..32]).ok_or_else(err)?;

        Ok(pubkey)
    }
}

#[test]
fn test_valid() {
    let ini = "[Interface]
Address = 10.0.0.25
PrivateKey = GBKsd3x+RCOc0t98XVAoRxlrauAHgATCgjr7vBeI5HM=
ListenPort = 50465

[Peer]
PersistentKeepalive = 60
PublicKey = zFGMqsiDRLI4tNhCfbn4O80ATfruc9iQ9nwJnPlW8jQ=
AllowedIPs = 10.0.0.0/24
Endpoint = 127.0.0.1:8123

[Peer]
PersistentKeepalive = 60
PublicKey = uAyF0vu7AvEW8IAc4FjG4NhoOoGhlqGu5iLzIcM332U=
AllowedIPs = 10.0.0.0/24
Endpoint = 127.0.0.1:8124
";

    let cfg = WireGuardConfig::parse("wg0", ini.to_string()).unwrap();
    assert!(cfg.listen_port != 0);
    assert_eq!(cfg.peers.len(), 2);
}
