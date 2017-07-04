use std::process::Stdio;
use std::process::Command;
use std::net::SocketAddr;
use std::str::FromStr;
use std::io::Write;
use std::io::Read;
use std::collections::HashMap;
use std::iter::FromIterator;

use base64;

use ini::Ini;
use ini::ini::Properties;

pub use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey;
pub use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

use errors::*;

pub struct Interface {
    pub secret_key: SecretKey,
    pub listen_port: u16,
}

impl Interface {
    fn parse(props: &Properties) -> Result<Interface> {
        let secret_key = props.get("PrivateKey").ok_or_else(|| "[Interface] section contains no 'PrivateKey'")?;
        let secret_key = base64::decode(secret_key).chain_err(|| "PrivateKey is not valid base64")?;
        let secret_key = SecretKey::from_slice(&secret_key[..32]).ok_or_else(|| "Invalid PrivateKey value")?;

        let listen_port = props.get("ListenPort").ok_or_else(|| "[Interface] section contains no 'ListenPort'")?;
        let listen_port = listen_port.parse::<u16>().chain_err(|| "ListenPort is invalid")?;

        Ok(Interface {
            secret_key,
            listen_port,
        })
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        let process = Command::new("/usr/bin/wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .chain_err(|| "failed to execute /usr/bin/wg")?;

        let b64_key = base64::encode(&self.secret_key[..]);
        let mut stdin = process.stdin.ok_or_else(|| "wg: Failed to open stdin")?;
        stdin.write_all(b64_key.as_bytes()).chain_err(|| "Error writing to stdin")?;
        drop(stdin);

        let mut s = String::new();
        let mut stdout = process.stdout.ok_or_else(|| "wg: Failed to open stdout")?;
        stdout.read_to_string(&mut s).chain_err(|| "wg: Reading stdout failed")?;;

        let pubkey = base64::decode(&s.trim()[..]).chain_err(|| "Base64-decoding public key failed!")?;
        let pubkey = PublicKey::from_slice(&pubkey[..32]).ok_or_else(|| "Decoding public key failed!")?;
        Ok(pubkey)
    }
}

pub struct Peer {
    public_key: PublicKey,
    pub endpoint: Option<SocketAddr>,
}

impl Peer {
    fn parse(props: &Properties) -> Result<Peer> {
        let public_key = props.get("PublicKey").ok_or_else(|| "[Peer] section contains no 'PublicKey'")?;
        let public_key = base64::decode(public_key).chain_err(|| "PublicKey is not valid base64")?;
        let public_key = PublicKey::from_slice(&public_key[..32]).ok_or_else(|| "Invalid PublicKey value")?;

        let endpoint = props.get("Endpoint");
//        let endpoint = endpoint.map(|s| SocketAddr::from_str(s).chain_err(|| "Invalid address")?);
        let endpoint = endpoint.and_then(|s| SocketAddr::from_str(s).ok());

        Ok(Peer {
            public_key,
            endpoint,
        })
    }

    pub fn set_endpoint<'a>(&self, interface: &'a str, addr: SocketAddr) -> Result<()> {
        let output = Command::new("/usr/bin/sudo")
            .arg("/usr/bin/wg")
            .arg("set")
            .arg(interface)
            .arg("peer")
            .arg(base64::encode(&self.public_key[..]))
            .arg("endpoint")
            .arg(format!("{}", addr))
            .output()
            .chain_err(|| "failed to execute /usr/bin/wg")?;

        if output.status.success() {
            Ok(())
        } else {
            Err("Failed to set enpoint".into())
        }
    }
}

pub struct WireGuardConfig {
    pub interface: Interface,
    pub peers: HashMap<PublicKey, Peer>,
}

impl WireGuardConfig {
    pub fn new<'a>(interface: &'a str) -> Result<WireGuardConfig> {
        let output = Command::new("/usr/bin/sudo")
            .arg("/usr/bin/wg")
            .arg("showconf")
            .arg(interface)
            .output()
            .chain_err(|| "failed to execute /usr/bin/wg")?;

        if !output.status.success() {
            let msg = String::from_utf8_lossy(&output.stderr);
            let msg = format!("/usr/bin/wg returned a failure: {:?}", msg);
            return Err(msg.into());
        }

        let ini = String::from_utf8_lossy(&output.stdout);
        Self::parse(ini.into())
    }

    fn parse(s: String) -> Result<WireGuardConfig> {
        let mut interface = None;
        let mut peer_list = Vec::new();

        for (i, txt) in s.split("[Peer]").enumerate() {
            let ini = if i == 0 { txt.to_string() }
                      else { format!("[Peer]{}", txt) };

            let ini = Ini::load_from_str(&ini[..]);
            let ini = ini.chain_err(|| "Parsing INI failed")?;

            if let Some(sect) = ini.section(Some("Interface")) {
                interface = Some(Interface::parse(sect)?);
            }

            if let Some(sect) = ini.section(Some("Peer")) {
                peer_list.push(Peer::parse(sect)?);
            }
        }

        let peer_list = HashMap::from_iter(peer_list.into_iter().map(|p| (p.public_key, p)));

        let interface = interface.ok_or_else(|| "No [Interface] section found")?;

        Ok(WireGuardConfig {
            interface: interface,
            peers: peer_list,
        })
    }
}

#[test]
fn test_valid () {
    let ini =
"[Interface]
Address = 10.0.0.25
PrivateKey = GBKsd3x+RCOc0t98XVAoRxlrauAHgATCgjr7vBeI5HM=
ListenPort = 50465

[Peer]
PersistentKeepalive = 60
PublicKey = zFGMqsiDRLI4tNhCfbn4O80ATfruc9iQ9nwJnPlW8jQ=
AllowedIPs = 10.0.0.0/24
Endpoint = 127.0.0.1:8123
";

    let cfg = WireGuardConfig::parse(ini.to_string()).unwrap();
    assert!(cfg.interface.listen_port > 0);
    assert_eq!(cfg.peers.len(), 1);
}

