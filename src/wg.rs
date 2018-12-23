use std::io::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::process::Command;
use regex::Regex;

use tokio_process::CommandExt;

#[derive(Deserialize, Serialize, Clone, PartialEq, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct IfaceConfig {
    pub interface: Interface,
    #[serde(skip)]
    pub peers: Vec<Peer>,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Interface {
    pub listen_port: u16,
    #[serde(skip)]
    pub private_key: String,
}

#[derive(Deserialize, Serialize, Clone, PartialEq, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Peer {
    pub public_key: String,
    #[serde(rename = "AllowedIPs")]
    pub allowed_ips: String,
    pub endpoint: Option<String>,
}

// TODO: use netlink interface instead
pub async fn set_endpoint<'a>(
    netns: Option<String>,
    iface: &'a str,
    remote_public_key: &'a [u8],
    addr: SocketAddr
) -> Result<(), Error>
{
    info!("Setting endpoint {} for peer {} on {}...", addr, base64::encode(remote_public_key), iface);

    let key = base64::encode(remote_public_key);
    let addr = format!("{}:{}", addr.ip(), addr.port());

    let mut cmd = &mut Command::new("sudo");
    if let Some(netns) = netns {
        cmd = cmd.arg("ip").arg("netns").arg("exec").arg(netns);
    }
    let cmd = cmd
            .arg("wg")
            .arg("set")
            .arg(iface)
            .arg("peer")
            .arg(key)
            .arg("endpoint")
            .arg(addr)
            .output_async();
    let out = await!(cmd)?;

    if out.status.success() {
        Ok(())
    } else {
        let msg = std::str::from_utf8(&out.stdout).unwrap();
        Err(Error::new(ErrorKind::InvalidInput, format!("TODO wg: {}", msg)))
    }
}

pub async fn get_config<'a>(netns: Option<String>, iface: &'a str) -> Result<IfaceConfig, Error> {
    let mut cmd = &mut Command::new("sudo");
    if let Some(netns) = netns {
        cmd = cmd.arg("ip").arg("netns").arg("exec").arg(netns);
    }
    let cmd = cmd
            .arg("wg")
            .arg("showconf")
            .arg(iface)
            .output_async();
    let out = await!(cmd)?;

    if out.status.success() {
        let out = std::str::from_utf8(&out.stdout).unwrap();
        let out = out.replace(" = ", "=");

        let mut parts = out.split("[Peer]");

        let interface = parts.next().unwrap();
        let mut cfg: IfaceConfig = serde_ini::from_str(interface).unwrap();

        cfg.peers = parts.map(|s| serde_ini::from_str(s).unwrap()).collect();

        Ok(cfg)
    } else {
        let msg = std::str::from_utf8(&out.stdout).unwrap();
        Err(Error::new(ErrorKind::InvalidInput, format!("TODO wg: {}", msg)))
    }
}

pub async fn get_interfaces(netns: Option<String>) -> Result<Vec<String>, Error> {
    let mut cmd = &mut Command::new("sudo");
    if let Some(netns) = netns {
        cmd = cmd.arg("ip").arg("netns").arg("exec").arg(netns);
    }
    let cmd = cmd
            .arg("ip")
            .arg("link")
            .arg("show")
            .arg("type")
            .arg("wireguard")
            .output_async();
    let out = await!(cmd)?;

    if out.status.success() {
        let out = std::str::from_utf8(&out.stdout).unwrap();

        let re = Regex::new(r"(\d+): ([^:]+): <").unwrap();
        let interfaces = out.lines().filter_map(|line| {
            re.captures(line).map(|c| c.get(2).unwrap().as_str().to_string())
        }).collect();

        Ok(interfaces)
    } else {
        let msg = std::str::from_utf8(&out.stdout).unwrap();
        Err(Error::new(ErrorKind::InvalidInput, format!("TODO wg: {}", msg)))
    }
}

pub async fn local_public_key<'a>(netns: Option<String>, iface: &'a str) -> Result<Vec<u8>, Error> {
    let mut cmd = &mut Command::new("sudo");
    if let Some(netns) = netns {
        cmd = cmd.arg("ip").arg("netns").arg("exec").arg(netns);
    }
    let cmd = cmd
            .arg("wg")
            .arg("show")
            .arg(iface)
            .arg("public-key")
            .output_async();
    let out = await!(cmd)?;

    if out.status.success() {
        let out = std::str::from_utf8(&out.stdout).unwrap();
        let key = base64::decode(&out.trim()).unwrap();
        Ok(key)
    } else {
        let msg = std::str::from_utf8(&out.stdout).unwrap();
        Err(Error::new(ErrorKind::InvalidInput, format!("TODO wg: {}", msg)))
    }
}

pub async fn local_secret_key<'a>(netns: Option<String>, iface: &'a str) -> Result<Vec<u8>, Error> {
    let mut cmd = &mut Command::new("sudo");
    if let Some(netns) = netns {
        cmd = cmd.arg("ip").arg("netns").arg("exec").arg(netns);
    }
    let cmd = cmd
            .arg("wg")
            .arg("show")
            .arg(iface)
            .arg("private-key")
            .output_async();
    let out = await!(cmd)?;

    if out.status.success() {
        let out = std::str::from_utf8(&out.stdout).unwrap();
        let key = base64::decode(&out.trim()).unwrap();
        Ok(key)
    } else {
        let msg = std::str::from_utf8(&out.stdout).unwrap();
        Err(Error::new(ErrorKind::InvalidInput, format!("TODO wg: {}", msg)))
    }
}
