use std::io::Error;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::process::Command;

use tokio_process::CommandExt;

// TODO: use netlink interface instead
pub async fn set_endpoint<'a>(
    iface: &'a str,
    remote_public_key: &'a [u8],
    addr: SocketAddr
) -> Result<(), Error>
{
    let key = base64::encode(remote_public_key);
    let addr = format!("{}:{}", addr.ip(), addr.port());

    let cmd = Command::new("sudo")
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
