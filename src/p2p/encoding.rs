use std::net::SocketAddr;
use std::net::IpAddr;
use std::io::Cursor;
use std::io::Read;
use std::io::Error;
use std::time::Duration;
use std::io::ErrorKind;

use bytes::BytesMut;
use bytes::Bytes;
use bytes::BufMut;
use byteorder::{BigEndian, ReadBytesExt};

use netlink_wg::WG_KEY_LEN;

pub fn encode_public_keys<T, U>(key1: T, key2: U) -> Bytes
    where T: AsRef<[u8]>,
          U: AsRef<[u8]>
{
    assert_eq!(key1.as_ref().len(), WG_KEY_LEN);
    assert_eq!(key2.as_ref().len(), WG_KEY_LEN);

    let mut key = BytesMut::with_capacity(256);
    key.put("wg-p2p-addr-v3");
    key.put_slice(key1.as_ref());
    key.put_slice(key2.as_ref());
    key.freeze()
}

pub fn encode_addr(time: Duration, addr: SocketAddr) -> Bytes {
    let mut value = BytesMut::with_capacity(256);
    value.put("wg-p2p-addr-v3");

    value.put_u64_be(time.as_secs());

    match addr.ip() {
        IpAddr::V4(ip) => {
            value.put_u8(0x04);
            value.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            value.put_u8(0x06);
            value.put_slice(&ip.octets());
        }
    }
    value.put_u16_be(addr.port());

    value.freeze()
}

pub fn decode_addr(buf: &[u8]) -> Result<(Duration, SocketAddr), Error> {
    let mut c = Cursor::new(buf);

    let expected = b"wg-p2p-addr-v3";
    let mut actual = [0u8; 14];
    c.read_exact(&mut actual[..])?;

    let version_match = &actual == expected;

    let time = c.read_u64::<BigEndian>()?;
    let time = Duration::from_secs(time);

    let ip_version = c.read_u8()?;
    let ip = match ip_version {
        0x04 => {
            let mut addr = [0u8; 4];
            c.read_exact(&mut addr)?;
            IpAddr::V4(addr.into())
        }
        0x06 => {
            let mut addr = [0u8; 16];
            c.read_exact(&mut addr)?;
            IpAddr::V6(addr.into())
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid IP version"))
    };
    let port = c.read_u16::<BigEndian>()?;

    if !version_match {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid magic data"))
    }

    Ok((time, (ip, port).into()))
}
