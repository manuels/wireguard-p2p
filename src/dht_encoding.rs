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

pub fn encode_key(key1: &[u8], key2: &[u8]) -> Bytes {
    let mut key = BytesMut::with_capacity(256);
    key.put("wg-p2p-v3");
    key.put_slice(key1);
    key.put_slice(key2);
    key.freeze()
}

pub fn encode_value(time: Duration, addr: SocketAddr) -> Bytes {
    let mut value = BytesMut::with_capacity(256);
    value.put("wg-p2p-v3");

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

pub fn decode_value(buf: &[u8]) -> Result<(Duration, SocketAddr), Error> {
    let mut c = Cursor::new(buf);

    let expected = b"wg-p2p-v3";
    let mut actual = [0u8; 9];
    c.read_exact(&mut actual[..])?;

    if &actual != expected {
        return Err(Error::new(ErrorKind::InvalidInput, "TODO"));
    }

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
        _ => return Err(Error::new(ErrorKind::InvalidInput, "TODO"))
    };
    let port = c.read_u16::<BigEndian>()?;

    Ok((time, (ip, port).into()))
}