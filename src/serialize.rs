use std::time::Duration;
use std::time::SystemTime;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV6;

use bytes::Buf;
use bytes::BufMut;

use crate::utils::IntoIpv6;
use crate::utils::MaybeIntoIpv4;

pub fn deserialize(buf: impl AsRef<[u8]>) -> Option<(SystemTime, SocketAddr)> {
    let mut buf = buf.as_ref();

    if buf.remaining() < std::mem::size_of::<u16>() {
        return None
    }

    let version = 0x0001;
    if buf.get_u16() != version {
        println!("b {}", buf.remaining());
        return None
    }

    if buf.remaining() < std::mem::size_of::<u64>() {
        return None
    }

    let time = buf.get_u64();
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(time);

    if buf.remaining() < std::mem::size_of::<u128>() {
        return None
    }

    let ip = buf.get_u128().into();

    if buf.remaining() < std::mem::size_of::<u16>() {
        return None
    }

    let port = buf.get_u16();

    let addr = SocketAddrV6::new(ip, port, 0, 0);
    Some((time, addr.maybe_into_ipv4()))
}

pub fn serialize(addr: Option<SocketAddr>) -> bytes::BytesMut {
    let mut buf = bytes::BytesMut::with_capacity(256);

    let version = 0x0001;
    buf.put_u16(version);

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("SytemTime error");
    let now = now.as_secs();
    buf.put_u64(now);

    let addr = addr.unwrap_or((Ipv6Addr::UNSPECIFIED, 0).into());
    let addr_v6 = addr.into_ipv6();

    buf.put_u128((*addr_v6.ip()).into());
    buf.put_u16(addr_v6.port());

    buf
}
