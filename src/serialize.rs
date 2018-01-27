use std::io::Read;
use std::io::Write;
use std::time::UNIX_EPOCH;
use std::time::Duration;
use std::time::SystemTime;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::Ipv6Addr;

use byteorder::NetworkEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;

use stun3489::Connectivity;

use errors::Result;

pub trait Serialize: Sized {
    fn serialize<W: Write>(&self, wrt: &mut W) -> Result<()>;
    fn deserialize<R: Read>(rdr: &mut R) -> Result<Self>;
}

impl Serialize for SocketAddr {
    fn serialize<W: Write>(&self, wrt: &mut W) -> Result<()> {
        let (ip, port) = match *self {
            SocketAddr::V4(a) => (a.ip().to_ipv6_compatible(), a.port()),
            SocketAddr::V6(a) => (*a.ip(), a.port()),
        };

        wrt.write_all(&ip.octets())?;
        wrt.write_u16::<NetworkEndian>(port)?;

        Ok(())
    }

    fn deserialize<R: Read>(rdr: &mut R) -> Result<Self> {
        let ip_v6: Ipv6Addr;
        let mut addr = [0; 16];

        rdr.read_exact(&mut addr)?;
        let port = rdr.read_u16::<NetworkEndian>()?;

        ip_v6 = addr.into();
        if let Some(ip_v4) = ip_v6.to_ipv4() {
            Ok(SocketAddrV4::new(ip_v4, port).into())
        } else {
            Ok(SocketAddrV6::new(ip_v6, port, 0, 0).into())
        }
    }
}

impl Serialize for (SystemTime, Connectivity) {
    fn serialize<W: Write>(&self, mut wrt: &mut W) -> Result<()> {
        let &(now, ref c) = self;

        let delta = now.duration_since(UNIX_EPOCH)?;

        let (nat_type, addr) = match *c {
            Connectivity::OpenInternet(addr) => (1, Some(addr)),
            Connectivity::FullConeNat(addr) => (2, Some(addr)),
            Connectivity::SymmetricNat => (3, None),
            Connectivity::RestrictedPortNat(addr) => (4, Some(addr)),
            Connectivity::RestrictedConeNat(addr) => (5, Some(addr)),
            Connectivity::SymmetricFirewall(addr) => (6, Some(addr)),
        };

        wrt.write_u8(0x02)?;
        wrt.write_u64::<NetworkEndian>(delta.as_secs())?;
        wrt.write_u8(nat_type)?;

        if let Some(addr) = addr {
            addr.serialize(&mut wrt)?;
        }

        Ok(())
    }

    fn deserialize<R: Read>(mut rdr: &mut R) -> Result<Self> {
        let version = rdr.read_u8()?;

        if version != 2 {
            return Err("Invalid version".into());
        }

        let unix_time = rdr.read_u64::<NetworkEndian>()?;

        let time = UNIX_EPOCH + Duration::from_secs(unix_time);

        let nat_type = match rdr.read_u8()? {
            1 => Connectivity::OpenInternet(SocketAddr::deserialize(&mut rdr)?),
            2 => Connectivity::FullConeNat(SocketAddr::deserialize(&mut rdr)?),
            3 => Connectivity::SymmetricNat,
            4 => Connectivity::RestrictedPortNat(SocketAddr::deserialize(&mut rdr)?),
            5 => Connectivity::RestrictedConeNat(SocketAddr::deserialize(&mut rdr)?),
            6 => Connectivity::SymmetricFirewall(SocketAddr::deserialize(&mut rdr)?),
            _ => return Err("Invalid NAT type".into()),
        };

        Ok((time, nat_type))
    }
}
