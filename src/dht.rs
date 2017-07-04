use std::io;
use std::io::Read;
use std::io::Cursor;
use std::io::ErrorKind;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::Ipv6Addr;

use byteorder::NetworkEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;

use futures::Stream;
use futures::Sink;
use futures::Future;
use futures::future::ok;
use futures::future::BoxFuture;
use futures::future::FutureResult;

use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::SecretKey;
use sodiumoxide::crypto::box_::Nonce;

use stun3489;
use stun3489::Connectivity;

use errors::*;
use errors::Error;

use MsgPair;
use catch_and_report_error;
use bulletinboard::BulletinBoard;

use wg::WireGuardConfig;
use wg::PublicKey;

fn encode_addr(addr: SocketAddr) -> Result<Vec<u8>> {
    let (ip, port) = match addr {
        SocketAddr::V4(a) => (a.ip().to_ipv6_compatible(), a.port()),
        SocketAddr::V6(a) => (a.ip().clone(), a.port()),
    };

    let mut vec = ip.octets().to_vec();
    vec.write_u16::<NetworkEndian>(port).chain_err(|| "Failed to write port")?;

    Ok(vec)
}

fn decode_addr<R:Read>(mut rdr: R) -> Result<SocketAddr> {
    let mut addr = [0; 16];
    rdr.read_exact(&mut addr).chain_err(|| "No IP address")?;
    let ip_v6 = Ipv6Addr::from(addr);

    let port = rdr.read_u16::<NetworkEndian>().chain_err(|| "No port")?;

    if let Some(ip_v4) = ip_v6.to_ipv4() {
        Ok(SocketAddrV4::new(ip_v4, port).into())
    } else {
        Ok(SocketAddrV6::new(ip_v6, port, 0, 0).into())
    }
}

fn dht_encode(c: &Connectivity) -> Result<Vec<u8>> {
    let now = match UNIX_EPOCH.elapsed() {
        Ok(duration) => duration,
        Err(err) => return Err(err).chain_err(|| "SystemTime is invalid"),
    };

    let (nat_type, addr) = match *c {
        Connectivity::OpenInternet(addr)      => (1, Some(addr)),
        Connectivity::FullConeNat(addr)       => (2, Some(addr)),
        Connectivity::SymmetricNat            => (3, None),
        Connectivity::RestrictedPortNat(addr) => (4, Some(addr)),
        Connectivity::RestrictedConeNat(addr) => (5, Some(addr)),
        Connectivity::SymmetricFirewall(addr) => (6, Some(addr)),
        Connectivity::UdpBlocked              => (7, None),
    };

    let mut value = vec![0x02]; // version
    value.write_u64::<NetworkEndian>(now.as_secs()).unwrap();
    value.push(nat_type);
    if let Some(addr) = addr {
        value.append(&mut encode_addr(addr)?);
    }

    Ok(value)
}

fn dht_decode(msg: Vec<u8>) -> Result<(u64, Connectivity)> {
    let mut c = Cursor::new(msg);

    let version = c.read_u8().chain_err(|| "Error reading version")?;
    if version != 2 {
        return Err("Invalid version".into());
    }

    let unix_time = c.read_u64::<NetworkEndian>().chain_err(|| "Error reading time stamp")?;

    let nat_type = match c.read_u8().chain_err(|| "Error reading NAT type")? {
        1 => Connectivity::OpenInternet(decode_addr(&mut c)?),
        2 => Connectivity::FullConeNat(decode_addr(&mut c)?),
        3 => Connectivity::SymmetricNat,
        4 => Connectivity::RestrictedPortNat(decode_addr(&mut c)?),
        5 => Connectivity::RestrictedConeNat(decode_addr(&mut c)?),
        6 => Connectivity::SymmetricFirewall(decode_addr(&mut c)?),
        7 => Connectivity::UdpBlocked,
        _ => return Err("Invalid NAT type".into()),
    };

    Ok((unix_time, nat_type))
}

fn dht_encrypt<'a>(secret_key: &'a SecretKey,
                   public_key: &'a PublicKey,
                   msg: &'a [u8]) -> Vec<u8>
{
    let nonce = box_::gen_nonce();
    let m = box_::seal(msg, &nonce, &public_key, &secret_key);

    [&nonce[..], &m[..]].concat().to_vec()
}

fn dht_decrypt<'a>(secret_key: &'a SecretKey,
                   public_key: &'a PublicKey,
                   msg: &'a [u8]) -> Result<Vec<u8>>
{
    let n = 24;
    let m = 44;

    if msg.len() != n + m {
        return Err("Message does not have the right length!".into());
    }

    let (nonce, msg) = msg.split_at(n);

    let nonce = Nonce::from_slice(nonce).ok_or_else(|| "Nonce is not 24 byte")?;
    match box_::open(&msg, &nonce, &public_key, &secret_key) {
        Ok(msg) => Ok(msg),
        Err(()) => Err("Decryption failed!".into()),
    }
}

pub fn stun_publish<SI,ST,E>(handle: Handle,
                             sink: SI,
                             stream: ST,
                             interface: String,
                             remote_key: PublicKey)
    -> BoxFuture<(),()>
    where SI: Sink<SinkItem=MsgPair, SinkError=E> + Send + 'static,
          ST: Stream<Item=MsgPair, Error=E> + Send + 'static,
{
    let timeout = Duration::from_secs(1);
    let bind_addr = "0.0.0.0:0".parse().unwrap();
    let server = "192.95.17.62:3478".parse().unwrap(); // stun.callwithus.com

    // TODO: filter stream for stun messages
    let stream = stream.map_err(|_| io::Error::new(ErrorKind::Other, ""));
    let sink = sink.sink_map_err(|_| io::Error::new(ErrorKind::Other, ""));

    let stun = stun3489::stun3489_generic(stream.boxed(),
                                          Box::new(sink),
                                          bind_addr,
                                          server,
                                          &handle,
                                          timeout);
    let stun = stun.and_then(|(stream, sink, conn)| {
        info!("{:?} detected.", conn);
        ok((stream, sink, conn))
    });

    let remote = handle.remote().clone();
    let dht_publish = move |(stream, sink, c)| {
        let iface = interface.clone();
        remote.clone().spawn(move |handle| {
            let future = catch_and_report_error(move || {
                let cfg = WireGuardConfig::new(&interface[..]).chain_err(|| "Reading WireGuard config failed.")?;
                let local_key = cfg.interface.public_key().chain_err(|| "Failed getting our public key.")?;

                let key = [&local_key[..], &remote_key[..]].concat();
                let value = dht_encode(&c).chain_err(|| "Encoding DHT message failed.")?;
                let value = dht_encrypt(&cfg.interface.secret_key, &remote_key, &value[..]);

                let future = BulletinBoard::insert(handle.clone(), &key[..], &value[..]);
                let future = future.then(move |res| {
                    if let Err(e) = res {
                        warn!("Publishing Connectivity failed: {:?}", e);
                    } else {
                        debug!("Connectivity published.");
                    }
                    ok(()) as FutureResult<(),()>
                });

                debug!("Publishing connectivity...");
                Ok(future)
            });

            future.flatten().then(move |_| {
                remote.clone().spawn(move |handle| {
                    let timeout = Timeout::new(Duration::from_secs(5*60), &handle).unwrap();
                    timeout.then(move |_| {
                        remote.spawn(move |handle| {
                            stun_publish(handle.clone(), sink, stream, iface, remote_key)
                        });

                        ok(())
                    })
                });

                ok(())
            })
        });
        ok(())
    };

    stun.and_then(dht_publish).map(|_| ()).map_err(|_| ()).boxed()
}

pub fn dht_get(handle: Handle, interface: String, remote_key: PublicKey)
    -> Result<Box<Future<Item=Option<Connectivity>, Error=Error>>>
{
    let cfg = WireGuardConfig::new(&interface[..]).chain_err(|| "Reading WireGuard config failed.")?;
    let local_key = cfg.interface.public_key().chain_err(|| "Failed getting our public key.")?;

    let key = [&remote_key[..], &local_key[..]].concat();
    let future = BulletinBoard::get(handle, &key[..]);

    let future = future.and_then(move |value_list| {
        info!("value_list len={}", value_list.len());
        info!("value_list[0] len={:?}", value_list.get(0).map(|x| x.len()));
        let value_list = value_list.into_iter();
        let value_list = value_list.filter_map(|v| dht_decrypt(&cfg.interface.secret_key, &remote_key, &v[..]).ok());
        let value_list = value_list.filter_map(|r| dht_decode(r).ok());

        let mut value_list: Vec<_> = value_list.collect();
        value_list.sort_by_key(|t| t.0);

        let mut value_list = value_list.into_iter().map(|t| t.1);
        Ok(value_list.next())
    });

    Ok(Box::new(future))
}

