mod codec;

use slog::{info, debug};

use std::net::SocketAddr;
use std::time::Instant;
use std::time::Duration;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use rand::Rng;
use rand::SeedableRng;

use async_std::prelude::*;
use async_std::sync::Mutex;

//pub const NETWORK_UNREACHABLE: i32 = 101;

use crate::stun::codec::*;
use crate::utils::UdpSender;
use crate::utils::UdpReceiver;

lazy_static::lazy_static! {
    static ref RNG: Mutex<rand::rngs::SmallRng> = Mutex::new(rand::rngs::SmallRng::from_entropy());
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Connectivity {
    OpenInternet(SocketAddr),
    FullConeNat(SocketAddr),
    SymmetricNat,
    RestrictedPortNat(SocketAddr),
    RestrictedConeNat(SocketAddr),
    SymmetricFirewall(SocketAddr),
}

impl Into<Option<SocketAddr>> for Connectivity {
    fn into(self) -> Option<SocketAddr> {
        match self {
            Connectivity::OpenInternet(addr) => Some(addr),
            Connectivity::FullConeNat(addr) => Some(addr),
            Connectivity::SymmetricNat => None,
            Connectivity::RestrictedPortNat(addr) => Some(addr),
            Connectivity::RestrictedConeNat(addr) => Some(addr),
            Connectivity::SymmetricFirewall(addr) => Some(addr),
        }
    }
}

pub struct Stun;

#[async_trait::async_trait]
impl crate::api::Stun for Stun {
    async fn lookup_public_address(&self, stun_log: &slog::Logger,
                                   mut to_inet_tx: &mut UdpSender,
                                   mut from_inet_rx: &mut UdpReceiver,
                                   stun_server: SocketAddr) -> anyhow::Result<Connectivity> {
        let bind_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let addr: Option<SocketAddr>;
        let conn = check(stun_log, &mut to_inet_tx, &mut from_inet_rx, bind_addr, stun_server).await?;
        Ok(conn)
    }
}


async fn check(stun_log: &slog::Logger,
               mut to_inet_tx: &mut UdpSender,
               mut from_inet_rx: &mut UdpReceiver,
               bind_addr: IpAddr,
               stun_server: SocketAddr,
) -> Result<Connectivity, anyhow::Error> {
    let resp = change_request(&mut to_inet_tx, &mut from_inet_rx, stun_server, ChangeRequest::None).await?;
    if let Some(Response::Bind(resp)) = resp {
        let public_addr = resp.mapped_address;

        if bind_addr == public_addr.ip() {
            debug!(stun_log,
                "No NAT. Public IP ({}) == Bind IP ({})",
                bind_addr,
                public_addr.ip()
            );
            let resp = change_request(&mut to_inet_tx, &mut from_inet_rx, stun_server, ChangeRequest::IpAndPort).await?;
            if resp.is_some() {
                info!(stun_log, "OpenInternet: {}", public_addr);
                return Ok(Connectivity::OpenInternet(public_addr));
            } else {
                info!(stun_log, "SymmetricFirewall: {}", public_addr);
                return Ok(Connectivity::SymmetricFirewall(public_addr));
            }
        }
        debug!(stun_log, "Public IP ({}) != Bind IP ({})", bind_addr, public_addr.ip());

        // NAT detected
        let resp = change_request(&mut to_inet_tx, &mut from_inet_rx, stun_server, ChangeRequest::IpAndPort).await?;
        if resp.is_some() {
            info!(stun_log, "FullConeNat: {}", public_addr);
            return Ok(Connectivity::FullConeNat(public_addr));
        }

        debug!(stun_log, "No respone from different IP and Port");
        let resp = change_request(&mut to_inet_tx, &mut from_inet_rx, stun_server, ChangeRequest::Port).await?;
        if let Some(Response::Bind(resp)) = resp {
            if resp.mapped_address.ip() != public_addr.ip() {
                info!(stun_log, "SymmetricNat");
                return Ok(Connectivity::SymmetricNat);
            }

            let resp = change_request(&mut to_inet_tx, &mut from_inet_rx, stun_server, ChangeRequest::Port).await?;
            if resp.is_some() {
                info!(stun_log, "RestrictedConeNat: {}", public_addr);
                Ok(Connectivity::RestrictedConeNat(public_addr))
            } else {
                info!(stun_log, "RestrictedPortNat: {}", public_addr);
                Ok(Connectivity::RestrictedPortNat(public_addr))
            }
        } else {
            let msg = format!("Expected Some(BindResponse) but got {:?} instead!", resp);
            todo!()
            //Err(std::io::Error::new(ErrorKind::InvalidData, msg))
        }
    } else {
        todo!()
//        Err(std::io::Error::from_raw_os_error(NETWORK_UNREACHABLE))
    }
}

async fn change_request(
    to_inet_tx: &mut UdpSender,
    from_inet_rx: &mut UdpReceiver,
    stun_server: SocketAddr,
    req: ChangeRequest,
) -> Result<Option<Response>, anyhow::Error> {
    let req = codec::Request::Bind(BindRequest {
        change_request: req,
        ..Default::default()
    });

    send_request(to_inet_tx, from_inet_rx, stun_server, req).await
}

async fn send_request(
    to_inet_tx: &mut UdpSender,
    from_inet_rx: &mut UdpReceiver,
    stun_server: SocketAddr,
    req: Request,
) -> Result<Option<Response>, anyhow::Error> {
    let mut lock = RNG.lock().await;
    let id: u64 = lock.gen();

    let mut buf = bytes::BytesMut::new();
    StunCodec::encode((id, req), &mut buf)?;
    to_inet_tx.send((buf.to_vec(), stun_server)).await?;

    let start = Instant::now();

    loop {
        let dur = Duration::from_secs(10).checked_sub(Instant::now() - start);
        let dur = dur.unwrap_or(Duration::from_secs(0));
        match async_std::future::timeout(dur, from_inet_rx.next()).await {
            Err(e) => return Ok(None),
            Ok(None) => return Ok(None),
            Ok(Some((buf, src))) => {
                if let Some((actual_id, resp)) = StunCodec::decode_const(&buf)? {
                    if actual_id == id {
                        return Ok(Some(resp));
                    }
                } else {
                    continue
                }
            }
        }
    }
}
