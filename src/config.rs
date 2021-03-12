use slog::debug;
use async_trait::async_trait;
use async_std::prelude::*;
use wireguard_uapi::RouteSocket;

use crate::api;
use crate::api::*;
use crate::wg_device::WireguardDev;

pub struct Config {
    log: slog::Logger,
    pub opendht_port: u16,
    interfaces: Option<Vec<String>>,
}

impl Config {
    pub fn new(log: slog::Logger) -> anyhow::Result<Config> {
        let matches = clap::App::new("wiregurad-p2p")
            .arg(clap::Arg::with_name("interfaces")
                .short("i")
                .long("ifnames")
                .takes_value(true)
                .help("Restrict to these devices [default: all]"))
            .arg(clap::Arg::with_name("opendht_port")
                .short("P")
                .default_value("4222")
                .help("OpenDHt listen port"))
            .get_matches();

        let interfaces = matches.value_of("interfaces").map(|ifnames| {
            ifnames.split(',').map(String::from).collect()
        });

        let opendht_port = matches.value_of("opendht_port").unwrap();
        let opendht_port = str::parse(opendht_port)?;

        Ok(Config {
            opendht_port,
            interfaces,
            log
        })
    }
}

#[async_trait]
impl api::ConfigApi for Config {
    fn get_wireguard_devices(&self) -> anyhow::Result<Box<dyn Stream<Item=(Box<dyn WireguardDevice>, DeviceConfig)> + Unpin>> {
        if let Some(ref ifnames) = self.interfaces {
            let vec: Result<Vec<_>, _> = ifnames.into_iter().map(|ifname| WireguardDev::new(ifname.to_string()).map(|d| d.as_trait())).collect();
            let it = vec?.into_iter().map(|dev| (dev, DeviceConfig {}));
            let s = futures::stream::iter(it);
            return Ok(Box::new(s));
        }

        debug!(self.log, "RouteSocket::connect()...");
        let mut c = RouteSocket::connect()?;
        debug!(self.log, "RouteSocket::connect() done.");

        let vec: anyhow::Result<Vec<Box<dyn WireguardDevice>>>;
        vec = c.list_device_names()?
            .into_iter()
            .map(|ifname| WireguardDev::new(ifname).map(|d| d.as_trait()))
            .collect();
        debug!(self.log, "Found {:?} devices.", vec.as_ref().map(|v| v.len()));

        let it = vec?.into_iter().map(|dev| (dev, DeviceConfig {}));

        let stream = futures::stream::iter(it);
        Ok(Box::new(stream))
    }

    async fn get_peers(&self, dev: &dyn WireguardDevice) -> anyhow::Result<Box<dyn Stream<Item=Box<dyn Peer>> + Unpin>> {
        Ok(Box::new(dev.get_peers().await?))
    }
}
