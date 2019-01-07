use clap::App;
use clap::Arg;

pub struct InterfaceArgs {
    pub ifname: String,
    pub peers: Option<Vec<Vec<u8>>>,
    pub netns: Option<String>,
}

pub struct CmdArgs {
    pub verbose: bool,
    pub default_netns: Option<String>,
    pub default_peers: Vec<Vec<u8>>,
    pub interfaces: Option<Vec<InterfaceArgs>>,
    pub stun_server: String,
    pub dht_port: u16,
    pub bootstrap_addrs: String,
}

impl CmdArgs {
    pub fn parse() -> CmdArgs {
        let m = App::new("wg-p2p")
            .version("0.1.990")
            .arg(Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Be more verbose"))
            .arg(Arg::with_name("stun_server")
                .short("s")
                .long("stun")
                .help("STUN 3578 server")
                .default_value("stun.wtfismyip.com:3478"))
            .arg(Arg::with_name("dht_port")
                .short("D")
                .long("dht")
                .default_value("4222")
                .help("Client port for OpenDHT"))
            .arg(Arg::with_name("dht_supernode")
                .short("B")
                .long("bootstrap")
                .help("Bootstrap using this OpenDHT supernode")
                .default_value("bootstrap.ring.cx:4222"))
            .arg(Arg::with_name("netns")
                .help("Linux network namespace of the WireGuard interface(s) [default: none]")
                .short("N")
                .long("netns")
                .takes_value(true)
                .multiple(true))
            .arg(Arg::with_name("ifname")
                .help("Network interface(s) to manage [default: all]")
                .short("i")
                .long("iface")
                .takes_value(true)
                .multiple(true))
            .arg(Arg::with_name("public_key")
                .help("Handle endpoint to these peers [default: all]")
                .short("p")
                .long("peers")
                .takes_value(true)
                .multiple(true))
            .get_matches();

        let iface_iter = if let Some(indices) = m.indices_of("ifname") {
            indices.zip(m.values_of("ifname").unwrap()).collect()
        } else {
            vec![]
        };
        let netns_iter = if let Some(indices) = m.indices_of("netns") {
            indices.zip(m.values_of("netns").unwrap()).collect()
        } else {
            vec![]
        };
        let peers_iter = if let Some(indices) = m.indices_of("peers") {
            indices.zip(m.values_of("peers").unwrap()).collect()
        } else {
            vec![]
        };

        let mut iface_iter = iface_iter.iter().peekable();
        let mut netns_iter = netns_iter.into_iter();
        let mut peers_iter = peers_iter.into_iter();

        let mut default_netns = None;
        let mut default_peers = vec![];

        let mut args = vec![];
        while let Some((ii, ifname)) = iface_iter.next() {
            let mut netns = None;
            while let Some((ni, netns_cur)) = netns_iter.next() {
                // at least we have a netns
                if ni > *ii {
                    // it is for this interface or a succeeding interface
                    let (iii, _) = iface_iter.peek().unwrap_or(&&(std::usize::MAX, ""));
                    if *iii > ni  {
                        // it must be for this interface
                        // but maybe there is another one...
                        netns = Some(netns_cur.to_string());
                    } else {
                        // it is for the next interface
                        break
                    }
                } else {
                    // it is for a previous interface => must be the default
                    // but maybe there is also one for this interface
                    default_netns.get_or_insert(netns_cur.to_string());
                }
            }
            netns = netns.or_else(|| default_netns.clone());

            let mut peers = vec![];
            while let Some((pi, peer)) = peers_iter.next() {
                let peer = base64::decode(peer).unwrap_or_else(|_| panic!("Invalid public key {}", peer));

                if pi > *ii {
                    let (iii, _) = iface_iter.peek().unwrap_or(&&(std::usize::MAX, ""));
                    if *iii > pi  {
                        peers.push(peer);
                    } else {
                        break
                    }
                } else {
                    default_peers.push(peer);
                }
            }
            let peers = if peers.is_empty() && !default_peers.is_empty() {
                Some(default_peers.clone())
            } else {
                None
            };

            args.push(InterfaceArgs {
                ifname: ifname.to_string(),
                netns: netns,
                peers,
            });
        };

        CmdArgs {
            default_netns,
            default_peers,
            verbose: m.is_present("verbose"),
            interfaces: if args.is_empty() { None } else { Some(args) },
            stun_server: value_t!(m, "stun_server", String).unwrap(),
            dht_port: value_t!(m, "dht_port", u16).unwrap(),
            bootstrap_addrs: value_t!(m, "dht_supernode", String).unwrap(),
        }
    }
}
