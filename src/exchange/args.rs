use clap::App;
use clap::Arg;

pub struct CmdExchangeArgs {
    pub netns: Option<String>,
    pub ifname: Option<String>,
    pub verbose: bool,
    pub dht_port: u16,
    pub bootstrap_addrs: String,
}

impl CmdExchangeArgs {
    pub fn parse() -> CmdExchangeArgs {
        let m = App::new("wg-exchange")
            .version("0.1.990")
            .about("Exchange WireGuard public keys")
            .arg(Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .help("Be more verbose"))
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
                .help("Linux network namespace of the WireGuard interface [default: none]")
                .short("N")
                .long("netns")
                .takes_value(true))
            .arg(Arg::with_name("ifname")
                .help("Network interface to manage")
                .short("i")
                .long("iface")
                .takes_value(true))
            .get_matches();

        CmdExchangeArgs {
            verbose: m.is_present("verbose"),
            ifname: m.value_of("ifname").map(|s| s.to_string()),
            netns: m.value_of("netns").map(|s| s.to_string()),
            dht_port: value_t!(m, "dht_port", u16).unwrap(),
            bootstrap_addrs: value_t!(m, "dht_supernode", String).unwrap(),
        }
    }
}
