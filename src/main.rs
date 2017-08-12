#![recursion_limit = "1024"]

macro_rules! box_try {
    ($e:expr) => (match $e {
        Ok(t) => t,
        Err(e) => return Box::new(::futures::future::err(e.into())),
    })
}

extern crate futures;
extern crate tokio_core;
extern crate docopt;

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate stun3489;
extern crate dbus;
extern crate dbus_tokio;
extern crate byteorder;
extern crate ini;
extern crate sodiumoxide;
extern crate base64;

#[macro_use]
extern crate error_chain;

mod errors {
    error_chain!{}
}

use errors::ResultExt;

mod wg;
mod dht;
mod crypto;
mod search;
mod publish;
mod interval;
mod duplicate;
mod serialization;
#[macro_use]
mod report_errors;
#[macro_use]
mod daemon;
mod bulletinboard;

use std::net::SocketAddr;

use futures::Future;

use docopt::Docopt;

use daemon::daemon;
use search::search;
use publish::publish;

type MsgPair = (Vec<u8>, SocketAddr);

type BoxedFuture<T> = Box<Future<Item = T, Error = errors::Error>>;

const USAGE: &'static str = "
WireGuard Peer-to-Peer Tool

Usage: wg-p2p search <peer_name>
       wg-p2p publish <interface> <peer_name>
       wg-p2p daemon [--config=<path>]

Options:
    -c, --config=<path>  Path to config file [default: /etc/wireguard-p2p.conf].
";

fn main() {
    if let Err(ref e) = main_() {
        println!("error: {}", e);

        for e in e.iter().skip(1) {
            println!("caused by: {}", e);
        }

        if let Some(backtrace) = e.backtrace() {
            println!("backtrace: {:?}", backtrace);
        }

        ::std::process::exit(1);
    }
}

fn main_() -> errors::Result<()> {
    env_logger::init().chain_err(|| "Failed to init env_logger")?;

    let argv = std::env::args();
    let args = Docopt::new(USAGE)
        .and_then(|d| d.argv(argv).parse())
        .unwrap_or_else(|e| e.exit());

    if args.get_bool("search") {
        let peer_name = args.get_str("<peer_name>").to_string();
        search(peer_name)
    } else if args.get_bool("publish") {
        let interface = args.get_str("<interface>").to_string();
        let peer_name = args.get_str("<peer_name>").to_string();

        publish(interface, peer_name)
    } else if args.get_bool("daemon") {
        let conf_path = args.get_str("--config").to_string();
        daemon(conf_path)
    } else {
        unreachable!()
    }
}
