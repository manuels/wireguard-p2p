#![feature(proc_macro, conservative_impl_trait, generators)]
#![recursion_limit = "1024"]

extern crate futures_await as futures;
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
    error_chain!{
        foreign_links {
            Fmt(::std::fmt::Error);
            Io(::std::io::Error);
            Base64(::base64::DecodeError);
            ParseInt(::std::num::ParseIntError);
            ParseAddr(::std::net::AddrParseError);
            Ini(::ini::ini::Error);
            SystemTime(::std::time::SystemTimeError);
            DBus(::dbus::Error);
            Send(::futures::sync::mpsc::SendError<::MsgPair>);
        }
    }
}

use errors::ResultExt;

mod wg;
mod dht;
mod crypto;
mod search;
mod publish;
mod duplicate;
mod serialization;
mod proxy_connection;
#[macro_use]
mod daemon;
mod bulletinboard;

use std::net::SocketAddr;

use docopt::Docopt;

use tokio_core::reactor::Core;

use daemon::daemon;
use search::search;
use publish::publish;

type MsgPair = (Vec<u8>, SocketAddr);

const USAGE: &'static str = "
WireGuard Peer-to-Peer Tool

Usage: wg-p2p search <peer_name>
       wg-p2p publish <interface> <peer_name>
       wg-p2p daemon [--config=<path>]

Options:
    -c, --config=<path>  Path to config file [default: /etc/wireguard-p2p.conf].
";

quick_main!(run);

fn run() -> errors::Result<()> {
    env_logger::init().chain_err(|| "Failed to init env_logger")?;

    let argv = std::env::args();
    let args = Docopt::new(USAGE)
        .and_then(|d| d.argv(argv).parse())
        .unwrap_or_else(|e| e.exit());

    if args.get_bool("search") {
        let mut core = Core::new()?;
        let handle = core.handle();

        let peer_name = args.get_str("<peer_name>").to_string();

        core.run(search(handle, peer_name))
    } else if args.get_bool("publish") {
        let mut core = Core::new()?;
        let handle = core.handle();

        let interface = args.get_str("<interface>").to_string();
        let peer_name = args.get_str("<peer_name>").to_string();

        core.run(publish(handle, interface, peer_name))
    } else if args.get_bool("daemon") {
        let conf_path = args.get_str("--config").to_string();
        daemon(conf_path)
    } else {
        unreachable!()
    }
}
