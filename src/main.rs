#![allow(dead_code)]
#![feature(proc_macro, conservative_impl_trait, generators, ip_constructors)]

extern crate docopt;
#[macro_use] extern crate error_chain;
#[macro_use] extern crate log;
extern crate env_logger;
extern crate ini;
extern crate base64;
extern crate sodiumoxide;
extern crate futures_await as futures;
extern crate tokio_core;
extern crate tokio_process;
extern crate dbus;
extern crate dbus_tokio;
extern crate stun3489;
extern crate byteorder;

/// Map a `Future<(),Error>` to `Future<(),()>` and write the error to stderr.
/// Use it for `Handle::spawn()`.
macro_rules! report {
    ($func:expr) => {
        (|| {
            use ::error_chain::ChainedError;
            use ::std::io::Write;

            ($func).then(|res| match res {
                Ok(()) => Ok(()),
                Err(ref e) => {
                    write!(&mut ::std::io::stderr(), "{}", e.display_chain())
                        .expect("Error writing to stderr");
                    Err(())
                }
            })
        })()
    };
}

mod dht;
mod wg_cmd;
mod cmd_daemon;
mod cmd_publish;
mod cmd_search;
mod crypto;
mod serialize;

const USAGE: &'static str = "
WireGuard Peer-to-Peer Tool.

Usage:
  wg-p2p search <peer_name>
  wg-p2p publish <interface> <peer_name>
  wg-p2p daemon [--config=<path>]

Options:
  -c --config=<path>  Path to config file [default: /etc/wireguard-p2p.conf].
";

use docopt::Docopt;
use errors::Result;
use tokio_core::reactor::Core;
use cmd_publish::publish;
use cmd_search::search;
use cmd_daemon::daemon;
use env_logger::{Builder, Target};

mod errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
            Dbus(::dbus::Error);
            Base64(::base64::DecodeError);
            Utf8(::std::str::Utf8Error);
            Ini(::ini::ini::Error);
            ParseInt(::std::num::ParseIntError);
            SystemTime(::std::time::SystemTimeError);
        }
    }
}

quick_main!(run);

fn run() -> Result<()> {
    let mut builder = Builder::new();
    builder.target(Target::Stdout);
    let rust_log = std::env::var("RUST_LOG").unwrap_or("wireguard_p2p=info".to_string());
    builder.parse(&rust_log);
    builder.init();

    let argv = std::env::args();
    let args = Docopt::new(USAGE)
        .and_then(|d| d.argv(argv).parse())
        .unwrap_or_else(|e| e.exit());

    let mut core = Core::new()?;
    let handle = core.handle();

    if args.get_bool("publish") {
        let interface = args.get_str("<interface>").to_string();
        let peer_name = args.get_str("<peer_name>").to_string();
        core.run(publish(handle, interface, peer_name))
    } else if args.get_bool("search") {
        let peer_name = args.get_str("<peer_name>").to_string();
        core.run(search(handle, peer_name))
    } else if args.get_bool("daemon") {
        let cfg_path = args.get_str("--config").to_string();
        core.run(daemon(handle, cfg_path))
    } else {
        unreachable!();
    }
}

