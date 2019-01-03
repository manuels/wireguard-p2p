#![feature(pin)]
#![feature(await_macro, async_await, futures_api)]
#![feature(try_blocks)]
#![feature(custom_attribute)]

#[macro_use] extern crate log;
#[macro_use] extern crate clap;
#[macro_use] extern crate tokio;

use std::io;
use std::io::Write;
use std::net::ToSocketAddrs;

use tokio::prelude::*;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::verify::verify_32;

macro_rules! log_err {
    ($expr: expr) => ({
        log_err!($expr, "{:?}")
    });
    ($expr: expr, $msg: expr) => ({
        if let Err(err) = $expr {
            error!($msg, err);
        }
    });
}

mod wg;
mod dht;
mod utils;
mod crypto;
mod args;
mod dht_encoding;

use crate::dht::Dht;
use crate::utils::tokio_try_async;
use crate::args::CmdExchangeArgs;

fn xor_slices<T, U>(slice1: T, slice2: U) -> Vec<u8>
    where T: AsRef<[u8]>, U: AsRef<[u8]>
{
    let slice1 = slice1.as_ref();
    let slice2 = slice2.as_ref();

    assert_eq!(slice1.len(), slice2.len());

    slice1.iter().zip(slice2).map(|(a,b)| a ^ b).collect()
}

static DESCRIPTION1: &'static str = "Key exchange is based on two shared secrets. These \
shared secrets have six code words each and must be shared with the other peer through \
an outside channel (e.g. via phone).

  Your shared secret is:  ";

static DESCRIPTION2: &'static str = "

Please enter the other peer's shared secret:
";

pub async fn exchange_keys(dht: Dht, local_secret_key: &box_::SecretKey)
{
    let local_public_key = local_secret_key.public_key();
    let local_secret = crate::crypto::rand(8);

    let mut mn_local_secret = Vec::new();
    mnemonic::encode_with_format(&local_secret, "x x x  -  ", &mut mn_local_secret).unwrap();
    let mn_local_secret = std::str::from_utf8(&mn_local_secret).unwrap();

    println!("{}{}{}", DESCRIPTION1, mn_local_secret, DESCRIPTION2);

    let remote_secret = loop {
        let mut input = String::new();
        let mut remote_secret = vec![];

        print!(">> ");
        io::stdout().flush().unwrap();
        match io::stdin().read_line(&mut input)
        {
            Ok(_n) => {
                match mnemonic::decode(input, &mut remote_secret) {
                    Ok(n) if n == 8 => if local_secret != remote_secret {
                        break remote_secret
                    } else {
                        println!("This is your shared secret, stupid!");
                    }
                    Ok(_) => println!("Shared secret must have 6 code words."),
                    Err(error) => println!("error: {}", error),
                }
            },
            Err(error) => println!("error: {}", error),
        }
    };

    let zero_salt = pwhash::Salt::from_slice(&[0; pwhash::SALTBYTES]).unwrap();

    let local_salt = loop {
        let salt = pwhash::gen_salt();

        let pwhash::Salt(ref buf1) = salt;
        let pwhash::Salt(ref buf2) = zero_salt;

        if !verify_32(buf1, buf2) {
            break salt;
        }
    };

    let mut dht_put_key = [0u8; 32];
    pwhash::derive_key(&mut dht_put_key, &[local_secret.clone(), remote_secret.clone()].concat(), &zero_salt,
                       pwhash::OPSLIMIT_INTERACTIVE,
                       pwhash::MEMLIMIT_INTERACTIVE).unwrap();
    let mut dht_get_key = [0u8; 32];
    pwhash::derive_key(&mut dht_get_key, &[remote_secret.clone(), local_secret.clone()].concat(), &zero_salt,
                       pwhash::OPSLIMIT_INTERACTIVE,
                       pwhash::MEMLIMIT_INTERACTIVE).unwrap();

    let mut local_shared_key = secretbox::Key([0u8; secretbox::KEYBYTES]);
    let secretbox::Key(ref mut kb) = local_shared_key;
    pwhash::derive_key(kb, &[local_secret.clone(), remote_secret.clone()].concat(), &local_salt,
                       pwhash::OPSLIMIT_INTERACTIVE,
                       pwhash::MEMLIMIT_INTERACTIVE).unwrap();

    let local_psk = crate::crypto::rand(32);
    let dht_put_value = dht_encoding::encode_key_and_psk(&local_shared_key,
        &local_salt, &local_public_key, &local_psk);

    let dht2 = dht.clone();
    tokio::spawn_async(async move {
        await!(dht2.put_key_loop(&dht_put_key[..], &dht_put_value));
    });

    let mut stream = dht.listen(&dht_get_key[..])
        .filter_map(|value|
        {
            dht_encoding::decode_key_and_psk(&local_secret, &remote_secret, value)
        });

    println!("Looking for remote peer's public key...");
    if let Some(Ok((remote_public_key, remote_psk))) = await!(stream.next()) {
        let shared_secret = if local_secret < remote_secret {
            [&local_public_key[..], &remote_public_key[..]].concat()
        } else {
            [&remote_public_key[..], &local_public_key[..]].concat()
        };

        println!("");
        println!("Remote peer's public key found!");
        println!("");

        let psk = xor_slices(&local_psk, &remote_psk);

        let bishop = drunken_bishop::drunken_bishop(&shared_secret[..],
            drunken_bishop::OPENSSL, drunken_bishop::BoxMode::Ascii);
        let bishop: Vec<_> = bishop.lines().skip(1).collect();

        println!("+-- Shared  Key --+");
        println!("{}", bishop.join("\n"));
        println!("");

        if local_secret < remote_secret {
            println!("  Your public key:  {}", base64::encode(&local_public_key));
            println!("  THEIR public key: {}", base64::encode(&remote_public_key));
        } else {
            println!("  THEIR public key: {}", base64::encode(&remote_public_key));
            println!("  Your public key:  {}", base64::encode(&local_public_key));
        };

        println!("");
        println!("Optional pre-shared key: {}", base64::encode(&psk[..]));
        println!("");
        println!("Done. Hit Ctrl+C when the other side is, too.");
    }
}

fn main() -> std::io::Result<()> {
    let args = CmdExchangeArgs::parse();

    let bootstrap_addrs: Vec<_> = args.bootstrap_addrs.to_socket_addrs()?.collect();

    tokio_try_async(async move {
        println!("Bootstrapping...");
        let dht = await!(dht::Dht::new(&bootstrap_addrs, args.dht_port))?;

        let netns = args.netns;
        let mut all_ifaces = await!(crate::wg::Interface::get_wg_interfaces(netns.clone()))?;

        let wg_iface = if let Some(ifname) = args.ifname {
            all_ifaces.into_iter()
                .filter(|i| i.ifname == ifname)
                .next()
                .unwrap_or_else(|| panic!("Interface {} not found!", ifname))
        } else {
            let mut iter = all_ifaces.into_iter();
            let iface = iter.next()
                .unwrap_or_else(|| panic!("No WireGuard interface found!"));

            if iter.next().is_some() {
                panic!("More than WireGuard interface found!");
            }

            iface
        };

        let family = await!(crate::wg::Interface::get_family("wireguard"))?;
        let family = family.unwrap_or_else(|| panic!("Wireguard kernel module not loaded"));

        let mut wg_iface = crate::wg::Interface::new(family, netns, wg_iface.ifindex)?;
        let wg_cfg = await!(wg_iface.get_config())?;
        let secret_key = wg_cfg.private_key();

        let secret_key = box_::SecretKey::from_slice(&secret_key[..]).unwrap();
        await!(exchange_keys(dht, &secret_key));

        Ok(()) as std::io::Result<()>
    });

    Ok(())
}
