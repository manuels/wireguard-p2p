use std::net::SocketAddr;
use std::net::IpAddr;
use std::io::Cursor;
use std::io::Read;
use std::io::Error;
use std::time::Duration;
use std::io::ErrorKind;

use bytes::BytesMut;
use bytes::Bytes;
use bytes::BufMut;
use byteorder::{BigEndian, ReadBytesExt};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;

use netlink_wg::WG_KEY_LEN;

pub fn encode_public_keys<T, U>(key1: T, key2: U) -> Bytes
    where T: AsRef<[u8]>,
          U: AsRef<[u8]>
{
    assert_eq!(key1.as_ref().len(), WG_KEY_LEN);
    assert_eq!(key2.as_ref().len(), WG_KEY_LEN);

    let mut key = BytesMut::with_capacity(256);
    key.put("wg-p2p-addr-v3");
    key.put_slice(key1.as_ref());
    key.put_slice(key2.as_ref());
    key.freeze()
}

pub fn encode_addr(time: Duration, addr: SocketAddr) -> Bytes {
    let mut value = BytesMut::with_capacity(256);
    value.put("wg-p2p-addr-v3");

    value.put_u64_be(time.as_secs());

    match addr.ip() {
        IpAddr::V4(ip) => {
            value.put_u8(0x04);
            value.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            value.put_u8(0x06);
            value.put_slice(&ip.octets());
        }
    }
    value.put_u16_be(addr.port());

    value.freeze()
}

pub fn decode_addr(buf: &[u8]) -> Result<(Duration, SocketAddr), Error> {
    let mut c = Cursor::new(buf);

    let expected = b"wg-p2p-addr-v3";
    let mut actual = [0u8; 14];
    c.read_exact(&mut actual[..])?;

    let version_match = &actual != expected;

    let time = c.read_u64::<BigEndian>()?;
    let time = Duration::from_secs(time);

    let ip_version = c.read_u8()?;
    let ip = match ip_version {
        0x04 => {
            let mut addr = [0u8; 4];
            c.read_exact(&mut addr)?;
            IpAddr::V4(addr.into())
        }
        0x06 => {
            let mut addr = [0u8; 16];
            c.read_exact(&mut addr)?;
            IpAddr::V6(addr.into())
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid IP version"))
    };
    let port = c.read_u16::<BigEndian>()?;

    if !version_match {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid magic data"))
    }

    Ok((time, (ip, port).into()))
}

pub fn encode_key_and_psk(key: &secretbox::Key,
                          salt: &pwhash::Salt,
                          public_key: &box_::PublicKey,
                          local_psk: &[u8])
    -> Vec<u8>
{
    let nonce = secretbox::gen_nonce();

    let mut msg = BytesMut::with_capacity(512);
    msg.put("wg-p2p-key-v3");

    msg.put(&public_key[..]);
    msg.put(&local_psk[..]);

    let ciphertext = secretbox::seal(&msg[..], &nonce, &key);

    let mut value = BytesMut::with_capacity(512);
    value.put(&nonce[..]);
    value.put(&salt[..]);
    value.put(&ciphertext[..]);

    value.freeze().to_vec()
}

pub fn decode_key_and_psk(local_secret: &[u8],
                          remote_secret: &[u8],
                          value: Vec<u8>)
    -> Option<(box_::PublicKey, [u8; 32])>
{
    let res: std::io::Result<_> = try {
        let mut c = Cursor::new(value);

        let mut nonce = secretbox::Nonce::from_slice(&[0u8; secretbox::NONCEBYTES]).unwrap();
        let secretbox::Nonce(ref mut buf) = nonce;
        c.read_exact(buf)?;

        let mut salt = pwhash::Salt::from_slice(&[0u8; pwhash::SALTBYTES]).unwrap();
        let pwhash::Salt(ref mut buf) = salt;
        c.read_exact(buf)?;

        let mut ciphertext = vec![];
        c.read_to_end(&mut ciphertext)?;

        let mut shared_key = secretbox::Key::from_slice(&[0u8; secretbox::KEYBYTES]).unwrap();
        let secretbox::Key(ref mut kb) = shared_key;
        pwhash::derive_key(kb, &[remote_secret, local_secret].concat(), &salt,
                        pwhash::OPSLIMIT_INTERACTIVE,
                        pwhash::MEMLIMIT_INTERACTIVE).unwrap();

        let msg = secretbox::open(&ciphertext, &nonce, &shared_key);
        let msg = if let Ok(m) = msg {
            m
        } else {
            return None
        };
        let mut c = Cursor::new(msg);

        let expected = b"wg-p2p-key-v3";
        let mut actual = [0u8; 13];

        c.read_exact(&mut actual[..])?;

        let version_match = &actual == expected;

        let mut public_key = box_::PublicKey::from_slice(&[0u8; box_::PUBLICKEYBYTES]).unwrap();
        let box_::PublicKey(ref mut buf) = public_key;
        c.read_exact(buf)?;

        let mut psk = [0u8; 32];
        c.read_exact(&mut psk)?;

        if !version_match {
            return None;
        }

        (public_key, psk)
    };

    res.ok()
}
