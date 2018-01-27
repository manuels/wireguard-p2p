use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey;

pub fn serialize_public_key<V>(public_key: V) -> Vec<u8>
    where V: AsRef<[u8]>
{
    let public_key = public_key.as_ref();
    let hash = sha256::hash(public_key);
    [&hash[..], public_key].concat()
}

pub fn deserialize_public_key<V>(value: V) -> Option<PublicKey>
    where V: AsRef<[u8]>
{
    let value = value.as_ref();
    if value.len() != 32 + 32 {
        return None;
    }

    let (actual_hash, public_key) = value.split_at(32);

    let expected_hash = sha256::hash(public_key);
    let actual_hash = sha256::Digest::from_slice(actual_hash);

    if Some(expected_hash) == actual_hash {
        PublicKey::from_slice(public_key)
    } else {
        None
    }
}

use std::rc::Rc;
use errors::Result;
use dbus::Connection;
use dbus::BusType;
use dbus::Message;
use futures::prelude::*;
use tokio_core::reactor::Handle;
use dbus_tokio::AConnection;

const DBUS_DEST: &'static str = "org.manuel.BulletinBoard";
const DBUS_IFACE: &'static str = "org.manuel.BulletinBoard";
const DBUS_OBJ_PATH: &'static str = "/";
const APP_ID: &'static str = "wg-p2p";

pub struct Dht {
    aconn: AConnection,
}

impl Dht {
  pub fn new(handle: Handle) -> Result<Dht>
    {
        let conn = Connection::get_private(BusType::Session)?;
        let aconn = AConnection::new(Rc::new(conn), handle)?;

        Ok(Dht { aconn })
    }

    #[async]
    pub fn insert(self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let msg = Message::new_method_call(DBUS_DEST, DBUS_OBJ_PATH,
                                           DBUS_IFACE, "Put")?;
        let msg = msg.append3(APP_ID, key, value);

        await!(self.aconn.method_call(msg)?)?;
        Ok(())
    }

    #[async]
    pub fn get(self, key: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        let msg = Message::new_method_call(DBUS_DEST, DBUS_OBJ_PATH,
                                           DBUS_IFACE, "Get")?;
        let msg = msg.append2(APP_ID, key);

        let resp = await!(self.aconn.method_call(msg)?)?;
        if let Some(values) = resp.get1() {
            Ok(values)
        } else {
            Err("Failed to convert D-Bus result".into())
        }
    }
}

