use std::rc::Rc;

use tokio_core::reactor::Handle;

use dbus::Connection;
use dbus::BusType;
use dbus::Message;
use dbus_tokio::AConnection;

use futures::prelude::*;

use errors::Result;

pub struct BulletinBoard;

const DBUS_DEST: &'static str = "org.manuel.BulletinBoard";
const DBUS_IFACE: &'static str = "org.manuel.BulletinBoard";
const DBUS_OBJ_PATH: &'static str = "/";
const APP_ID: &'static str = "wg-p2p";

impl BulletinBoard {
    fn create_message(handle: Handle, method: &str)
        -> Result<(AConnection, Message)>
    {
        let conn = Connection::get_private(BusType::Session)?;
        let aconn = AConnection::new(Rc::new(conn), handle)?;

        let msg = Message::new_method_call(DBUS_DEST, DBUS_OBJ_PATH, DBUS_IFACE,
                                           method)?;

        Ok((aconn, msg))
    }

    #[async]
    pub fn get(handle: Handle, key: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        let (aconn, msg) = Self::create_message(handle, "Get")?;
        let msg = msg.append2(APP_ID, key);

        let resp = await!(aconn.method_call(msg)?)?;

        let r = resp.get1();
        let err = || "Failed to convert D-Bus result".into();
        r.ok_or_else(err)
    }

    #[async]
    pub fn insert(handle: Handle, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let (aconn, msg) = Self::create_message(handle, "Put")?;
        let msg = msg.append3(APP_ID, key, value);

        await!(aconn.method_call(msg)?)?;
        Ok(())
    }
}

