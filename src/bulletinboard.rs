use std::rc::Rc;

use futures::Future;
use futures::future::result;

use tokio_core::reactor::Handle;

use dbus::Connection;
use dbus::BusType;
use dbus::Message;
use dbus_tokio::AConnection;

use errors::Error;
use errors::Result;
use errors::ResultExt;

type BoxedFuture<T> = Box<Future<Item=T,Error=Error>>;

pub struct BulletinBoard;

const DBUS_DEST: &'static str = "org.manuel.BulletinBoard";
const DBUS_IFACE: &'static str = "org.manuel.BulletinBoard";
const DBUS_OBJ_PATH: &'static str = "/";
const APP_ID: &'static str = "wg-p2p";

impl BulletinBoard {
    pub fn get<'a>(handle: Handle, key: &'a [u8]) -> BoxedFuture<Vec<Vec<u8>>> {
        let func = || -> Result<_> {
            let conn = Connection::get_private(BusType::Session).chain_err(|| "Unable to establish D-Bus connection")?;
            let aconn = AConnection::new(Rc::new(conn), handle).chain_err(|| "Unable to establish D-Bus connection (II)")?;

            let msg = Message::new_method_call(DBUS_DEST, DBUS_OBJ_PATH, DBUS_IFACE, "Get").unwrap();//chain_err(|| "Failed to create D-Bus message")?;
            let msg = msg.append2(APP_ID, key);

            let future = aconn.method_call(msg).unwrap(); //.chain_err(|| "D-Bus method call failed.")?;
            let future = future.then(move |res| {
                drop(aconn);

                let res = res.chain_err(|| "D-Bus call failed!");
                result(res)
            }).and_then(|res| {
                result(res.get1().ok_or_else(|| "Failed to convert D-Bus result".into()))
            });

            Ok(future)
        };

        Box::new(result(func()).flatten())
    }

    pub fn insert<'a>(handle: Handle, key: &'a [u8], value: &'a [u8]) -> BoxedFuture<()> {
        let func = || -> Result<_> {
            let conn = Connection::get_private(BusType::Session).chain_err(|| "Unable to establish D-Bus connection")?;
            let aconn = AConnection::new(Rc::new(conn), handle).chain_err(|| "Unable to establish D-Bus connection (II)")?;

            let msg = Message::new_method_call(DBUS_DEST, DBUS_OBJ_PATH, DBUS_IFACE, "Put").unwrap();//chain_err(|| "Failed to create D-Bus message")?;
            let msg = msg.append3(APP_ID, key, value);

            let future = aconn.method_call(msg).unwrap(); //.chain_err(|| "D-Bus method call failed.")?;
            let future = future.then(move |res| {
                drop(aconn);

                let res = res.chain_err(|| "D-Bus call failed!");
                result(res)
            });

            Ok(future.map(|_| ()))
        };

        Box::new(result(func()).flatten())
    }
}

