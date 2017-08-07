use std::rc::Rc;

use futures::Future;
use futures::future::result;

use tokio_core::reactor::Handle;

use dbus::Connection;
use dbus::BusType;
use dbus::Message;
use dbus_tokio::AConnection;

use BoxedFuture;

use errors::Error;
use errors::ResultExt;

pub struct BulletinBoard;

const DBUS_DEST: &'static str = "org.manuel.BulletinBoard";
const DBUS_IFACE: &'static str = "org.manuel.BulletinBoard";
const DBUS_OBJ_PATH: &'static str = "/";
const APP_ID: &'static str = "wg-p2p";

impl BulletinBoard {
    pub fn get<'a>(handle: Handle, key: &'a [u8]) -> BoxedFuture<Vec<Vec<u8>>> {
        let err = || "Unable to establish D-Bus connection";
        let conn = Connection::get_private(BusType::Session);
        let conn = box_try!(conn.chain_err(err));

        let err = || "Unable to establish D-Bus connection (II)";
        let aconn = AConnection::new(Rc::new(conn), handle);
        let aconn = box_try!(aconn.chain_err(err));

        let err = || "Failed to create D-Bus message";
        let msg = Message::new_method_call(DBUS_DEST, DBUS_OBJ_PATH, DBUS_IFACE, "Get");
        let msg = box_try!(msg.map_err(Error::from).chain_err(err));
        let msg = msg.append2(APP_ID, key);

        let err = || "D-Bus method call failed.";
        let future = aconn.method_call(msg);
        let future = box_try!(future.map_err(Error::from).chain_err(err));

        let future = future.then(move |res| {
            drop(aconn);

            let res = res.chain_err(|| "D-Bus call failed!");

            let err = || "Failed to convert D-Bus result".into();
            let res = res.and_then(|msg| msg.get1().ok_or_else(err));
            result(res)
        });

        Box::new(future)
    }

    pub fn insert<'a>(handle: Handle, key: &'a [u8], value: &'a [u8]) -> BoxedFuture<()> {
        let err = || "Unable to establish D-Bus connection";
        let conn = Connection::get_private(BusType::Session);
        let conn = box_try!(conn.chain_err(err));

        let err = || "Unable to establish D-Bus connection (II)";
        let aconn = AConnection::new(Rc::new(conn), handle);
        let aconn = box_try!(aconn.chain_err(err));

        let err = || "Failed to create D-Bus message";
        let msg = Message::new_method_call(DBUS_DEST, DBUS_OBJ_PATH, DBUS_IFACE, "Put");
        let msg = box_try!(msg.map_err(Error::from).chain_err(err));
        let msg = msg.append3(APP_ID, key, value);

        let err = || "D-Bus method call failed.";
        let future = aconn.method_call(msg);
        let future = box_try!(future.map_err(Error::from).chain_err(err));

        let future = future.then(move |res| {
            drop(aconn);

            result(res.chain_err(|| "D-Bus call failed!"))
        });

        Box::new(future.map(|_| ()))
    }
}
