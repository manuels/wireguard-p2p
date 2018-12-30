use std::io::Error;
use std::io::ErrorKind;

use futures::sync::mpsc;
use futures::Stream;
use tokio::prelude::*;

pub fn tokio_try_async<E: std::fmt::Debug>(f: impl std::future::Future<Output=Result<(), E>> + Send + 'static) {
    tokio::run_async(async move {
        if let Err(err) = await!(f) {
            panic!("{:?}", err);
        }
    });
}

/// Convert a nix::Error to a std::io::Error
pub fn nix2io(error: nix::Error) -> Error {
    match error {
        nix::Error::Sys(errno) => Error::from_raw_os_error(errno as _),
        nix::Error::InvalidPath => Error::new(ErrorKind::InvalidInput, "Invalid Path"),
        nix::Error::InvalidUtf8 => Error::new(ErrorKind::InvalidInput, "Invalid Utf8"),
        nix::Error::UnsupportedOperation => Error::new(ErrorKind::Other, "Invalid Operation"),
    }
}

pub trait CloneStream: Stream
where
    Self::Item: Clone + Send
{
    fn clone_stream(self) -> (mpsc::UnboundedReceiver<Self::Item>, mpsc::UnboundedReceiver<Self::Item>);
}

impl<T: StreamExt + std::marker::Unpin + Send + 'static> CloneStream for T
where T::Item: Clone + Send,
    T::Error: std::fmt::Debug + Send
{
    fn clone_stream(mut self) -> (mpsc::UnboundedReceiver<Self::Item>, mpsc::UnboundedReceiver<Self::Item>)
    {
        let (mut tx1, rx1) = mpsc::unbounded();
        let (mut tx2, rx2) = mpsc::unbounded();

        tokio::spawn_async(async move {
            while let Some(res) = await!(self.next()) {
                match res {
                    Ok(item1) => {
                        let item2 = item1.clone();
                        log_err!(await!(tx1.send_async(item1)), "CloneSender Error 1: {:?}");
                        log_err!(await!(tx2.send_async(item2)), "CloneSender Error 2: {:?}");
                    },
                    Err(err) => error!("ClonedReceiver Error: {:?}", err)
                }
            }
        });

        (rx1, rx2)
    }
}

pub trait CloneSink: Sink
where
    Self::SinkItem: Send
{
    fn clone_sink(self) -> (mpsc::UnboundedSender<Self::SinkItem>, mpsc::UnboundedSender<Self::SinkItem>);
}

impl<T: SinkExt + std::marker::Unpin + Send + 'static> CloneSink for T
where T::SinkItem: Send,
    T::SinkError: std::fmt::Debug + Send
{
    fn clone_sink(mut self) -> (mpsc::UnboundedSender<Self::SinkItem>, mpsc::UnboundedSender<Self::SinkItem>)
    {
        let (tx1, rx1) = mpsc::unbounded();
        let (tx2, rx2) = mpsc::unbounded();

        let mut rx = rx1.select(rx2);
        tokio::spawn_async(async move {
            while let Some(res) = await!(rx.next()) {
                match res {
                    Ok(item) => {
                        log_err!(await!(self.send_async(item)), "CloneSender Error 1: {:?}");
                    },
                    Err(err) => error!("CloneSender Error: {:?}", err)
                }
            }
        });

        (tx1, tx2)
    }
}
