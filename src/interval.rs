use std::time::Duration;

use futures::Future;
use futures::Sink;
use futures::Stream;
use futures::future::ok;

use tokio_core::reactor::Handle;
use tokio_core::reactor::Timeout;

use BoxedFuture;
use MsgPair;
use errors::Error;

pub struct Interval {
    dur: Duration,
    handle: Handle,
}

impl Interval {
    pub fn new(handle: Handle, dur: Duration) -> Interval {
        Interval { dur, handle }
    }

    pub fn run<F, R>(
        self,
        sink: Box<Sink<SinkItem = MsgPair, SinkError = Error>>,
        stream: Box<Stream<Item = MsgPair, Error = Error>>,
        new_job: F,
    ) -> BoxedFuture<()>
    where
        F: Send
            + Fn(Handle,
           Box<Sink<SinkItem = MsgPair, SinkError = Error>>,
           Box<Stream<Item = MsgPair, Error = Error>>)
           -> R
            + 'static,
        R: Future<
            Item = (Box<Sink<SinkItem = MsgPair, SinkError = Error>>,
                    Box<Stream<Item = MsgPair, Error = Error>>),
            Error = (Box<Sink<SinkItem = MsgPair, SinkError = Error>>,
                     Box<Stream<Item = MsgPair, Error = Error>>,
                     Error),
        >
            + 'static,
    {
        let timeout = Timeout::new(self.dur, &self.handle);
        let timeout = box_try!(timeout.map_err(
            |e| Error::with_chain(e, "Creating Timeout failed"),
        ));

        let future = new_job(self.handle.clone(), sink, stream);
        let future = future.then(|result| {
            // TODO log error
            match result {
                Ok((sink, stream)) => ok((sink, stream)),
                Err((sink, stream, _)) => ok((sink, stream)),
            }
        });

        let future = future.and_then(move |(sink, stream)| {
            timeout.then(move |_| {
                self.run(sink, stream, new_job).map_err(|e| {
                    Error::with_chain(e, "Interval::run() failed")
                })
            })
        });

        Box::new(future)
    }
}
