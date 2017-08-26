use futures::Future;
use futures::Stream;
use futures::Sink;
use futures::future::result;
use futures::sync::mpsc::channel;
use futures::sync::mpsc::Receiver;
use futures::sync::mpsc::Sender;

use MsgPair;

use errors::Error;

use tokio_core::reactor::Handle;

pub fn duplicate_stream<S>(handle: &Handle, stream: S) -> (Receiver<MsgPair>, Receiver<MsgPair>)
where
    S: 'static + Stream<Item = MsgPair, Error = Error>
{
    let (mut tx1, rx1) = channel(10);
    let (mut tx2, rx2) = channel(10);

    let future = stream.for_each(move |item| {
        // UDP => AsyncSink::NotReady is ignored in this function

        let res11 = tx1.start_send(item.clone());
        let res21 = tx2.start_send(item);
        let res12 = tx1.poll_complete();
        let res22 = tx2.poll_complete();

        result(res11.and(res21).and(res12).and(res22)
                    .and(Ok(())).map_err(|e| e.into()))
    });

    let future = future.map_err(|_| ());
    handle.spawn(future);

    (rx1, rx2)
}

pub fn duplicate_sink<S, I>(handle: &Handle, sink: S) -> Sender<I>
where
    S: 'static + Sink<SinkItem = I, SinkError = ()>,
    I: 'static + Send + Clone,
{
    let (tx, rx) = channel(10);

    let future = rx.forward(sink);
    handle.spawn(future.map(|_| ()));

    tx
}

#[test]
fn test_duplicate_stream() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use tokio_core::reactor::Core;
    use futures::future::ok;

    let (tx, rx) = channel(10);

    let mut core = Core::new().unwrap();

    let (rx1, rx2) = duplicate_stream(&core.handle(), rx.map_err(|_| "".into()));

    let received1 = Arc::new(AtomicBool::new(false));
    let f2 = rx1.for_each(|_| {
        received1.store(true, Ordering::SeqCst);
        ok(())
    });

    let received2 = Arc::new(AtomicBool::new(false));
    let f3 = rx2.for_each(|_| {
        received2.store(true, Ordering::SeqCst);
        ok(())
    });

    let f = tx.send((vec![], ([0,0,0,0], 0).into()));
    core.handle().spawn(f.map(|_| ()).map_err(|_| ()));

    core.run(f2.join(f3)).unwrap();

    assert!(received1.load(Ordering::SeqCst));
    assert!(received2.load(Ordering::SeqCst));
}
