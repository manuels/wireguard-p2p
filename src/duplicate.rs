use futures::Future;
use futures::Stream;
use futures::Sink;
use futures::future::result;
use futures::sync::mpsc::Receiver;
use futures::sync::mpsc::Sender;
use futures::sync::mpsc::channel;

use tokio_core::reactor::Handle;

use errors::Error;
use errors::ResultExt;

pub fn duplicate_stream<S, I>(handle: &Handle, stream: S) -> (Receiver<I>, Receiver<I>)
where
    S: 'static + Stream<Item = I, Error = Error>,
    I: 'static + Send + Clone,
{
    let (mut tx1, rx1) = channel(10);
    let (mut tx2, rx2) = channel(10);

    let future = stream.for_each(move |item| {
        // UDP => AsyncSink::NotReady is ignored in this function

        let res11 = tx1.start_send(item.clone()).chain_err(
            || "start_send to tx1 failed",
        );
        let res21 = tx2.start_send(item.clone()).chain_err(
            || "start_send to tx2 failed",
        );
        let res12 = tx1.poll_complete().chain_err(
            || "poll_complete() to tx1 failed",
        );
        let res22 = tx2.poll_complete().chain_err(
            || "poll_complete() to tx2 failed",
        );

        result(res11.and(res21).and(res12).and(res22).and(Ok(())))
    });

    let future = future.map(|_| ()).map_err(|_| ());
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
    let future = future.map(|_| ());
    handle.spawn(future);

    tx
}

#[test]
fn test_duplicate_stream() {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use tokio_core::reactor::Core;

    let (tx, rx) = channel(10);

    let mut core = Core::new().unwrap();

    let (f1, rx1, rx2) = duplicate_stream(rx);

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

    let f = tx.send(42);
    core.handle().spawn(f.map(|_| ()).map_err(|_| ()));

    core.run(f1.join3(f2, f3)).unwrap();

    assert!(received1.load(Ordering::SeqCst));
    assert!(received2.load(Ordering::SeqCst));
}
