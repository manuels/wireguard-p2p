use futures::Future;
use futures::Stream;
use futures::Sink;
use futures::future::ok;
use futures::future::BoxFuture;
use futures::sync::mpsc::Receiver;
use futures::sync::mpsc::Sender;
use futures::sync::mpsc::channel;

#[allow(dead_code)]
pub fn duplicate_stream<S,I,E>(stream: S)
    -> (BoxFuture<(), E>, Receiver<I>, Receiver<I>)
    where S: 'static + Stream<Item=I, Error=E> + Send,
          I: 'static + Send + Clone,
          E: 'static + Send,
{
    let (mut tx1, rx1) = channel(10);
    let (mut tx2, rx2) = channel(10);

    let future = stream.for_each(move |item| {
        // UDP => AsyncSink::NotReady is ignored in this function

        if let Err(err) = tx1.start_send(item.clone()) {
            unimplemented!()
        }

        if let Err(err) = tx2.start_send(item) {
            unimplemented!()
        }

        if let Err(err) = tx1.poll_complete() {
            unimplemented!()
        }

        if let Err(err) = tx2.poll_complete() {
            unimplemented!()
        }

        ok(())
    });

    (future.boxed(), rx1, rx2)
}

#[allow(dead_code)]
pub fn duplicate_sink<S,I>(sink: S)
    -> (BoxFuture<(), ()>, Sender<I>)
    where S: 'static + Sink<SinkItem=I, SinkError=()> + Send,
          I: 'static + Send + Clone,
{
    let (tx, rx) = channel(10);

    let future = rx.forward(sink);
    let future = future.map(|_| ());

    (future.boxed(), tx)
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

