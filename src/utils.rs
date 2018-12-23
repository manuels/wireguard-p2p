use futures::sync::mpsc;
use futures::Stream;
use tokio::prelude::*;

pub trait CloneReceiver: Stream
where
    Self::Item: Clone + Send
{
    fn clone_stream(self) -> (mpsc::UnboundedReceiver<Self::Item>, mpsc::UnboundedReceiver<Self::Item>);
}

impl<T: StreamExt + std::marker::Unpin + Send + 'static> CloneReceiver for T
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

pub trait CloneSender: Sink
where
    Self::SinkItem: Send
{
    fn clone_sink(self) -> (mpsc::UnboundedSender<Self::SinkItem>, mpsc::UnboundedSender<Self::SinkItem>);
}

impl<T: SinkExt + std::marker::Unpin + Send + 'static> CloneSender for T
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
