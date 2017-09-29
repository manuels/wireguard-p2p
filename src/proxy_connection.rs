use std::net::SocketAddr;
use std::collections::HashMap;

use futures::Sink;
use futures::Stream;
use futures::Future;
use futures::stream::SplitSink;
use futures::sync::mpsc::Sender;

use tokio_core::reactor::Handle;
use tokio_core::net::UdpSocket;
use tokio_core::net::UdpFramed;

use daemon::RawCodec;

use MsgPair;
use errors::Result;

type PeerSink = SplitSink<UdpFramed<RawCodec>>;

pub struct ProxyConnections {
    wg_addr: SocketAddr,
    sinks: HashMap<SocketAddr, (PeerSink, SocketAddr)>,
    handle: Handle,
    public_sink: Sender<MsgPair>,
}

// TODO: refactor
impl ProxyConnections {
    pub fn new(handle: Handle, public_sink: Sender<MsgPair>, wg_addr: SocketAddr)
        -> ProxyConnections
    {
        ProxyConnections {
            handle,
            public_sink,
            wg_addr,
            sinks: HashMap::new(),
        }
    }

    pub fn get_local_addr(&mut self, remote_addr: SocketAddr) -> SocketAddr {
        let &mut (_, ref local_addr) = self.get_entry(remote_addr);
        *local_addr
    }

    fn get_local_sink(&mut self, remote_addr: SocketAddr) -> &mut PeerSink {
        let &mut (ref mut sink, _) = self.get_entry(remote_addr);
        sink
    }

    fn new_connection(handle: &Handle,
                      public_sink: Sender<MsgPair>,
                      remote_addr: SocketAddr)
        -> (PeerSink, SocketAddr)
    {
        debug!("New connection from {}.", remote_addr);

        let ((local_sink, local_stream), local_addr) = {
            let local_addr_mask = ([127,0,0,1], 0).into();
            let msg = "Unable to bind to a UDP socket on localhost";
            let local_sock = UdpSocket::bind(&local_addr_mask, handle).expect(msg);
            let local_addr = local_sock.local_addr().unwrap();

            debug!("Adding new proxy for {:?}: {:?}", remote_addr, local_addr);
            (local_sock.framed(RawCodec).split(), local_addr)
        };

        let redirect_to_public = local_stream.map(move |(buf, _)| {
            debug!("len={} dst={}", buf.len(), remote_addr);
            (buf, remote_addr)
        });

        handle.spawn(
            redirect_to_public
                .map_err(|_| ())
                .forward(public_sink.sink_map_err(|_| ()))
                .map(|_| ()),
        );

        (local_sink, local_addr)
    }

    fn get_entry(&mut self, remote_addr: SocketAddr) -> &mut (PeerSink, SocketAddr) {
        let handle = &self.handle;
        let public_sink = self.public_sink.clone();

        let create_connection = || Self::new_connection(handle, public_sink, remote_addr);

        let entry = self.sinks.entry(remote_addr);
        entry.or_insert_with(create_connection)
    }

    pub fn forward(&mut self, msg: Vec<u8>, remote_addr: SocketAddr)
        -> Result<()>
    {
        let wg_addr = self.wg_addr;
        debug!("forwardig to {:?}", wg_addr);

        let sink = &mut *self.get_local_sink(remote_addr);
        sink.start_send((msg, wg_addr))?;
        sink.poll_complete()?;

        Ok(())
    }
}

