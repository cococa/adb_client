//! One-reader ADB packet dispatcher.
//!
//! ADB multiplexes all logical services on one physical transport. The
//! original client opened a session and let that session call `read_message()`
//! directly, which is safe only while exactly one command exists. A reverse
//! socket (scrcpy) makes that assumption false. This dispatcher owns the sole
//! reader and routes every packet by host `local_id` (`arg1` on incoming
//! packets) to the registered consumer.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}, mpsc::{self, Receiver, Sender}},
    thread,
    time::Duration,
};

use crate::{
    Result, RustADBError,
    message_devices::{
        adb_message_transport::ADBMessageTransport, adb_transport_message::ADBTransportMessage,
        message_commands::MessageCommand,
    },
};

const READ_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Debug)]
enum DispatcherCommand {
    Write {
        message: ADBTransportMessage,
        completion: Sender<Result<()>>,
    },
    Register {
        local_id: u32,
        receiver: Sender<ADBTransportMessage>,
        completion: Sender<()>,
    },
    Unregister {
        local_id: u32,
    },
    Route { remote: String, local: Option<String>, completion: Sender<()> },
    Routes { completion: Sender<Vec<(String, String)>> },
    Shutdown,
}

/// A handle for a single logical service. It never reads the USB transport.
#[derive(Debug)]
pub(crate) struct DispatchedSession {
    local_id: u32,
    command_tx: Sender<DispatcherCommand>,
    packet_rx: Receiver<ADBTransportMessage>,
}

impl DispatchedSession {
    pub(crate) const fn local_id(&self) -> u32 {
        self.local_id
    }

    pub(crate) fn receive(&self) -> Result<ADBTransportMessage> {
        self.packet_rx
            .recv()
            .map_err(|_| RustADBError::ADBRequestFailed("ADB packet dispatcher stopped".to_owned()))
    }

    pub(crate) fn receive_timeout(&self, timeout: Duration) -> Result<Option<ADBTransportMessage>> {
        match self.packet_rx.recv_timeout(timeout) {
            Ok(packet) => Ok(Some(packet)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(RustADBError::ADBRequestFailed("ADB packet dispatcher stopped".to_owned())),
        }
    }

    pub(crate) fn send(&self, message: ADBTransportMessage) -> Result<()> {
        let (completion_tx, completion_rx) = mpsc::channel();
        self.command_tx
            .send(DispatcherCommand::Write {
                message,
                completion: completion_tx,
            })
            .map_err(|_| {
                RustADBError::ADBRequestFailed("ADB packet dispatcher stopped".to_owned())
            })?;
        completion_rx.recv().map_err(|_| {
            RustADBError::ADBRequestFailed("ADB packet dispatcher stopped".to_owned())
        })?
    }
}

impl Drop for DispatchedSession {
    fn drop(&mut self) {
        let _ = self.command_tx.send(DispatcherCommand::Unregister {
            local_id: self.local_id,
        });
    }
}

/// Owns the sole transport reader. Device-initiated `OPEN` packets are
/// delivered to `incoming_open`, which is where the reverse-forward allow-list
/// and TCP relay will be attached.
#[derive(Debug)]
pub(crate) struct TransportDispatcher {
    alive: Arc<AtomicBool>,
    command_tx: Sender<DispatcherCommand>,
    incoming_open_rx: Mutex<Receiver<ADBTransportMessage>>,
}

impl TransportDispatcher {
    pub(crate) fn start<T: ADBMessageTransport>(mut transport: T) -> Self {
        let (command_tx, command_rx) = mpsc::channel();
        let (incoming_open_tx, incoming_open_rx) = mpsc::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let running = Arc::clone(&alive);
        let relay_tx = command_tx.clone();
        thread::spawn(move || {
            run_loop(&mut transport, command_rx, incoming_open_tx, relay_tx);
            running.store(false, Ordering::Release);
        });
        Self {
            alive,
            command_tx,
            incoming_open_rx: Mutex::new(incoming_open_rx),
        }
    }

    pub(crate) fn register(&self, local_id: u32) -> Result<DispatchedSession> {
        let (packet_tx, packet_rx) = mpsc::channel();
        let (completion_tx, completion_rx) = mpsc::channel();
        self.command_tx
            .send(DispatcherCommand::Register {
                local_id,
                receiver: packet_tx,
                completion: completion_tx,
            })
            .map_err(|_| {
                RustADBError::ADBRequestFailed("ADB packet dispatcher stopped".to_owned())
            })?;
        completion_rx.recv().map_err(|_| {
            RustADBError::ADBRequestFailed("ADB packet dispatcher stopped".to_owned())
        })?;
        Ok(DispatchedSession {
            local_id,
            command_tx: self.command_tx.clone(),
            packet_rx,
        })
    }

    pub(crate) fn is_alive(&self) -> bool { self.alive.load(Ordering::Acquire) }

    pub(crate) fn set_route(&self, remote: String, local: Option<String>) -> Result<()> {
        let (tx, rx) = mpsc::channel();
        self.command_tx.send(DispatcherCommand::Route { remote, local, completion: tx })
            .map_err(|_| RustADBError::ADBRequestFailed("dispatcher stopped".into()))?;
        rx.recv().map_err(|_| RustADBError::ADBRequestFailed("dispatcher stopped".into()))
    }

    pub(crate) fn routes(&self) -> Result<Vec<(String, String)>> {
        let (tx, rx) = mpsc::channel();
        self.command_tx.send(DispatcherCommand::Routes { completion: tx })
            .map_err(|_| RustADBError::ADBRequestFailed("dispatcher stopped".into()))?;
        rx.recv().map_err(|_| RustADBError::ADBRequestFailed("dispatcher stopped".into()))
    }

    pub(crate) fn receive_open(&self) -> Result<ADBTransportMessage> {
        self.incoming_open_rx.lock().unwrap()
            .recv()
            .map_err(|_| RustADBError::ADBRequestFailed("ADB packet dispatcher stopped".to_owned()))
    }

    pub(crate) fn shutdown(&self) {
        let _ = self.command_tx.send(DispatcherCommand::Shutdown);
    }
}

impl Drop for TransportDispatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_loop<T: ADBMessageTransport>(
    transport: &mut T,
    command_rx: Receiver<DispatcherCommand>,
    incoming_open_tx: Sender<ADBTransportMessage>,
    command_tx: Sender<DispatcherCommand>,
) {
    let mut routes: HashMap<String, String> = HashMap::new();
    let mut sessions: HashMap<u32, Sender<ADBTransportMessage>> = HashMap::new();
    loop {
        while let Ok(command) = command_rx.try_recv() {
            match command {
                DispatcherCommand::Write {
                    message,
                    completion,
                } => {
                    let _ = completion.send(transport.write_message(message));
                }
                DispatcherCommand::Register {
                    local_id,
                    receiver,
                    completion,
                } => {
                    sessions.insert(local_id, receiver);
                    let _ = completion.send(());
                }
                DispatcherCommand::Unregister { local_id } => {
                    sessions.remove(&local_id);
                }
                DispatcherCommand::Route { remote, local, completion } => {
                    if let Some(local) = local { routes.insert(remote, local); }
                    else { routes.remove(&remote); }
                    let _ = completion.send(());
                }
                DispatcherCommand::Routes { completion } => {
                    let _ = completion.send(routes.iter().map(|(remote, local)| (remote.clone(), local.clone())).collect());
                }
                DispatcherCommand::Shutdown => return,
            }
        }

        match transport.read_message_with_timeout(READ_POLL_INTERVAL) {
            Ok(packet) => match packet.header().command() {
                MessageCommand::Open => {
                    // adbd OPEN names the host destination (tcp:port), not
                    // the Android localabstract endpoint used to register it.
                    let destination = String::from_utf8_lossy(packet.payload());
                    let destination = destination.trim_end_matches('\0');
                    eprintln!("[adb_client] device OPEN destination={destination} routes={:?}", routes);
                    // For reverse forwarding, adbd opens the configured
                    // remote endpoint (the map key); the map value is the
                    // host TCP listener to which that connection is relayed.
                    if let Some(local) = routes.get(destination) {
                        if let Some(port) = local.strip_prefix("tcp:").and_then(|s| s.parse::<u16>().ok()) {
                            let local_id = (1..u32::MAX).find(|id| !sessions.contains_key(id)).unwrap();
                            let (tx, rx) = mpsc::channel();
                            sessions.insert(local_id, tx);
                            let session = DispatchedSession { local_id, command_tx: command_tx.clone(), packet_rx: rx };
                            let remote_id = packet.header().arg0();
                            thread::spawn(move || {
                                if let Err(error) = relay(session, remote_id, port) {
                                    eprintln!("[adb_client] reverse relay failed for tcp:{port}: {error}");
                                    log::debug!("reverse relay closed: {error}");
                                }
                            });
                        }
                    } else {
                        let _ = transport.write_message(ADBTransportMessage::try_new(
                            MessageCommand::Clse, 0, packet.header().arg0(), &[]).unwrap());
                        #[cfg(test)]
                        let _ = incoming_open_tx.send(packet);
                    }
                }
                _ => {
                    let local_id = packet.header().arg1();
                    if let Some(session_tx) = sessions.get(&local_id) {
                        // A consumer disappearing simply closes its session;
                        // never let it stall unrelated streams.
                        let _ = session_tx.send(packet);
                    } else {
                        log::debug!("discarding ADB packet for unregistered local-id {local_id}");
                    }
                }
            },
            Err(RustADBError::IOError(error)) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => {
                log::debug!("ADB dispatcher stopped after transport error: {error}");
                // Wake every in-flight operation so callers fail immediately
                // instead of waiting for a USB timeout after unplug/replug.
                for (local_id, session_tx) in sessions.drain() {
                    if let Ok(close) = ADBTransportMessage::try_new(
                        MessageCommand::Clse, 0, local_id, &[]
                    ) {
                        let _ = session_tx.send(close);
                    }
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb_transport::ADBTransport, message_devices::adb_transport_message::ADBTransportMessage,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    struct TestTransport {
        incoming: Arc<Mutex<Receiver<ADBTransportMessage>>>,
        written: Sender<ADBTransportMessage>,
    }

    impl ADBTransport for TestTransport {
        fn connect(&mut self) -> Result<()> {
            Ok(())
        }
        fn disconnect(&mut self) -> Result<()> {
            Ok(())
        }
    }

    impl ADBMessageTransport for TestTransport {
        fn read_message_with_timeout(&mut self, timeout: Duration) -> Result<ADBTransportMessage> {
            self.incoming
                .lock()
                .unwrap()
                .recv_timeout(timeout)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => RustADBError::IOError(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "test timeout",
                    )),
                    mpsc::RecvTimeoutError::Disconnected => {
                        RustADBError::ADBRequestFailed("test transport closed".to_owned())
                    }
                })
        }
        fn write_message_with_timeout(
            &mut self,
            message: ADBTransportMessage,
            _timeout: Duration,
        ) -> Result<()> {
            self.written.send(message).unwrap();
            Ok(())
        }
    }

    #[test]
    fn routes_packets_by_host_local_id_and_separates_device_open() {
        let (input_tx, input_rx) = mpsc::channel();
        let (written, _output) = mpsc::channel();
        let dispatcher = TransportDispatcher::start(TestTransport {
            incoming: Arc::new(Mutex::new(input_rx)),
            written,
        });
        let first = dispatcher.register(41).unwrap();
        let second = dispatcher.register(42).unwrap();
        input_tx
            .send(ADBTransportMessage::try_new(MessageCommand::Write, 700, 41, b"one").unwrap())
            .unwrap();
        input_tx
            .send(ADBTransportMessage::try_new(MessageCommand::Write, 701, 42, b"two").unwrap())
            .unwrap();
        input_tx
            .send(
                ADBTransportMessage::try_new(MessageCommand::Open, 702, 0, b"localabstract:scrcpy")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(first.receive().unwrap().payload(), b"one");
        assert_eq!(second.receive().unwrap().payload(), b"two");
        assert_eq!(dispatcher.receive_open().unwrap().header().arg0(), 702);
    }
    #[test]
    fn reverse_relays_video_and_obeys_control_write_acknowledgements() {
        use std::{io::{Read, Write}, net::TcpListener};
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let local = format!("tcp:{}", listener.local_addr().unwrap().port());
        let (input, incoming) = mpsc::channel();
        let (written, output) = mpsc::channel();
        let dispatcher = TransportDispatcher::start(TestTransport {
            incoming: Arc::new(Mutex::new(incoming)), written,
        });
        dispatcher.set_route("localabstract:scrcpy_test".into(), Some(local.clone())).unwrap();
        input.send(ADBTransportMessage::try_new(MessageCommand::Open, 99, 0, local.as_bytes()).unwrap()).unwrap();
        let okay = output.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(okay.header().command(), MessageCommand::Okay);
        let id = okay.header().arg0();
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        input.send(ADBTransportMessage::try_new(MessageCommand::Write, 99, id, b"frame").unwrap()).unwrap();
        let mut frame = [0; 5];
        socket.read_exact(&mut frame).unwrap();
        assert_eq!(&frame, b"frame");
        assert_eq!(output.recv_timeout(Duration::from_secs(2)).unwrap().header().command(), MessageCommand::Okay);
        socket.write_all(b"tap").unwrap();
        assert_eq!(output.recv_timeout(Duration::from_secs(2)).unwrap().payload(), b"tap");
        socket.write_all(b"swipe").unwrap();
        assert!(output.recv_timeout(Duration::from_millis(50)).is_err());
        input.send(ADBTransportMessage::try_new(MessageCommand::Okay, 99, id, &[]).unwrap()).unwrap();
        assert_eq!(output.recv_timeout(Duration::from_secs(2)).unwrap().payload(), b"swipe");
        // Another shell session can progress while relay control waits for ACK.
        let shell = dispatcher.register(123).unwrap();
        input.send(ADBTransportMessage::try_new(MessageCommand::Write, 88, 123, b"model").unwrap()).unwrap();
        assert_eq!(shell.receive().unwrap().payload(), b"model");
        input.send(ADBTransportMessage::try_new(MessageCommand::Clse, 99, id, &[]).unwrap()).unwrap();
        assert_eq!(output.recv_timeout(Duration::from_secs(2)).unwrap().header().command(), MessageCommand::Clse);
    }

}

// One outstanding host WRTE per stream. Device video/audio writes continue
// to be acknowledged while waiting for control-input acknowledgements.
fn relay(session: DispatchedSession, remote_id: u32, port: u16) -> Result<()> {
    use std::{io::{Read, Write}, net::{TcpStream, Shutdown}};
    let mut socket = match TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_secs(2)) {
        Ok(socket) => socket,
        Err(error) => {
            session.send(ADBTransportMessage::try_new(MessageCommand::Clse, 0, remote_id, &[])?)?;
            return Err(error.into());
        }
    };
    socket.set_nodelay(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let send = |command, payload: &[u8]| session.send(ADBTransportMessage::try_new(
        command, session.local_id, remote_id, payload)?);
    send(MessageCommand::Okay, &[])?;
    let result = (|| -> Result<()> {
        let mut pending_write = false;
        let mut buffer = [0; 64 * 1024];
        loop {
            match session.packet_rx.recv_timeout(Duration::from_millis(1)) {
                Ok(packet) => match packet.header().command() {
                    MessageCommand::Write => {
                        socket.write_all(packet.payload())?;
                        send(MessageCommand::Okay, &[])?;
                    }
                    MessageCommand::Okay => pending_write = false,
                    MessageCommand::Clse => return Ok(()),
                    _ => return Err(RustADBError::ADBRequestFailed("unexpected relay packet".into())),
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {},
                Err(_) => return Ok(()),
            }
            if !pending_write {
                match socket.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(length) => { send(MessageCommand::Write, &buffer[..length])?; pending_write = true; }
                    Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {},
                    Err(error) => return Err(error.into()),
                }
            }
        }
    })();
    let _ = socket.shutdown(Shutdown::Both);
    let _ = send(MessageCommand::Clse, &[]);
    result
}
