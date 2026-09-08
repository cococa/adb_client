//! ADB services backed by [`TransportDispatcher`].

use std::{
    collections::HashMap,
    collections::VecDeque,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use crate::{
    Result, RustADBError,
    message_devices::{
        adb_message_transport::ADBMessageTransport,
        adb_transport_message::ADBTransportMessage,
        message_commands::{MessageCommand, MessageSubcommand},
        transport_dispatcher::{DispatchedSession, TransportDispatcher},
        utils::BinaryEncodable,
    },
    models::ADBLocalCommand,
};

/// Authenticated ADB device whose USB transport has exactly one packet reader.
#[derive(Debug)]
pub(crate) struct DispatchedADBMessageDevice {
    dispatcher: TransportDispatcher,
    forwards: Arc<Mutex<HashMap<String, (String, Arc<AtomicBool>)>>>,
}

struct ForwardReaderStop(Arc<AtomicBool>);

#[cfg(test)]
mod forward_tests {
    use super::*;
    #[derive(Clone, Debug)]
    struct IdleTransport;
    impl crate::adb_transport::ADBTransport for IdleTransport {
        fn connect(&mut self) -> Result<()> {
            Ok(())
        }
        fn disconnect(&mut self) -> Result<()> {
            Ok(())
        }
    }
    impl ADBMessageTransport for IdleTransport {
        fn read_message_with_timeout(
            &mut self,
            timeout: std::time::Duration,
        ) -> Result<ADBTransportMessage> {
            std::thread::sleep(timeout);
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
        }
        fn write_message_with_timeout(
            &mut self,
            _: ADBTransportMessage,
            _: std::time::Duration,
        ) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn forward_readiness_conflicts_and_removal() {
        let device = Arc::new(DispatchedADBMessageDevice::new(IdleTransport));
        let reservation = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let local = format!("tcp:{}", reservation.local_addr().unwrap().port());
        assert!(
            device
                .serve_forward(local.clone(), "tcp:80".into(), None)
                .is_err()
        );
        assert!(device.forward_routes().is_empty());
        drop(reservation);
        let (tx, rx) = mpsc::channel();
        let child = Arc::clone(&device);
        let endpoint = local.clone();
        let listener =
            std::thread::spawn(move || child.serve_forward(endpoint, "tcp:80".into(), Some(&tx)));
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert!(
            device
                .serve_forward(local.clone(), "tcp:81".into(), None)
                .is_err()
        );
        assert_eq!(
            device.forward_routes(),
            vec![(local.clone(), "tcp:80".into())]
        );
        assert!(device.remove_forward(&local));
        listener.join().unwrap().unwrap();
        assert!(device.forward_routes().is_empty());
        let (tx, rx) = mpsc::channel();
        let child = Arc::clone(&device);
        let listener =
            std::thread::spawn(move || child.serve_forward(local, "tcp:82".into(), Some(&tx)));
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        assert_eq!(device.remove_all_forwards(), 1);
        listener.join().unwrap().unwrap();
    }
}

impl Drop for ForwardReaderStop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl DispatchedADBMessageDevice {
    pub(crate) fn new<T: ADBMessageTransport>(transport: T) -> Self {
        Self {
            dispatcher: TransportDispatcher::start(transport),
            forwards: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn open_session(&self, command: &ADBLocalCommand) -> Result<DispatchedService> {
        // Register before OPEN so an immediate OKAY can never be lost.
        let session = self.dispatcher.register()?;
        let local_id = session.local_id();
        let mut destination = command.to_string().into_bytes();
        if !destination.ends_with(&[0]) {
            destination.push(0);
        }
        session.send(ADBTransportMessage::try_new(
            MessageCommand::Open,
            local_id,
            0,
            &destination,
        )?)?;
        let response = session.receive()?;
        if response.header().command() != MessageCommand::Okay
            || response.header().arg1() != local_id
        {
            return Err(RustADBError::ADBRequestFailed(format!(
                "open dispatched session failed: expected OKAY for {local_id}"
            )));
        }
        Ok(DispatchedService {
            session,
            remote_id: response.header().arg0(),
        })
    }

    fn open_destination(&self, destination: &str) -> Result<DispatchedService> {
        let session = self.dispatcher.register()?;
        let local_id = session.local_id();
        let mut payload = destination.as_bytes().to_vec();
        payload.push(0);
        session.send(ADBTransportMessage::try_new(
            MessageCommand::Open,
            local_id,
            0,
            &payload,
        )?)?;
        let response = session.receive()?;
        if response.header().command() != MessageCommand::Okay
            || response.header().arg1() != local_id
        {
            return Err(RustADBError::ADBRequestFailed(
                "forward destination rejected".into(),
            ));
        }
        Ok(DispatchedService {
            session,
            remote_id: response.header().arg0(),
        })
    }

    /// Serves a local TCP listener and forwards each accepted connection to an
    /// Android ADB destination such as `tcp:5555`.
    pub(crate) fn serve_forward(
        &self,
        local: String,
        remote: String,
        ready: Option<&std::sync::mpsc::Sender<std::result::Result<(), String>>>,
    ) -> Result<()> {
        let port = local
            .strip_prefix("tcp:")
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| RustADBError::ADBRequestFailed("forward requires tcp:<port>".into()))?;
        let mut routes = self.forwards.lock().unwrap();
        if port == 0 || routes.contains_key(&local) {
            return Err(RustADBError::ADBRequestFailed(
                "forward requires an unused nonzero TCP port".into(),
            ));
        }
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        routes.insert(local.clone(), (remote.clone(), Arc::clone(&stop)));
        drop(routes);
        if let Some(ready) = ready {
            let _ = ready.send(Ok(()));
        }
        std::thread::scope(|scope| -> Result<()> {
            for incoming in listener.incoming() {
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let socket = match incoming {
                    Ok(socket) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let device = self;
                let destination = remote.clone();
                scope.spawn(move || {
                    if let Err(error) = device.forward_connection(socket, &destination) {
                        log::debug!("ADB forward connection ended: {error}");
                    }
                });
            }
            Ok(())
        })?;
        let mut routes = self.forwards.lock().unwrap();
        if routes
            .get(&local)
            .is_some_and(|(_, flag)| Arc::ptr_eq(flag, &stop))
        {
            routes.remove(&local);
        }
        Ok(())
    }

    pub(crate) fn forward_routes(&self) -> Vec<(String, String)> {
        self.forwards
            .lock()
            .unwrap()
            .iter()
            .map(|(local, (remote, _))| (local.clone(), remote.clone()))
            .collect()
    }

    pub(crate) fn remove_forward(&self, local: &str) -> bool {
        self.forwards
            .lock()
            .unwrap()
            .remove(local)
            .map(|(_, stop)| {
                stop.store(true, Ordering::Release);
                true
            })
            .unwrap_or(false)
    }

    pub(crate) fn remove_all_forwards(&self) -> usize {
        let mut forwards = self.forwards.lock().unwrap();
        let count = forwards.len();
        for (_, (_, stop)) in forwards.drain() {
            stop.store(true, Ordering::Release);
        }
        count
    }

    fn forward_connection(&self, mut socket: TcpStream, remote: &str) -> Result<()> {
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(std::time::Duration::from_millis(100)))?;
        let service = self.open_destination(remote)?;
        // Keep this bounded: if adbd is waiting for an OKAY, TCP naturally
        // applies backpressure instead of letting a fast local producer grow
        // an unbounded memory queue.
        let (tx, rx) = mpsc::sync_channel::<Option<Vec<u8>>>(16);
        let mut reader = socket.try_clone()?;
        let reader_running = Arc::new(AtomicBool::new(true));
        let _reader_stop = ForwardReaderStop(Arc::clone(&reader_running));
        std::thread::spawn(move || {
            let mut buffer = vec![0; 64 * 1024];
            while reader_running.load(Ordering::Acquire) {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        let _ = tx.send(None);
                        return;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        continue;
                    }
                    Err(_) => {
                        let _ = tx.send(None);
                        return;
                    }
                    Ok(length) if tx.send(Some(buffer[..length].to_vec())).is_err() => return,
                    Ok(_) => {}
                }
            }
        });
        let mut pending = false;
        loop {
            // ADB permits one outstanding host WRTE per service. Do not drain
            // the queue while that WRTE is awaiting its OKAY: doing so would
            // silently discard forward data under load.
            if !pending {
                match rx.try_recv() {
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                    Ok(event) => match event {
                        None => {
                            let _ = service.close_ack();
                            return Ok(());
                        }
                        Some(payload) => {
                            service.session.send(ADBTransportMessage::try_new(
                                MessageCommand::Write,
                                service.session.local_id(),
                                service.remote_id,
                                &payload,
                            )?)?;
                            pending = true;
                        }
                    },
                }
            }
            match service
                .session
                .receive_timeout(std::time::Duration::from_millis(10))?
            {
                Some(packet) => match packet.header().command() {
                    MessageCommand::Write => {
                        socket.write_all(packet.payload())?;
                        service.acknowledge()?;
                    }
                    MessageCommand::Okay => {
                        pending = false;
                    }
                    MessageCommand::Clse => {
                        let _ = service.close_ack();
                        return Ok(());
                    }
                    _ => {
                        return Err(RustADBError::ADBRequestFailed(
                            "unexpected forward packet".into(),
                        ));
                    }
                },
                None => {}
            }
        }
    }

    pub(crate) fn shell_command(
        &self,
        command: &str,
        mut stdout: Option<&mut dyn Write>,
    ) -> Result<()> {
        let service = self.open_session(&ADBLocalCommand::ShellCommand(
            command.to_owned(),
            vec!["v2".to_owned()],
        ))?;
        let mut buffered = VecDeque::new();
        let mut errors = Vec::new();
        loop {
            let header = service.read_bytes(&mut buffered, 5)?;
            let length = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
            if length > 1024 * 1024 {
                return Err(RustADBError::ADBRequestFailed(
                    "oversized shell packet".into(),
                ));
            }
            let data = service.read_bytes(&mut buffered, length)?;
            match header[0] {
                1 => {
                    if let Some(output) = stdout.as_deref_mut() {
                        output.write_all(&data)?;
                    }
                }
                2 => {
                    // Bound diagnostics without blocking or mixing stderr into binary data.
                    if errors.len() < 64 * 1024 {
                        errors.extend_from_slice(&data);
                    }
                }
                3 => {
                    service.close_ack()?;
                    return match data.first() {
                        Some(0) => Ok(()),
                        code => Err(RustADBError::ADBRequestFailed(format!(
                            "remote command exited {code:?}: {}",
                            String::from_utf8_lossy(&errors)
                        ))),
                    };
                }
                _ => {
                    return Err(RustADBError::ADBRequestFailed(
                        "invalid shell packet".into(),
                    ));
                }
            }
        }
    }

    pub(crate) fn pull(&self, path: &str, output: &mut dyn Write) -> Result<()> {
        let service = self.open_session(&ADBLocalCommand::Sync)?;
        let mut request = b"RECV".to_vec();
        request.extend_from_slice(&u32::try_from(path.len())?.to_le_bytes());
        request.extend_from_slice(path.as_bytes());
        service.send_expect_okay(&request)?;
        let mut buffered = VecDeque::new();
        let result = (|| -> Result<()> {
            loop {
                let header = service.read_bytes(&mut buffered, 8)?;
                let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
                match &header[..4] {
                    b"DONE" => return Ok(()),
                    b"DATA" if length <= 64 * 1024 => {
                        output.write_all(&service.read_bytes(&mut buffered, length)?)?
                    }
                    b"FAIL" if length <= 64 * 1024 => {
                        return Err(RustADBError::ADBRequestFailed(
                            String::from_utf8_lossy(&service.read_bytes(&mut buffered, length)?)
                                .into_owned(),
                        ));
                    }
                    _ => {
                        return Err(RustADBError::ADBRequestFailed(
                            "invalid sync download packet".into(),
                        ));
                    }
                }
            }
        })();
        let _ = service.close_ack();
        result
    }

    pub(crate) fn exec_out(&self, command: &str, output: &mut dyn Write) -> Result<()> {
        self.open_session(&ADBLocalCommand::Exec(command.to_owned()))?
            .drain_to(&mut Some(output))
    }

    pub(crate) fn reverse_forward(&self, remote: String, local: String) -> Result<()> {
        eprintln!("[adb_client] installing reverse remote={remote} local={local}");
        let port = local
            .strip_prefix("tcp:")
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|port| *port != 0)
            .ok_or_else(|| RustADBError::ADBRequestFailed("reverse requires tcp:<port>".into()))?;
        self.dispatcher
            .set_route(remote.clone(), Some(format!("tcp:{port}")))?;
        let result = self.reverse_command(&ADBLocalCommand::Reverse(remote.clone(), local));
        if result.is_err() {
            let _ = self.dispatcher.set_route(remote, None);
        }
        result
    }

    /// Pushes data over a dispatcher-owned sync service. This is intentionally
    /// kept on the same physical connection as shell and reverse so the macOS
    /// USB interface is never reopened while scrcpy is starting.
    pub(crate) fn push<R: Read>(&self, mut input: R, path: &str) -> Result<()> {
        const CHUNK_SIZE: usize = 65_535;
        let service = self.open_session(&ADBLocalCommand::Sync)?;
        let destination = format!("{path},0777");
        let mut begin = MessageSubcommand::Send
            .with_arg(u32::try_from(destination.len())?)
            .encode();
        begin.extend_from_slice(destination.as_bytes());
        service.send_expect_okay(&begin)?;

        let mut buffer = vec![0; CHUNK_SIZE];
        loop {
            let length = input.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            let mut chunk = MessageSubcommand::Data
                .with_arg(u32::try_from(length)?)
                .encode();
            chunk.extend_from_slice(&buffer[..length]);
            service.send_expect_okay(&chunk)?;
        }
        service.send_expect_okay(&MessageSubcommand::Done.with_arg(0).encode())?;

        // adbd returns the sync result as WRTE after acknowledging DONE.
        let result = service.session.receive()?;
        if result.header().command() != MessageCommand::Write {
            return Err(RustADBError::ADBRequestFailed(
                "sync push did not return a result packet".to_owned(),
            ));
        }
        service.acknowledge()?;
        service.close_ack()?;
        if !result.payload().starts_with(b"OKAY") {
            return Err(RustADBError::ADBRequestFailed(format!(
                "sync push failed: {}",
                String::from_utf8_lossy(result.payload())
            )));
        }
        Ok(())
    }

    pub(crate) fn remove_reverse_forward(&self, remote: String) -> Result<()> {
        self.reverse_command(&ADBLocalCommand::ReverseRemove(remote.clone()))?;
        self.dispatcher.set_route(remote, None)
    }

    fn reverse_command(&self, command: &ADBLocalCommand) -> Result<()> {
        let mut response = Vec::new();
        self.open_session(command)?
            .drain_to(&mut Some(&mut response))?;
        if !response.starts_with(b"OKAY") {
            return Err(RustADBError::ADBRequestFailed(format!(
                "reverse failed: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        Ok(())
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.dispatcher.is_alive()
    }

    pub(crate) fn reverse_routes(&self) -> Result<Vec<(String, String)>> {
        self.dispatcher.routes()
    }

    pub(crate) fn remove_all_reverse_routes(&self) -> Result<()> {
        for (remote, _) in self.dispatcher.routes()? {
            self.reverse_command(&ADBLocalCommand::ReverseRemove(remote.clone()))?;
            self.dispatcher.set_route(remote, None)?;
        }
        Ok(())
    }

    pub(crate) fn root(&self) -> Result<()> {
        self.open_session(&ADBLocalCommand::Root)?
            .drain_to(&mut None)
    }

    pub(crate) fn remount(&self) -> Result<()> {
        self.open_session(&ADBLocalCommand::Remount)?
            .drain_to(&mut None)
    }

    /// Asks `adbd` to restart its TCP listener on `port`.
    pub(crate) fn tcpip(&self, port: u16) -> Result<()> {
        self.open_session(&ADBLocalCommand::TcpIp(port))?
            .drain_to(&mut None)
    }
}

#[derive(Debug)]
struct DispatchedService {
    session: DispatchedSession,
    remote_id: u32,
}

impl DispatchedService {
    fn read_bytes(&self, buffered: &mut VecDeque<u8>, length: usize) -> Result<Vec<u8>> {
        while buffered.len() < length {
            let packet = self.session.receive()?;
            match packet.header().command() {
                MessageCommand::Write => {
                    buffered.extend(packet.payload());
                    self.acknowledge()?;
                }
                MessageCommand::Okay => {}
                MessageCommand::Clse => {
                    let _ = self.close_ack();
                    return Err(RustADBError::ADBRequestFailed(
                        "device closed service before completion".into(),
                    ));
                }
                _ => {
                    return Err(RustADBError::ADBRequestFailed(
                        "unexpected service packet".into(),
                    ));
                }
            }
        }
        Ok(buffered.drain(..length).collect())
    }

    fn send_expect_okay(&self, payload: &[u8]) -> Result<()> {
        self.session.send(ADBTransportMessage::try_new(
            MessageCommand::Write,
            self.session.local_id(),
            self.remote_id,
            payload,
        )?)?;
        let response = self.session.receive()?;
        if response.header().command() != MessageCommand::Okay {
            return Err(RustADBError::ADBRequestFailed(
                "ADB service did not acknowledge write".to_owned(),
            ));
        }
        Ok(())
    }

    fn acknowledge(&self) -> Result<()> {
        self.session.send(ADBTransportMessage::try_new(
            MessageCommand::Okay,
            self.session.local_id(),
            self.remote_id,
            &[],
        )?)
    }

    fn close_ack(&self) -> Result<()> {
        self.session.send(ADBTransportMessage::try_new(
            MessageCommand::Clse,
            self.session.local_id(),
            self.remote_id,
            &[],
        )?)
    }

    fn drain_to(self, stdout: &mut Option<&mut dyn Write>) -> Result<()> {
        loop {
            let message = self.session.receive()?;
            match message.header().command() {
                MessageCommand::Write => {
                    if let Some(output) = stdout.as_deref_mut() {
                        output.write_all(message.payload())?;
                    }
                    self.acknowledge()?;
                }
                MessageCommand::Clse => {
                    self.close_ack()?;
                    return Ok(());
                }
                MessageCommand::Okay => {}
                command => {
                    return Err(RustADBError::ADBRequestFailed(format!(
                        "unexpected {command} in dispatched shell session"
                    )));
                }
            }
        }
    }
}
