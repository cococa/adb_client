//! Direct-USB reverse-forward data plane.
//!
//! AOSP keeps the USB transport open after `reverse:forward`. When the device
//! connects to that reverse endpoint it sends an ADB `OPEN` packet to the
//! host. This module performs the equivalent packet-to-TCP relay without an
//! adb server process.

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::Duration,
};

use rand::RngExt;

use crate::{
    Result, RustADBError,
    message_devices::{
        adb_message_transport::ADBMessageTransport, adb_transport_message::ADBTransportMessage,
        message_commands::MessageCommand,
    },
};

const USB_POLL_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_ADB_PAYLOAD: usize = 64 * 1024;

#[derive(Debug)]
enum LocalEvent {
    Data { local_id: u32, payload: Vec<u8> },
    Closed { local_id: u32 },
}

/// Bridges one configured ADB reverse endpoint to the TCP listener created by
/// scrcpy. It deliberately owns no listener: stock scrcpy remains responsible
/// for its socket lifecycle and protocol.
#[derive(Debug)]
pub(crate) struct ReverseRelay<'a, T: ADBMessageTransport> {
    transport: &'a mut T,
    remote: String,
    local_port: u16,
    sockets: HashMap<u32, (u32, TcpStream)>,
    event_tx: Sender<LocalEvent>,
    event_rx: Receiver<LocalEvent>,
}

impl<'a, T: ADBMessageTransport> ReverseRelay<'a, T> {
    pub(crate) fn new(transport: &'a mut T, remote: String, local: String) -> Result<Self> {
        let local_port = local
            .strip_prefix("tcp:")
            .ok_or_else(|| {
                RustADBError::ADBRequestFailed(format!(
                    "reverse relay needs tcp:<port>, got {local}"
                ))
            })?
            .parse::<u16>()
            .map_err(|error| {
                RustADBError::ADBRequestFailed(format!("invalid reverse TCP port: {error}"))
            })?;
        let (event_tx, event_rx) = mpsc::channel();
        Ok(Self {
            transport,
            remote,
            local_port,
            sockets: HashMap::new(),
            event_tx,
            event_rx,
        })
    }

    /// Runs until the device closes the transport. The short USB read timeout
    /// lets outbound TCP bytes progress even when Android is temporarily idle.
    pub(crate) fn run(&mut self) -> Result<()> {
        loop {
            self.flush_local_events()?;
            match self.transport.read_message_with_timeout(USB_POLL_TIMEOUT) {
                Ok(message) => self.handle_device_message(message)?,
                Err(RustADBError::IOError(error))
                    if error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn flush_local_events(&mut self) -> Result<()> {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                LocalEvent::Data { local_id, payload } => {
                    let Some((remote_id, _)) = self.sockets.get(&local_id) else {
                        continue;
                    };
                    self.transport.write_message(ADBTransportMessage::try_new(
                        MessageCommand::Write,
                        local_id,
                        *remote_id,
                        &payload,
                    )?)?;
                }
                LocalEvent::Closed { local_id } => {
                    if let Some((remote_id, _)) = self.sockets.remove(&local_id) {
                        self.transport.write_message(ADBTransportMessage::try_new(
                            MessageCommand::Clse,
                            local_id,
                            remote_id,
                            &[],
                        )?)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_device_message(&mut self, message: ADBTransportMessage) -> Result<()> {
        match message.header().command() {
            MessageCommand::Open => self.accept_device_open(message),
            MessageCommand::Write => self.write_to_local(message),
            MessageCommand::Clse => self.close_device_stream(message),
            // OKAY is an acknowledgement of host-originated relay data. ADB
            // has one outstanding write per stream; TCP backpressure naturally
            // limits this initial implementation until the daemon scheduler is
            // layered above it.
            MessageCommand::Okay => Ok(()),
            command => Err(RustADBError::ADBRequestFailed(format!(
                "unexpected {command} while serving reverse relay"
            ))),
        }
    }

    fn accept_device_open(&mut self, message: ADBTransportMessage) -> Result<()> {
        let destination = String::from_utf8_lossy(message.payload())
            .trim_end_matches('\0')
            .to_owned();
        if destination != self.remote {
            return Err(RustADBError::ADBRequestFailed(format!(
                "device requested non-configured reverse destination {destination}"
            )));
        }
        let stream = TcpStream::connect(("127.0.0.1", self.local_port))?;
        stream.set_nodelay(true)?;
        let reader = stream.try_clone()?;
        let device_id = message.header().arg0();
        let mut rng = rand::rng();
        let local_id: u32 = rng.random();
        self.transport.write_message(ADBTransportMessage::try_new(
            MessageCommand::Okay,
            local_id,
            device_id,
            &[],
        )?)?;
        self.sockets.insert(local_id, (device_id, stream));
        Self::spawn_local_reader(reader, local_id, self.event_tx.clone());
        Ok(())
    }

    fn write_to_local(&mut self, message: ADBTransportMessage) -> Result<()> {
        let local_id = message.header().arg1();
        let remote_id = message.header().arg0();
        let Some((expected_remote, stream)) = self.sockets.get_mut(&local_id) else {
            return Err(RustADBError::ADBRequestFailed(
                "write for unknown reverse stream".into(),
            ));
        };
        if *expected_remote != remote_id {
            return Err(RustADBError::ADBRequestFailed(
                "reverse stream id mismatch".into(),
            ));
        }
        stream.write_all(message.payload())?;
        self.transport.write_message(ADBTransportMessage::try_new(
            MessageCommand::Okay,
            local_id,
            remote_id,
            &[],
        )?)?;
        Ok(())
    }

    fn close_device_stream(&mut self, message: ADBTransportMessage) -> Result<()> {
        let local_id = message.header().arg1();
        let remote_id = message.header().arg0();
        self.sockets.remove(&local_id);
        self.transport.write_message(ADBTransportMessage::try_new(
            MessageCommand::Clse,
            local_id,
            remote_id,
            &[],
        )?)?;
        Ok(())
    }

    fn spawn_local_reader(mut stream: TcpStream, local_id: u32, sender: Sender<LocalEvent>) {
        thread::spawn(move || {
            let mut buffer = vec![0; MAX_ADB_PAYLOAD];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => {
                        let _ = sender.send(LocalEvent::Closed { local_id });
                        return;
                    }
                    Ok(length) => {
                        if sender
                            .send(LocalEvent::Data {
                                local_id,
                                payload: buffer[..length].to_vec(),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
        });
    }
}
