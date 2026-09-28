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

fn is_idle_poll_error(error: &RustADBError) -> bool {
    matches!(
        error,
        RustADBError::IOError(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
    )
}

fn is_expected_reverse_destination(destination: &str, local: &str) -> bool {
    destination == local
}

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
    local: String,
    local_port: u16,
    sockets: HashMap<u32, (u32, TcpStream)>,
    accepted_stream: bool,
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
            local,
            local_port,
            sockets: HashMap::new(),
            accepted_stream: false,
            event_tx,
            event_rx,
        })
    }

    /// Runs until the device closes the transport. The short USB read timeout
    /// lets outbound TCP bytes progress even when Android is temporarily idle.
    pub(crate) fn run(&mut self) -> Result<()> {
        // The scrcpy compatibility process waits for this exact readiness
        // signal before returning from `adb reverse`. Emit it only after the
        // relay is fully initialized, immediately before it receives Android
        // `OPEN` requests, so server startup cannot race the reverse route.
        if std::env::var_os("ANDROCONNECT_REVERSE_RELAY_READY").is_some() {
            eprintln!(
                "[ANDROCONNECT-WIRELESS-REVERSE] relay ready remote={} local={} local_port={}",
                self.remote, self.local, self.local_port
            );
            println!("ANDROCONNECT_REVERSE_RELAY_READY");
            std::io::stdout().flush()?;
        }
        loop {
            self.flush_local_events()?;
            if self.accepted_stream && self.sockets.is_empty() {
                eprintln!("[ANDROCONNECT-WIRELESS-REVERSE] all local streams closed; relay exiting");
                return Ok(());
            }
            match self.transport.read_message_with_timeout(USB_POLL_TIMEOUT) {
                Ok(message) => {
                    self.handle_device_message(message)?;
                    if self.accepted_stream && self.sockets.is_empty() {
                        eprintln!(
                            "[ANDROCONNECT-WIRELESS-REVERSE] all device streams closed; relay exiting"
                        );
                        return Ok(());
                    }
                }
                // macOS reports a socket receive timeout as EAGAIN/WouldBlock
                // while other platforms commonly use TimedOut. Both mean the
                // polling loop is idle, not that the wireless transport died.
                Err(error) if is_idle_poll_error(&error) => {}
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
        eprintln!(
            "[ANDROCONNECT-WIRELESS-REVERSE] received device OPEN destination={destination} expected={} local_port={}",
            self.local, self.local_port
        );
        if !is_expected_reverse_destination(&destination, &self.local) {
            return Err(RustADBError::ADBRequestFailed(format!(
                "device requested reverse destination {destination}, expected {}",
                self.local
            )));
        }
        let stream = TcpStream::connect(("127.0.0.1", self.local_port)).map_err(|error| {
            eprintln!(
                "[ANDROCONNECT-WIRELESS-REVERSE] local TCP connect failed port={} error={error}",
                self.local_port
            );
            RustADBError::ADBRequestFailed(format!(
                "reverse relay could not connect to 127.0.0.1:{}: {error}",
                self.local_port
            ))
        })?;
        stream.set_nodelay(true)?;
        eprintln!(
            "[ANDROCONNECT-WIRELESS-REVERSE] local TCP connected port={}",
            self.local_port
        );
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
        self.accepted_stream = true;
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
        eprintln!(
            "[ANDROCONNECT-WIRELESS-REVERSE] device stream closed local_id={local_id} remote_id={remote_id}"
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_poll_accepts_macos_would_block() {
        let error = RustADBError::IOError(std::io::Error::from(std::io::ErrorKind::WouldBlock));

        assert!(is_idle_poll_error(&error));
    }

    #[test]
    fn idle_poll_rejects_connection_reset() {
        let error =
            RustADBError::IOError(std::io::Error::from(std::io::ErrorKind::ConnectionReset));

        assert!(!is_idle_poll_error(&error));
    }

    #[test]
    fn reverse_open_accepts_registered_local_target() {
        assert!(is_expected_reverse_destination("tcp:27183", "tcp:27183"));
    }

    #[test]
    fn reverse_open_rejects_device_side_socket_name() {
        assert!(!is_expected_reverse_destination(
            "localabstract:scrcpy_test",
            "tcp:27183"
        ));
    }
}
