use std::{io::Read, time::Duration};

use crate::{
    AdbStatResponse, BinaryDecodable, Result, RustADBError,
    message_devices::{
        adb_message_transport::ADBMessageTransport,
        adb_transport_message::ADBTransportMessage,
        message_commands::{MessageCommand, MessageSubcommand},
        utils::BinaryEncodable,
    },
};

const BUFFER_SIZE: usize = 65535;
const MAX_SYNC_ERROR_LENGTH: usize = 1024 * 1024;

struct SyncPayloadReader<'a, T: ADBMessageTransport> {
    session: &'a mut ADBSession<T>,
    payload: Vec<u8>,
    offset: usize,
}

impl<'a, T: ADBMessageTransport> SyncPayloadReader<'a, T> {
    fn new(session: &'a mut ADBSession<T>) -> Self {
        Self {
            session,
            payload: Vec::new(),
            offset: 0,
        }
    }
}

impl<T: ADBMessageTransport> Read for SyncPayloadReader<'_, T> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.offset == self.payload.len() {
            let message = self
                .session
                .recv_and_reply_okay()
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            message
                .assert_command(MessageCommand::Write)
                .map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
                })?;
            self.payload = message.into_payload();
            self.offset = 0;
            if self.payload.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "empty ADB sync payload",
                ));
            }
        }
        let count = output.len().min(self.payload.len() - self.offset);
        output[..count].copy_from_slice(&self.payload[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

fn copy_sync_file<R: Read, W: std::io::Write>(
    input: &mut R,
    output: &mut W,
) -> std::result::Result<(), RustADBError> {
    loop {
        let mut header = [0; 8];
        input.read_exact(&mut header)?;
        let command = u32::from_le_bytes(header[..4].try_into()?);
        let length = u32::from_le_bytes(header[4..].try_into()?) as usize;
        match MessageSubcommand::try_from(command) {
            Ok(MessageSubcommand::Data) => {
                let copied = std::io::copy(&mut (&mut *input).take(length as u64), output)?;
                if copied != length as u64 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "truncated ADB sync DATA payload",
                    )
                    .into());
                }
            }
            Ok(MessageSubcommand::Done) => return Ok(()),
            Ok(MessageSubcommand::Fail) => {
                if length > MAX_SYNC_ERROR_LENGTH {
                    return Err(RustADBError::ADBRequestFailed(format!(
                        "ADB sync error exceeds {MAX_SYNC_ERROR_LENGTH} bytes"
                    )));
                }
                let mut message = vec![0; length];
                input.read_exact(&mut message)?;
                return Err(RustADBError::ADBRequestFailed(
                    String::from_utf8_lossy(&message).into_owned(),
                ));
            }
            Ok(other) => {
                return Err(RustADBError::UnknownResponseType(format!(
                    "unexpected ADB sync response {other:?}"
                )));
            }
            Err(_) => {
                return Err(RustADBError::UnknownResponseType(format!(
                    "unknown ADB sync response 0x{command:08x}"
                )));
            }
        }
    }
}

/// Represent a session between an `ADBDevice` and remote `adbd`.
#[derive(Debug)]
pub struct ADBSession<T: ADBMessageTransport> {
    transport: T,
    local_id: u32,
    remote_id: u32,
}

impl<T: ADBMessageTransport> ADBSession<T> {
    /// Create a new session with the given transport and IDs.
    pub const fn new(transport: T, local_id: u32, remote_id: u32) -> Self {
        Self {
            transport,
            local_id,
            remote_id,
        }
    }

    pub const fn get_transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn local_id(&self) -> u32 {
        self.local_id
    }

    pub const fn remote_id(&self) -> u32 {
        self.remote_id
    }

    /// Receive a message and acknowledge it by replying with an `OKAY` command
    pub(crate) fn recv_and_reply_okay(&mut self) -> Result<ADBTransportMessage> {
        let message = self.transport.read_message()?;
        self.transport.write_message(ADBTransportMessage::try_new(
            MessageCommand::Okay,
            self.local_id,
            self.remote_id,
            &[],
        )?)?;
        Ok(message)
    }

    /// Expect a message with an `OKAY` command after sending a message.
    pub(crate) fn send_and_expect_okay(
        &mut self,
        message: ADBTransportMessage,
    ) -> Result<ADBTransportMessage> {
        self.transport.write_message(message)?;

        self.transport.read_message().and_then(|message| {
            message.assert_command(MessageCommand::Okay)?;
            Ok(message)
        })
    }

    pub(crate) fn recv_file<W: std::io::Write>(
        &mut self,
        mut output: W,
    ) -> std::result::Result<(), RustADBError> {
        copy_sync_file(&mut SyncPayloadReader::new(self), &mut output)
    }

    pub(crate) fn push_file<R: std::io::Read>(&mut self, mut reader: R) -> Result<()> {
        let mut buffer = vec![0; BUFFER_SIZE].into_boxed_slice();
        let amount_read = reader.read(&mut buffer)?;
        let subcommand_data = MessageSubcommand::Data.with_arg(u32::try_from(amount_read)?);

        let mut serialized_message = subcommand_data.encode();
        serialized_message.append(&mut buffer[..amount_read].to_vec());

        let message = ADBTransportMessage::try_new(
            MessageCommand::Write,
            self.local_id(),
            self.remote_id(),
            &serialized_message,
        )?;

        self.send_and_expect_okay(message)?;

        loop {
            let mut buffer = vec![0; BUFFER_SIZE].into_boxed_slice();

            match reader.read(&mut buffer) {
                Ok(0) => {
                    // Currently file mtime is not forwarded
                    let subcommand_data = MessageSubcommand::Done.with_arg(0);

                    let message = ADBTransportMessage::try_new(
                        MessageCommand::Write,
                        self.local_id(),
                        self.remote_id(),
                        &subcommand_data.encode(),
                    )?;

                    self.send_and_expect_okay(message)?;

                    // Command should end with a Write => Okay
                    let received = self.transport.read_message()?;
                    match received.header().command() {
                        MessageCommand::Write => return Ok(()),
                        c => {
                            return Err(RustADBError::ADBRequestFailed(format!(
                                "Wrong command received {c}"
                            )));
                        }
                    }
                }
                Ok(size) => {
                    let subcommand_data = MessageSubcommand::Data.with_arg(u32::try_from(size)?);

                    let mut serialized_message = subcommand_data.encode();
                    serialized_message.append(&mut buffer[..size].to_vec());

                    let message = ADBTransportMessage::try_new(
                        MessageCommand::Write,
                        self.local_id(),
                        self.remote_id(),
                        &serialized_message,
                    )?;

                    self.send_and_expect_okay(message)?;
                }
                Err(e) => {
                    return Err(RustADBError::IOError(e));
                }
            }
        }
    }

    pub(crate) fn stat_with_explicit_ids(&mut self, remote_path: &str) -> Result<AdbStatResponse> {
        let stat_buffer = MessageSubcommand::Stat.with_arg(u32::try_from(remote_path.len())?);
        let message = ADBTransportMessage::try_new(
            MessageCommand::Write,
            self.local_id(),
            self.remote_id(),
            &stat_buffer.encode(),
        )?;
        self.send_and_expect_okay(message)?;
        self.send_and_expect_okay(ADBTransportMessage::try_new(
            MessageCommand::Write,
            self.local_id(),
            self.remote_id(),
            remote_path.as_bytes(),
        )?)?;

        let response = self.transport.read_message()?;
        // Skip first 4 bytes as this is the literal "STAT".
        // Interesting part starts right after
        let payload = response.into_payload();
        if payload.len() != 16 || payload[..4] != MessageSubcommand::Stat.encode() {
            return Err(RustADBError::StatResponseError(
                "invalid legacy STAT payload".to_owned(),
            ));
        }
        AdbStatResponse::decode(&payload[4..])
    }
}

impl<T: ADBMessageTransport> Drop for ADBSession<T> {
    fn drop(&mut self) {
        // some devices will repeat the trailing CLSE command to ensure
        // the client has acknowledged it. Read them quickly if present.
        while let Ok(_discard_close_message) = self
            .transport
            .read_message_with_timeout(Duration::from_millis(20))
        {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FragmentedReader {
        data: std::io::Cursor<Vec<u8>>,
        maximum: usize,
    }

    impl Read for FragmentedReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let count = output.len().min(self.maximum);
            self.data.read(&mut output[..count])
        }
    }

    fn sync_data(bytes: &[u8]) -> Vec<u8> {
        let mut input = MessageSubcommand::Data
            .with_arg(bytes.len() as u32)
            .encode();
        input.extend_from_slice(bytes);
        input.extend(MessageSubcommand::Done.with_arg(0).encode());
        input
    }

    #[test]
    fn sync_receive_handles_headers_and_data_split_at_every_byte() {
        let mut input = FragmentedReader {
            data: std::io::Cursor::new(sync_data(b"fragmented")),
            maximum: 1,
        };
        let mut output = Vec::new();
        copy_sync_file(&mut input, &mut output).unwrap();
        assert_eq!(output, b"fragmented");
    }

    #[test]
    fn sync_receive_rejects_truncated_packets_without_panicking() {
        for input in [
            MessageSubcommand::Data.encode(),
            MessageSubcommand::Data.with_arg(5).encode(),
        ] {
            assert!(copy_sync_file(&mut std::io::Cursor::new(input), &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn sync_receive_reports_remote_failure_and_caps_its_allocation() {
        let mut failure = MessageSubcommand::Fail.with_arg(4).encode();
        failure.extend_from_slice(b"nope");
        let error = copy_sync_file(&mut std::io::Cursor::new(failure), &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(error.contains("nope"));

        let oversized = MessageSubcommand::Fail
            .with_arg((MAX_SYNC_ERROR_LENGTH + 1) as u32)
            .encode();
        assert!(copy_sync_file(&mut std::io::Cursor::new(oversized), &mut Vec::new()).is_err());
    }
}
