use thiserror::Error;

/// Errors raised while encoding, decoding or driving the ADB protocol.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// The header magic does not match `command ^ 0xFFFF_FFFF`.
    #[error("invalid ADB message magic")]
    BadMagic,
    /// The advertised payload is larger than the negotiated maximum.
    #[error("ADB message payload exceeds {max} bytes: {len}")]
    PayloadTooLarge { len: u32, max: u32 },
    /// The payload does not match the header checksum.
    #[error("ADB message payload checksum mismatch")]
    BadChecksum,
    /// The header names a command this implementation does not know.
    #[error("unknown ADB command 0x{0:08x}")]
    UnknownCommand(u32),
    /// The peer sent a packet that is not valid in the current state.
    #[error("ADB protocol error: {0}")]
    Protocol(String),
    /// A host key could not be generated, parsed or used.
    #[error("ADB key error: {0}")]
    Key(String),
}
