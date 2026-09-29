//! ADB packet layout and an incremental decoder for byte streams.

use crate::ProtoError;

/// Size of the fixed ADB packet header.
pub const HEADER_LEN: usize = 24;

/// ADB packet commands.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Command {
    /// Connect to a device.
    Cnxn = 0x4E58_4E43,
    /// Close a stream.
    Clse = 0x4553_4C43,
    /// Authentication exchange.
    Auth = 0x4854_5541,
    /// Open a stream.
    Open = 0x4E45_504F,
    /// Stream data.
    Wrte = 0x4554_5257,
    /// Stream ready / data acknowledged.
    Okay = 0x5941_4B4F,
    /// Upgrade the connection to TLS.
    Stls = 0x534C_5453,
}

impl TryFrom<u32> for Command {
    type Error = ProtoError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            0x4E58_4E43 => Self::Cnxn,
            0x4553_4C43 => Self::Clse,
            0x4854_5541 => Self::Auth,
            0x4E45_504F => Self::Open,
            0x4554_5257 => Self::Wrte,
            0x5941_4B4F => Self::Okay,
            0x534C_5453 => Self::Stls,
            other => return Err(ProtoError::UnknownCommand(other)),
        })
    }
}

impl Command {
    const fn magic(self) -> u32 {
        self as u32 ^ 0xFFFF_FFFF
    }
}

/// One ADB packet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub command: Command,
    pub arg0: u32,
    pub arg1: u32,
    pub payload: Vec<u8>,
}

/// Legacy ADB payload checksum: the byte sum of the payload.
pub fn checksum(data: &[u8]) -> u32 {
    data.iter().map(|&b| u32::from(b)).fold(0, u32::wrapping_add)
}

impl Packet {
    pub fn new(command: Command, arg0: u32, arg1: u32, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            command,
            arg0,
            arg1,
            payload: payload.into(),
        }
    }

    /// Encodes the header. USB sends the header and payload as two separate
    /// bulk transfers, so the payload is not appended here.
    pub fn encode_header(&self) -> [u8; HEADER_LEN] {
        let len = u32::try_from(self.payload.len()).expect("ADB payload fits in u32");
        let mut out = [0; HEADER_LEN];
        for (i, word) in [
            self.command as u32,
            self.arg0,
            self.arg1,
            len,
            checksum(&self.payload),
            self.command.magic(),
        ]
        .into_iter()
        .enumerate()
        {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

struct PendingHeader {
    command: Command,
    arg0: u32,
    arg1: u32,
    len: usize,
    checksum: u32,
}

/// Reassembles packets from arbitrarily fragmented input.
pub struct PacketDecoder {
    buf: Vec<u8>,
    header: Option<PendingHeader>,
    max_payload: u32,
    verify_checksum: bool,
}

impl PacketDecoder {
    pub fn new(max_payload: u32) -> Self {
        Self {
            buf: Vec::new(),
            header: None,
            max_payload,
            verify_checksum: true,
        }
    }

    pub fn set_max_payload(&mut self, max_payload: u32) {
        self.max_payload = max_payload;
    }

    /// Protocol versions from `0x0100_0001` send a zero checksum.
    pub fn set_verify_checksum(&mut self, verify: bool) {
        self.verify_checksum = verify;
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next complete packet, if enough bytes have arrived.
    pub fn next_packet(&mut self) -> Result<Option<Packet>, ProtoError> {
        if self.header.is_none() {
            if self.buf.len() < HEADER_LEN {
                return Ok(None);
            }
            let word = |i: usize| {
                u32::from_le_bytes(self.buf[i * 4..i * 4 + 4].try_into().expect("4 bytes"))
            };
            let raw_command = word(0);
            let len = word(3);
            let command = Command::try_from(raw_command)?;
            if word(5) != command.magic() {
                return Err(ProtoError::BadMagic);
            }
            if len > self.max_payload {
                return Err(ProtoError::PayloadTooLarge {
                    len,
                    max: self.max_payload,
                });
            }
            self.header = Some(PendingHeader {
                command,
                arg0: word(1),
                arg1: word(2),
                len: len as usize,
                checksum: word(4),
            });
            self.buf.drain(..HEADER_LEN);
        }

        let header = self.header.as_ref().expect("header parsed above");
        if self.buf.len() < header.len {
            return Ok(None);
        }
        let payload: Vec<u8> = self.buf.drain(..header.len).collect();
        let header = self.header.take().expect("header parsed above");
        if self.verify_checksum && checksum(&payload) != header.checksum {
            return Err(ProtoError::BadChecksum);
        }
        Ok(Some(Packet {
            command: header.command,
            arg0: header.arg0,
            arg1: header.arg1,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(packet: &Packet) -> Vec<u8> {
        let mut bytes = packet.encode_header().to_vec();
        bytes.extend_from_slice(&packet.payload);
        bytes
    }

    fn decode_all(chunks: &[&[u8]]) -> Vec<Packet> {
        let mut decoder = PacketDecoder::new(1 << 20);
        let mut out = Vec::new();
        for chunk in chunks {
            decoder.push(chunk);
            while let Some(p) = decoder.next_packet().unwrap() {
                out.push(p);
            }
        }
        out
    }

    #[test]
    fn header_bytes_match_adb_wire_layout() {
        // command, arg0, arg1, len, byte-sum checksum, magic — little endian,
        // the same order `adb_client`'s ADBTransportMessageHeader encodes.
        let header = Packet::new(Command::Wrte, 1, 2, b"hello".to_vec()).encode_header();
        let expected: [u8; HEADER_LEN] = [
            0x57, 0x52, 0x54, 0x45, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00,
            0x00, 0x00, 0x14, 0x02, 0x00, 0x00, 0xA8, 0xAD, 0xAB, 0xBA,
        ];
        assert_eq!(header, expected);
    }

    #[test]
    fn round_trips_a_packet() {
        let packet = Packet::new(Command::Wrte, 1, 2, b"hello".to_vec());
        assert_eq!(decode_all(&[&wire(&packet)]), vec![packet]);
    }

    #[test]
    fn reassembles_any_fragmentation() {
        let packet = Packet::new(Command::Open, 7, 0, b"shell:getprop\0".to_vec());
        let bytes = wire(&packet);
        for size in [1, 7, HEADER_LEN, bytes.len()] {
            let chunks: Vec<&[u8]> = bytes.chunks(size).collect();
            assert_eq!(decode_all(&chunks), vec![packet.clone()], "chunk size {size}");
        }
    }

    #[test]
    fn splits_coalesced_packets() {
        let a = Packet::new(Command::Okay, 1, 2, Vec::new());
        let b = Packet::new(Command::Wrte, 1, 2, b"data".to_vec());
        let mut bytes = wire(&a);
        bytes.extend(wire(&b));
        assert_eq!(decode_all(&[&bytes]), vec![a, b]);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = wire(&Packet::new(Command::Okay, 1, 2, Vec::new()));
        bytes[20] ^= 1;
        let mut decoder = PacketDecoder::new(1 << 20);
        decoder.push(&bytes);
        assert_eq!(decoder.next_packet(), Err(ProtoError::BadMagic));
    }

    #[test]
    fn rejects_oversized_payload_before_it_arrives() {
        let bytes = wire(&Packet::new(Command::Wrte, 1, 2, vec![0; 32]));
        let mut decoder = PacketDecoder::new(16);
        decoder.push(&bytes[..HEADER_LEN]);
        assert_eq!(
            decoder.next_packet(),
            Err(ProtoError::PayloadTooLarge { len: 32, max: 16 })
        );
    }

    #[test]
    fn rejects_bad_checksum_unless_disabled() {
        let mut bytes = wire(&Packet::new(Command::Wrte, 1, 2, b"abc".to_vec()));
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes());
        let mut decoder = PacketDecoder::new(1 << 20);
        decoder.push(&bytes);
        assert_eq!(decoder.next_packet(), Err(ProtoError::BadChecksum));

        let mut decoder = PacketDecoder::new(1 << 20);
        decoder.set_verify_checksum(false);
        decoder.push(&bytes);
        assert!(decoder.next_packet().unwrap().is_some());
    }

    #[test]
    fn rejects_unknown_command() {
        let mut bytes = wire(&Packet::new(Command::Okay, 0, 0, Vec::new()));
        bytes[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let mut decoder = PacketDecoder::new(1 << 20);
        decoder.push(&bytes);
        assert_eq!(
            decoder.next_packet(),
            Err(ProtoError::UnknownCommand(0x1234_5678))
        );
    }
}
