//! Framing for the `sync:` file-transfer service (AOSP file_sync_protocol.h).
//!
//! Each request is a 4-byte id plus a little-endian u32, optionally followed
//! by that many bytes. Frames are written into a `sync:` stream opened with
//! [`crate::Session::open`].

use crate::ProtoError;

/// Largest DATA chunk adbd accepts.
pub const MAX_DATA_CHUNK: usize = 64 * 1024;

fn frame(id: &[u8; 4], arg: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(id);
    out.extend_from_slice(&arg.to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn len_u32(len: usize) -> u32 {
    u32::try_from(len).expect("sync frame fits in u32")
}

/// `SEND` for `remote_path` with a full `st_mode`, e.g. `0o100644`.
pub fn send_request(remote_path: &str, mode: u32) -> Vec<u8> {
    let spec = format!("{remote_path},{mode}");
    frame(b"SEND", len_u32(spec.len()), spec.as_bytes())
}

/// AOSP v1 sync requests share the same eight-byte header and UTF-8 path.
pub fn stat_request(path: &str) -> Vec<u8> {
    frame(b"STAT", len_u32(path.len()), path.as_bytes())
}

pub fn list_request(path: &str) -> Vec<u8> {
    frame(b"LIST", len_u32(path.len()), path.as_bytes())
}

pub fn recv_request(path: &str) -> Vec<u8> {
    frame(b"RECV", len_u32(path.len()), path.as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    Stat,
    List,
    Recv,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncEvent {
    Stat {
        mode: u32,
        size: u32,
        mtime: u32,
    },
    Dent {
        mode: u32,
        size: u32,
        mtime: u32,
        name: String,
    },
    Data(Vec<u8>),
    Done,
    Fail(String),
}

/// Incremental parser for AOSP's v1 STAT/LIST/RECV replies. Feed arbitrary
/// transport fragments with `push`, then drain available events.
pub struct SyncReader {
    kind: SyncKind,
    bytes: Vec<u8>,
    complete: bool,
}

impl SyncReader {
    pub fn new(kind: SyncKind) -> Self {
        Self {
            kind,
            bytes: Vec::new(),
            complete: false,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        if !self.complete {
            self.bytes.extend_from_slice(bytes);
        }
    }

    pub fn next_event(&mut self) -> Result<Option<SyncEvent>, ProtoError> {
        if self.complete || self.bytes.len() < 4 {
            return Ok(None);
        }
        let id = &self.bytes[..4];
        let (len, event, terminal) = if id == b"STAT" && self.kind == SyncKind::Stat {
            if self.bytes.len() < 16 {
                return Ok(None);
            }
            let event = SyncEvent::Stat {
                mode: word(&self.bytes[4..8]),
                size: word(&self.bytes[8..12]),
                mtime: word(&self.bytes[12..16]),
            };
            (16, event, true)
        } else if id == b"DENT" && self.kind == SyncKind::List {
            if self.bytes.len() < 20 {
                return Ok(None);
            }
            let name_len = word(&self.bytes[16..20]) as usize;
            if name_len > 1024 {
                return Err(protocol("directory entry name exceeds 1024 bytes"));
            }
            if self.bytes.len() < 20 + name_len {
                return Ok(None);
            }
            let event = SyncEvent::Dent {
                mode: word(&self.bytes[4..8]),
                size: word(&self.bytes[8..12]),
                mtime: word(&self.bytes[12..16]),
                name: String::from_utf8_lossy(&self.bytes[20..20 + name_len]).into_owned(),
            };
            (20 + name_len, event, false)
        } else if id == b"DATA" && self.kind == SyncKind::Recv {
            if self.bytes.len() < 8 {
                return Ok(None);
            }
            let size = word(&self.bytes[4..8]) as usize;
            if size > MAX_DATA_CHUNK {
                return Err(protocol("DATA exceeds 64 KiB"));
            }
            if self.bytes.len() < 8 + size {
                return Ok(None);
            }
            (
                8 + size,
                SyncEvent::Data(self.bytes[8..8 + size].to_vec()),
                false,
            )
        } else if id == b"DONE" && self.kind != SyncKind::Stat {
            let len = if self.kind == SyncKind::List { 20 } else { 8 };
            if self.bytes.len() < len {
                return Ok(None);
            }
            (len, SyncEvent::Done, true)
        } else if id == b"FAIL" {
            if self.bytes.len() < 8 {
                return Ok(None);
            }
            let size = word(&self.bytes[4..8]) as usize;
            if size > 4096 {
                return Err(protocol("FAIL message exceeds 4096 bytes"));
            }
            if self.bytes.len() < 8 + size {
                return Ok(None);
            }
            let text = String::from_utf8_lossy(&self.bytes[8..8 + size]).into_owned();
            (8 + size, SyncEvent::Fail(text), true)
        } else {
            return Err(protocol(format!(
                "unexpected sync reply {:?}",
                String::from_utf8_lossy(id)
            )));
        };
        self.bytes.drain(..len);
        if terminal {
            self.complete = true;
        }
        Ok(Some(event))
    }
}

fn word(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("four bytes"))
}

fn protocol(message: impl Into<String>) -> ProtoError {
    ProtoError::Protocol(message.into())
}

/// `DATA` frames of at most [`MAX_DATA_CHUNK`] bytes each.
pub fn data_frames(bytes: &[u8]) -> impl Iterator<Item = Vec<u8>> + '_ {
    bytes
        .chunks(MAX_DATA_CHUNK)
        .map(|chunk| frame(b"DATA", len_u32(chunk.len()), chunk))
}

/// `DONE` with the file's modification time in seconds since the epoch.
pub fn done(mtime: u32) -> Vec<u8> {
    frame(b"DONE", mtime, &[])
}

pub fn quit() -> Vec<u8> {
    frame(b"QUIT", 0, &[])
}

/// Parses the reply to `DONE`: `OKAY` with a zero argument, or `FAIL` with a
/// message. Returns `Ok(None)` until the whole reply has arrived.
pub fn parse_status(bytes: &[u8]) -> Result<Option<usize>, ProtoError> {
    if bytes.len() < 8 {
        return Ok(None);
    }
    let arg = u32::from_le_bytes(bytes[4..8].try_into().expect("4 bytes")) as usize;
    match &bytes[..4] {
        b"OKAY" => Ok(Some(8)),
        b"FAIL" => {
            if bytes.len() < 8 + arg {
                return Ok(None);
            }
            Err(ProtoError::Protocol(format!(
                "file transfer failed: {}",
                String::from_utf8_lossy(&bytes[8..8 + arg])
            )))
        }
        other => Err(ProtoError::Protocol(format!(
            "unexpected sync reply {:?}",
            String::from_utf8_lossy(other)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_request_layout() {
        // 0o100644 == 33188; adbd parses the mode with strtoul(base 0).
        let spec = b"/data/local/tmp/a.jar,33188";
        let mut expected = b"SEND".to_vec();
        expected.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        expected.extend_from_slice(spec);
        assert_eq!(send_request("/data/local/tmp/a.jar", 0o100644), expected);
    }

    #[test]
    fn data_is_split_into_64k_frames() {
        let bytes = vec![7u8; MAX_DATA_CHUNK * 2 + 3];
        let frames: Vec<_> = data_frames(&bytes).collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(&frames[0][..4], b"DATA");
        assert_eq!(&frames[0][4..8], &(MAX_DATA_CHUNK as u32).to_le_bytes());
        assert_eq!(frames[0].len(), 8 + MAX_DATA_CHUNK);
        assert_eq!(&frames[2][4..8], &3u32.to_le_bytes());
        assert_eq!(&frames[2][8..], &[7, 7, 7]);
    }

    #[test]
    fn done_and_quit_layout() {
        assert_eq!(done(0x0102_0304), b"DONE\x04\x03\x02\x01");
        assert_eq!(quit(), b"QUIT\0\0\0\0");
    }

    #[test]
    fn parses_status_replies() {
        assert_eq!(parse_status(b"OKA"), Ok(None));
        assert_eq!(parse_status(b"OKAY\0\0\0\0"), Ok(Some(8)));
        assert_eq!(parse_status(b"FAIL\x05\0\0\0den"), Ok(None));
        assert_eq!(
            parse_status(b"FAIL\x06\0\0\0denied"),
            Err(ProtoError::Protocol("file transfer failed: denied".into()))
        );
        assert!(parse_status(b"WHAT\0\0\0\0").is_err());
    }

    #[test]
    fn read_request_layouts_follow_aosp_sync_request() {
        // AOSP file_sync_protocol.h: four ASCII ID bytes, LE path byte count,
        // then UTF-8 path bytes without a trailing NUL.
        assert_eq!(stat_request("/sdcard/é"), b"STAT\x0a\0\0\0/sdcard/\xc3\xa9");
        assert_eq!(list_request("/sdcard"), b"LIST\x07\0\0\0/sdcard");
        assert_eq!(recv_request("/a"), b"RECV\x02\0\0\0/a");
    }

    #[test]
    fn reads_stat_and_multiple_directory_entries_by_single_bytes() {
        // AOSP sync_stat_v1 is 16 bytes, sync_dent_v1 is 20 plus namelen.
        let stat = b"STAT\xa4\x81\0\0\x03\0\0\0\x04\0\0\0";
        let mut reader = SyncReader::new(SyncKind::Stat);
        for byte in stat.iter().take(stat.len() - 1) {
            reader.push(&[*byte]);
            assert_eq!(reader.next_event().unwrap(), None);
        }
        reader.push(&stat[stat.len() - 1..]);
        assert_eq!(
            reader.next_event().unwrap(),
            Some(SyncEvent::Stat {
                mode: 0o100644,
                size: 3,
                mtime: 4
            })
        );

        let list = b"DENT\xed\x41\0\0\0\0\0\0\x04\0\0\0\x03\0\0\0dir\
                     DENT\xa4\x81\0\0\x05\0\0\0\x06\0\0\0\x01\0\0\0x\
                     DONE\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let mut reader = SyncReader::new(SyncKind::List);
        let mut events = Vec::new();
        for byte in list {
            reader.push(&[*byte]);
            while let Some(event) = reader.next_event().unwrap() {
                events.push(event);
            }
        }
        assert_eq!(
            events,
            vec![
                SyncEvent::Dent {
                    mode: 0o40755,
                    size: 0,
                    mtime: 4,
                    name: "dir".into()
                },
                SyncEvent::Dent {
                    mode: 0o100644,
                    size: 5,
                    mtime: 6,
                    name: "x".into()
                },
                SyncEvent::Done,
            ]
        );
    }

    #[test]
    fn reads_data_done_and_fail_incrementally() {
        let mut reader = SyncReader::new(SyncKind::Recv);
        reader.push(b"DATA\x03\0\0\0abcDATA\x02\0\0\0deDONE\0\0\0\0");
        assert_eq!(
            reader.next_event().unwrap(),
            Some(SyncEvent::Data(b"abc".to_vec()))
        );
        assert_eq!(
            reader.next_event().unwrap(),
            Some(SyncEvent::Data(b"de".to_vec()))
        );
        assert_eq!(reader.next_event().unwrap(), Some(SyncEvent::Done));
        assert_eq!(reader.next_event().unwrap(), None);

        let mut reader = SyncReader::new(SyncKind::Recv);
        reader.push(b"FAIL\x06\0\0\0den");
        assert_eq!(reader.next_event().unwrap(), None);
        reader.push(b"ied");
        assert_eq!(
            reader.next_event().unwrap(),
            Some(SyncEvent::Fail("denied".into()))
        );
    }

    #[test]
    fn rejects_oversize_data_and_wrong_reply() {
        let mut reader = SyncReader::new(SyncKind::Recv);
        reader.push(b"DATA\x01\0\x01\0");
        assert!(reader.next_event().is_err());
        let mut reader = SyncReader::new(SyncKind::List);
        reader.push(b"DATA\0\0\0\0");
        assert!(reader.next_event().is_err());
    }
}
