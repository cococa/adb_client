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
}
