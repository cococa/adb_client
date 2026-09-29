//! Connection handshake and stream multiplexing as a pure state machine.
//!
//! Drivers loop: send everything from [`Session::poll_transmit`], feed
//! received bytes to [`Session::handle_input`], then drain
//! [`Session::poll_event`].

use std::collections::{BTreeMap, VecDeque};

use crate::ProtoError;
use crate::auth::AdbKey;
use crate::message::{Command, Packet, PacketDecoder};

const AUTH_TOKEN: u32 = 1;
const AUTH_SIGNATURE: u32 = 2;
const AUTH_RSAPUBLICKEY: u32 = 3;
/// First protocol version whose packets carry no payload checksum.
const VERSION_SKIP_CHECKSUM: u32 = 0x0100_0001;

#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// Protocol version announced in CNXN.
    pub version: u32,
    /// Largest payload this host accepts.
    pub max_payload: u32,
    /// System identity announced in CNXN, e.g. `host::andro-connect`.
    pub system_identity: String,
    /// Label shown on the phone's "Allow USB debugging?" prompt.
    pub key_comment: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            version: 0x0100_0000,
            max_payload: 1024 * 1024,
            system_identity: "host::adb_proto".to_owned(),
            key_comment: "adb_proto".to_owned(),
        }
    }
}

/// Device properties announced in its CNXN banner.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeviceBanner {
    pub product: Option<String>,
    pub model: Option<String>,
    pub device: Option<String>,
    pub features: Vec<String>,
}

impl DeviceBanner {
    /// Parses `device::ro.product.name=x;ro.product.model=y;...;features=a,b`.
    pub fn parse(banner: &str) -> Self {
        let props = banner
            .trim_end_matches('\0')
            .split_once("::")
            .map_or("", |(_, props)| props);
        let mut out = Self::default();
        for (key, value) in props.split(';').filter_map(|kv| kv.split_once('=')) {
            match key {
                "ro.product.name" => out.product = Some(value.to_owned()),
                "ro.product.model" => out.model = Some(value.to_owned()),
                "ro.product.device" => out.device = Some(value.to_owned()),
                "features" => out.features = value.split(',').map(str::to_owned).collect(),
                _ => {}
            }
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    /// The public key was offered; the user must allow it on the phone.
    AwaitingUserApproval,
    Connected(DeviceBanner),
    StreamOpened {
        local_id: u32,
    },
    /// Call [`Session::ack`] once consumed; the device sends nothing more on
    /// this stream until then.
    StreamData {
        local_id: u32,
        data: Vec<u8>,
    },
    /// The device closed the stream, or refused to open it.
    StreamClosed {
        local_id: u32,
    },
}

#[derive(Debug, Eq, PartialEq)]
enum State {
    Idle,
    Handshaking,
    Connected,
}

#[derive(Default)]
struct Stream {
    remote_id: Option<u32>,
    outbox: VecDeque<u8>,
    write_in_flight: bool,
}

pub struct Session {
    config: SessionConfig,
    key: AdbKey,
    state: State,
    decoder: PacketDecoder,
    transmit: VecDeque<Packet>,
    events: VecDeque<Event>,
    send_public_key_next: bool,
    peer_max_payload: usize,
    streams: BTreeMap<u32, Stream>,
    next_local_id: u32,
}

impl Session {
    pub fn new(config: SessionConfig, key: AdbKey) -> Self {
        let decoder = PacketDecoder::new(config.max_payload);
        Self {
            config,
            key,
            state: State::Idle,
            decoder,
            transmit: VecDeque::new(),
            events: VecDeque::new(),
            send_public_key_next: false,
            peer_max_payload: 4096,
            streams: BTreeMap::new(),
            next_local_id: 1,
        }
    }

    /// Queues the CNXN that starts the handshake.
    pub fn start(&mut self) {
        let mut identity = self.config.system_identity.clone().into_bytes();
        identity.push(0);
        self.transmit.push_back(Packet::new(
            Command::Cnxn,
            self.config.version,
            self.config.max_payload,
            identity,
        ));
        self.state = State::Handshaking;
    }

    pub fn is_connected(&self) -> bool {
        self.state == State::Connected
    }

    pub fn poll_transmit(&mut self) -> Option<Packet> {
        self.transmit.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn handle_input(&mut self, bytes: &[u8]) -> Result<(), ProtoError> {
        self.decoder.push(bytes);
        while let Some(packet) = self.decoder.next_packet()? {
            self.handle_packet(packet)?;
        }
        Ok(())
    }

    /// Opens a stream to a device service such as `shell:ls` and returns its
    /// local id; [`Event::StreamOpened`] or [`Event::StreamClosed`] follows.
    pub fn open(&mut self, service: &str) -> Result<u32, ProtoError> {
        self.require_connected()?;
        let local_id = self.next_local_id;
        self.next_local_id += 1;
        let mut payload = service.as_bytes().to_vec();
        payload.push(0);
        self.transmit
            .push_back(Packet::new(Command::Open, local_id, 0, payload));
        self.streams.insert(local_id, Stream::default());
        Ok(local_id)
    }

    /// Queues data; it is sent in peer-sized chunks, one WRTE in flight at a
    /// time, as the device acknowledges each chunk.
    pub fn write(&mut self, local_id: u32, data: &[u8]) -> Result<(), ProtoError> {
        let stream = self
            .streams
            .get_mut(&local_id)
            .ok_or_else(|| ProtoError::Protocol(format!("stream {local_id} is not open")))?;
        stream.outbox.extend(data);
        self.flush(local_id);
        Ok(())
    }

    /// Bytes queued on a stream but not yet acknowledged by the device.
    pub fn pending_write_len(&self, local_id: u32) -> usize {
        self.streams.get(&local_id).map_or(0, |s| s.outbox.len())
    }

    /// Acknowledges one [`Event::StreamData`], letting the device send more.
    pub fn ack(&mut self, local_id: u32) {
        if let Some(remote_id) = self.streams.get(&local_id).and_then(|s| s.remote_id) {
            self.transmit
                .push_back(Packet::new(Command::Okay, local_id, remote_id, Vec::new()));
        }
    }

    pub fn close(&mut self, local_id: u32) {
        if let Some(stream) = self.streams.remove(&local_id) {
            self.transmit.push_back(Packet::new(
                Command::Clse,
                local_id,
                stream.remote_id.unwrap_or(0),
                Vec::new(),
            ));
        }
    }

    fn require_connected(&self) -> Result<(), ProtoError> {
        if self.is_connected() {
            Ok(())
        } else {
            Err(ProtoError::Protocol("device is not connected".to_owned()))
        }
    }

    fn flush(&mut self, local_id: u32) {
        let max = self.peer_max_payload;
        let Some(stream) = self.streams.get_mut(&local_id) else {
            return;
        };
        let Some(remote_id) = stream.remote_id else {
            return;
        };
        if stream.write_in_flight || stream.outbox.is_empty() {
            return;
        }
        let len = stream.outbox.len().min(max);
        let chunk: Vec<u8> = stream.outbox.drain(..len).collect();
        stream.write_in_flight = true;
        self.transmit
            .push_back(Packet::new(Command::Wrte, local_id, remote_id, chunk));
    }

    fn handle_packet(&mut self, packet: Packet) -> Result<(), ProtoError> {
        match (&self.state, packet.command) {
            (State::Handshaking, Command::Cnxn) => {
                let negotiated = packet.arg0.min(self.config.version);
                self.decoder
                    .set_verify_checksum(negotiated < VERSION_SKIP_CHECKSUM);
                self.peer_max_payload = packet.arg1.clamp(1, self.config.max_payload) as usize;
                self.state = State::Connected;
                let banner = String::from_utf8_lossy(&packet.payload);
                self.events
                    .push_back(Event::Connected(DeviceBanner::parse(&banner)));
                Ok(())
            }
            (State::Handshaking, Command::Auth) if packet.arg0 == AUTH_TOKEN => {
                // Devices re-issue tokens while the user decides; alternate
                // signature and public-key replies like adb_client does.
                if self.send_public_key_next {
                    let key = self.key.android_public_key(&self.config.key_comment)?;
                    self.transmit
                        .push_back(Packet::new(Command::Auth, AUTH_RSAPUBLICKEY, 0, key));
                    self.events.push_back(Event::AwaitingUserApproval);
                } else {
                    let signature = self.key.sign_token(&packet.payload)?;
                    self.transmit.push_back(Packet::new(
                        Command::Auth,
                        AUTH_SIGNATURE,
                        0,
                        signature,
                    ));
                }
                self.send_public_key_next = !self.send_public_key_next;
                Ok(())
            }
            (State::Handshaking, Command::Stls) => Err(ProtoError::Protocol(
                "TLS is not supported on this transport".to_owned(),
            )),
            (State::Connected, Command::Okay) => {
                self.on_okay(packet.arg0, packet.arg1);
                Ok(())
            }
            (State::Connected, Command::Wrte) => {
                self.on_write(packet.arg0, packet.arg1, packet.payload);
                Ok(())
            }
            (State::Connected, Command::Clse) => {
                if self.streams.remove(&packet.arg1).is_some() {
                    self.events.push_back(Event::StreamClosed {
                        local_id: packet.arg1,
                    });
                }
                Ok(())
            }
            (state, command) => Err(ProtoError::Protocol(format!(
                "unexpected {command:?} while {state:?}"
            ))),
        }
    }

    fn on_okay(&mut self, remote_id: u32, local_id: u32) {
        let Some(stream) = self.streams.get_mut(&local_id) else {
            return;
        };
        if stream.remote_id.is_none() {
            stream.remote_id = Some(remote_id);
            self.events.push_back(Event::StreamOpened { local_id });
        } else {
            stream.write_in_flight = false;
        }
        self.flush(local_id);
    }

    fn on_write(&mut self, remote_id: u32, local_id: u32, data: Vec<u8>) {
        if self.streams.contains_key(&local_id) {
            self.events.push_back(Event::StreamData { local_id, data });
        } else {
            // Unknown stream: tell the device to drop it.
            self.transmit
                .push_back(Packet::new(Command::Clse, 0, remote_id, Vec::new()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn key() -> AdbKey {
        static KEY: OnceLock<AdbKey> = OnceLock::new();
        KEY.get_or_init(|| {
            AdbKey::from_pkcs8_pem(include_str!("../tests/fixtures/test_key.pem")).unwrap()
        })
        .clone()
    }

    fn feed(session: &mut Session, packet: Packet) {
        let mut bytes = packet.encode_header().to_vec();
        bytes.extend_from_slice(&packet.payload);
        session.handle_input(&bytes).unwrap();
    }

    fn sent(session: &mut Session) -> Vec<Packet> {
        std::iter::from_fn(|| session.poll_transmit()).collect()
    }

    fn events(session: &mut Session) -> Vec<Event> {
        std::iter::from_fn(|| session.poll_event()).collect()
    }

    const BANNER: &[u8] = b"device::ro.product.name=p1;ro.product.model=Pixel 8;ro.product.device=shiba;features=shell_v2,cmd\0";

    fn device_cnxn(max_payload: u32) -> Packet {
        Packet::new(Command::Cnxn, 0x0100_0001, max_payload, BANNER.to_vec())
    }

    fn connected(max_payload: u32) -> Session {
        let mut s = Session::new(SessionConfig::default(), key());
        s.start();
        sent(&mut s);
        feed(&mut s, device_cnxn(max_payload));
        events(&mut s);
        s
    }

    fn opened(s: &mut Session, remote_id: u32) -> u32 {
        let id = s.open("shell:echo").unwrap();
        sent(s);
        feed(s, Packet::new(Command::Okay, remote_id, id, Vec::new()));
        events(s);
        id
    }

    #[test]
    fn start_sends_cnxn_with_identity() {
        let mut s = Session::new(SessionConfig::default(), key());
        s.start();
        let packets = sent(&mut s);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].command, Command::Cnxn);
        assert_eq!(packets[0].arg0, 0x0100_0000);
        assert_eq!(packets[0].arg1, 1024 * 1024);
        assert_eq!(packets[0].payload, b"host::adb_proto\0");
    }

    #[test]
    fn connects_without_auth() {
        let mut s = Session::new(SessionConfig::default(), key());
        s.start();
        sent(&mut s);
        feed(&mut s, device_cnxn(4096));
        assert!(s.is_connected());
        let banner = DeviceBanner {
            product: Some("p1".into()),
            model: Some("Pixel 8".into()),
            device: Some("shiba".into()),
            features: vec!["shell_v2".into(), "cmd".into()],
        };
        assert_eq!(events(&mut s), vec![Event::Connected(banner)]);
    }

    #[test]
    fn signs_first_token() {
        let mut s = Session::new(SessionConfig::default(), key());
        s.start();
        sent(&mut s);
        let token = vec![9u8; 20];
        feed(
            &mut s,
            Packet::new(Command::Auth, AUTH_TOKEN, 0, token.clone()),
        );
        let reply = sent(&mut s);
        assert_eq!(reply.len(), 1);
        assert_eq!(reply[0].arg0, AUTH_SIGNATURE);
        assert_eq!(reply[0].payload, key().sign_token(&token).unwrap());
        assert!(events(&mut s).is_empty());
        feed(&mut s, device_cnxn(4096));
        assert!(s.is_connected());
    }

    #[test]
    fn offers_public_key_after_rejected_signature() {
        let cfg = SessionConfig {
            key_comment: "andro-connect".into(),
            ..SessionConfig::default()
        };
        let mut s = Session::new(cfg, key());
        s.start();
        sent(&mut s);
        feed(
            &mut s,
            Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![1; 20]),
        );
        sent(&mut s);
        feed(
            &mut s,
            Packet::new(Command::Auth, AUTH_TOKEN, 0, vec![2; 20]),
        );
        let reply = sent(&mut s);
        assert_eq!(reply[0].arg0, AUTH_RSAPUBLICKEY);
        assert_eq!(
            reply[0].payload,
            key().android_public_key("andro-connect").unwrap()
        );
        assert_eq!(events(&mut s), vec![Event::AwaitingUserApproval]);
        feed(&mut s, device_cnxn(4096));
        assert!(s.is_connected());
    }

    #[test]
    fn rejects_stream_data_before_connect() {
        let mut s = Session::new(SessionConfig::default(), key());
        s.start();
        let mut bytes = Packet::new(Command::Wrte, 1, 1, b"x".to_vec())
            .encode_header()
            .to_vec();
        bytes.push(b'x');
        assert!(matches!(
            s.handle_input(&bytes),
            Err(ProtoError::Protocol(_))
        ));
    }

    #[test]
    fn open_before_connect_fails() {
        let mut s = Session::new(SessionConfig::default(), key());
        assert!(s.open("shell:").is_err());
    }

    #[test]
    fn opens_stream_on_okay() {
        let mut s = connected(4096);
        let id = s.open("shell:getprop").unwrap();
        let open = sent(&mut s);
        assert_eq!(open[0].command, Command::Open);
        assert_eq!(open[0].arg0, id);
        assert_eq!(open[0].payload, b"shell:getprop\0");
        feed(&mut s, Packet::new(Command::Okay, 77, id, Vec::new()));
        assert_eq!(events(&mut s), vec![Event::StreamOpened { local_id: id }]);
    }

    #[test]
    fn keeps_one_write_in_flight_in_peer_sized_chunks() {
        let mut s = connected(4);
        let id = opened(&mut s, 77);
        s.write(id, b"abcdefghij").unwrap();
        let first = sent(&mut s);
        assert_eq!(first.len(), 1);
        assert_eq!((first[0].command, first[0].arg1), (Command::Wrte, 77));
        assert_eq!(first[0].payload, b"abcd");
        assert_eq!(s.pending_write_len(id), 6);

        feed(&mut s, Packet::new(Command::Okay, 77, id, Vec::new()));
        assert_eq!(sent(&mut s)[0].payload, b"efgh");
        feed(&mut s, Packet::new(Command::Okay, 77, id, Vec::new()));
        assert_eq!(sent(&mut s)[0].payload, b"ij");
        feed(&mut s, Packet::new(Command::Okay, 77, id, Vec::new()));
        assert!(sent(&mut s).is_empty());
    }

    #[test]
    fn writes_queued_before_open_flush_on_open() {
        let mut s = connected(4096);
        let id = s.open("shell:cat").unwrap();
        s.write(id, b"early").unwrap();
        assert_eq!(sent(&mut s).len(), 1); // only OPEN
        feed(&mut s, Packet::new(Command::Okay, 5, id, Vec::new()));
        assert_eq!(sent(&mut s)[0].payload, b"early");
    }

    #[test]
    fn data_is_acknowledged_only_on_ack() {
        let mut s = connected(4096);
        let id = opened(&mut s, 77);
        feed(&mut s, Packet::new(Command::Wrte, 77, id, b"out".to_vec()));
        assert_eq!(
            events(&mut s),
            vec![Event::StreamData {
                local_id: id,
                data: b"out".to_vec()
            }]
        );
        assert!(sent(&mut s).is_empty());
        s.ack(id);
        let okay = sent(&mut s);
        assert_eq!(
            (okay[0].command, okay[0].arg0, okay[0].arg1),
            (Command::Okay, id, 77)
        );
    }

    #[test]
    fn refused_open_reports_closed() {
        let mut s = connected(4096);
        let id = s.open("localabstract:missing").unwrap();
        sent(&mut s);
        feed(&mut s, Packet::new(Command::Clse, 0, id, Vec::new()));
        assert_eq!(events(&mut s), vec![Event::StreamClosed { local_id: id }]);
        assert!(s.write(id, b"x").is_err());
    }

    #[test]
    fn interleaved_streams_do_not_mix() {
        let mut s = connected(4096);
        let a = opened(&mut s, 10);
        let b = opened(&mut s, 20);
        feed(&mut s, Packet::new(Command::Wrte, 20, b, b"B".to_vec()));
        feed(&mut s, Packet::new(Command::Wrte, 10, a, b"A".to_vec()));
        assert_eq!(
            events(&mut s),
            vec![
                Event::StreamData {
                    local_id: b,
                    data: b"B".to_vec()
                },
                Event::StreamData {
                    local_id: a,
                    data: b"A".to_vec()
                },
            ]
        );
    }

    #[test]
    fn unknown_stream_data_is_closed() {
        let mut s = connected(4096);
        feed(&mut s, Packet::new(Command::Wrte, 42, 99, b"x".to_vec()));
        let reply = sent(&mut s);
        assert_eq!((reply[0].command, reply[0].arg1), (Command::Clse, 42));
        assert!(events(&mut s).is_empty());
    }

    #[test]
    fn host_close_sends_clse() {
        let mut s = connected(4096);
        let id = opened(&mut s, 77);
        s.close(id);
        let clse = sent(&mut s);
        assert_eq!(
            (clse[0].command, clse[0].arg0, clse[0].arg1),
            (Command::Clse, id, 77)
        );
    }
}
