#![forbid(unsafe_code)]
#![doc = "Sans-IO core of the Android Debug Bridge wire protocol."]
#![doc = ""]
#![doc = "Nothing in this crate reads or writes a transport, spawns a thread or"]
#![doc = "consults a clock. Drivers feed received bytes in and drain packets to"]
#![doc = "send, so the same protocol logic runs over blocking native USB and over"]
#![doc = "asynchronous WebUSB in a browser."]

mod error;
pub mod auth;
pub mod message;

pub use error::ProtoError;
pub use message::{Command, Packet, PacketDecoder};
