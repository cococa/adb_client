use rand::RngExt;
use std::{path::Path, time::Duration};

use crate::{
    Result, RustADBError,
    message_devices::{
        adb_message_transport::ADBMessageTransport,
        adb_session::ADBSession,
        adb_transport_message::{
            ADBTransportMessage, AUTH_RSAPUBLICKEY, AUTH_SIGNATURE, AUTH_TOKEN,
        },
        message_commands::{MessageCommand, MessageSubcommand},
        models::{ADBRsaKey, read_adb_private_key},
        utils::BinaryEncodable,
    },
    models::ADBLocalCommand,
};

/// Generic structure representing an ADB device reachable over an [`ADBMessageTransport`].
/// Structure is totally agnostic over which transport is truly used.
#[derive(Debug)]
pub struct ADBMessageDevice<T: ADBMessageTransport> {
    transport: T,
}

impl<T: ADBMessageTransport> ADBMessageDevice<T> {
    /// Instantiate a new [`ADBMessageDevice`]
    pub fn new<P: AsRef<Path>>(transport: T, adb_private_key_path: P) -> Result<Self> {
        let private_key = if let Some(private_key) = read_adb_private_key(&adb_private_key_path)? {
            private_key
        } else {
            log::warn!(
                "No private key found at path {}. Generating a new random.",
                adb_private_key_path.as_ref().display()
            );
            let private_key = ADBRsaKey::new_random()?;
            private_key.write_pkcs8(&adb_private_key_path)?;
            private_key
        };

        let mut message_device = Self { transport };
        message_device.connect(&private_key)?;

        Ok(message_device)
    }

    pub(crate) const fn get_transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Transfers the authenticated transport to the packet dispatcher. Once
    /// moved, only the dispatcher may read USB packets; consumers receive
    /// packets by their ADB local-id instead of racing on the USB endpoint.
    pub(crate) fn into_transport(self) -> T {
        // Suppress the legacy disconnect while moving (not cloning) its sole
        // field. The dispatcher now owns and eventually drops the transport.
        let this = std::mem::ManuallyDrop::new(self);
        // SAFETY: this is never dropped or accessed again; transport is moved once.
        unsafe { std::ptr::read(&this.transport) }
    }

    pub(crate) fn into_dispatched(
        self,
    ) -> crate::message_devices::dispatched_device::DispatchedADBMessageDevice {
        crate::message_devices::dispatched_device::DispatchedADBMessageDevice::new(
            self.into_transport(),
        )
    }

    /// Send initial connect
    fn connect(&mut self, private_key: &ADBRsaKey) -> Result<()> {
        self.get_transport_mut().connect()?;

        let message = ADBTransportMessage::try_new(
            MessageCommand::Cnxn,
            0x0100_0000,
            1_048_576,
            format!("host::{}\0", env!("CARGO_PKG_NAME")).as_bytes(),
        )?;

        self.get_transport_mut().write_message(message)?;

        let message = self.get_transport_mut().read_message()?;

        // Check if a client is requesting a secure connection and upgrade it if necessary
        match message.header().command() {
            MessageCommand::Stls => {
                self.get_transport_mut()
                    .write_message(ADBTransportMessage::try_new(
                        MessageCommand::Stls,
                        1,
                        0,
                        &[],
                    )?)?;
                self.get_transport_mut().upgrade_connection()?;
                log::debug!("Connection successfully upgraded from TCP to TLS");
                Ok(())
            }
            MessageCommand::Cnxn => {
                log::debug!("Unencrypted connection established");
                Ok(())
            }
            MessageCommand::Auth => {
                log::debug!("Authentication required");
                self.auth_handshake(message, private_key)
            }
            _ => Err(crate::RustADBError::WrongResponseReceived(
                "Expected CNXN, STLS or AUTH command".to_string(),
                message.header().command().to_string(),
            )),
        }
    }

    fn auth_handshake(
        &mut self,
        message: ADBTransportMessage,
        private_key: &ADBRsaKey,
    ) -> Result<()> {
        match message.header().command() {
            MessageCommand::Auth => {
                log::debug!("Authentication required");
            }
            _ => return Ok(()),
        }

        // At this point, we should have received an AUTH message with arg0 == 1
        let auth_message = match message.header().arg0() {
            AUTH_TOKEN => message,
            v => {
                return Err(RustADBError::ADBRequestFailed(format!(
                    "Received AUTH message with type != 1 ({v})"
                )));
            }
        };

        // Devices can issue another token while the user is deciding the RSA
        // dialog. Alternate signature and public-key replies until adbd
        // confirms the connection, rather than treating that normal AUTH as a
        // protocol error.
        let mut response = auth_message;
        let mut send_public_key = false;
        for _ in 0..8 {
            match response.header().command() {
                MessageCommand::Cnxn => {
                    log::info!(
                        "Authentication OK, device info {}",
                        String::from_utf8(response.into_payload())?
                    );
                    return Ok(());
                }
                MessageCommand::Auth if response.header().arg0() == AUTH_TOKEN => {
                    let (auth_type, payload) = if send_public_key {
                        let mut public_key = private_key.android_pubkey_encode()?.into_bytes();
                        public_key.push(b'\0');
                        (AUTH_RSAPUBLICKEY, public_key)
                    } else {
                        (AUTH_SIGNATURE, private_key.sign(response.into_payload())?)
                    };
                    self.transport.write_message(ADBTransportMessage::try_new(
                        MessageCommand::Auth,
                        auth_type,
                        0,
                        &payload,
                    )?)?;
                    send_public_key = !send_public_key;
                    response = self
                        .transport
                        .read_message_with_timeout(Duration::from_secs(15))?;
                }
                MessageCommand::Auth => {
                    return Err(crate::RustADBError::ADBRequestFailed(format!(
                        "Received AUTH message with type != 1 ({})",
                        response.header().arg0()
                    )));
                }
                command => {
                    return Err(crate::RustADBError::WrongResponseReceived(
                        "Expected CNXN or AUTH command".to_string(),
                        command.to_string(),
                    ));
                }
            }
        }
        Err(crate::RustADBError::ADBRequestFailed(
            "Android device did not finish RSA authorization".to_string(),
        ))
    }

    pub(crate) fn open_synchronization_session(&mut self) -> Result<ADBSession<T>> {
        self.open_session(&ADBLocalCommand::Sync)
    }

    /// Installs a reverse socket rule directly on adbd. Unlike `host:forward`,
    /// this service is available over a direct USB ADB connection and is the
    /// foundation for the scrcpy server's connection back to the Mac.
    pub(crate) fn reverse_forward(&mut self, remote: String, local: String) -> Result<()> {
        let _session = self.open_session(&ADBLocalCommand::Reverse(remote, local))?;
        Ok(())
    }

    /// Register a reverse rule and keep this authenticated transport alive to
    /// relay device-initiated socket streams to the specified local TCP port.
    pub(crate) fn run_reverse_relay(&mut self, remote: String, local: String) -> Result<()> {
        self.reverse_forward(remote.clone(), local.clone())?;
        crate::message_devices::reverse_relay::ReverseRelay::new(
            &mut self.transport,
            remote,
            local,
        )?
        .run()
    }

    pub(crate) fn remove_reverse_forward(&mut self, remote: String) -> Result<()> {
        let _session = self.open_session(&ADBLocalCommand::ReverseRemove(remote))?;
        Ok(())
    }

    /// Open a new ADB session with the given local command.
    pub(crate) fn open_session(&mut self, cmd: &ADBLocalCommand) -> Result<ADBSession<T>> {
        let mut rng = rand::rng();
        let local_id: u32 = rng.random();

        // adbd used to expect a null-terminated string.
        // keep doing so to maintain compatibility with older versions.
        // https://cs.android.com/android/platform/superproject/+/android-latest-release:packages/modules/adb/sockets.cpp;l=560?q=sockets.cpp
        let mut destination = cmd.to_string().into_bytes();
        if !destination.ends_with(&[0]) {
            destination.push(0);
        }

        let message = ADBTransportMessage::try_new(
            MessageCommand::Open,
            local_id, // Our 'local-id'
            0,
            &destination,
        )?;
        self.transport.write_message(message)?;

        let response = self.transport.read_message()?;

        if response.header().command() != MessageCommand::Okay {
            return Err(RustADBError::ADBRequestFailed(format!(
                "Open session failed: got {} in response instead of OKAY",
                response.header().command()
            )));
        }

        if response.header().arg1() != local_id {
            return Err(RustADBError::ADBRequestFailed(format!(
                "Open session failed: responses used {} for our local_id instead of {local_id}",
                response.header().arg1()
            )));
        }

        Ok(ADBSession::new(
            self.transport.clone(),
            local_id,
            response.header().arg0(),
        ))
    }

    pub(crate) fn end_transaction(&mut self, session: &mut ADBSession<T>) -> Result<()> {
        let quit_buffer = MessageSubcommand::Quit.with_arg(0u32);
        session.send_and_expect_okay(ADBTransportMessage::try_new(
            MessageCommand::Write,
            session.local_id(),
            session.remote_id(),
            &quit_buffer.encode(),
        )?)?;

        let _discard_close = self.transport.read_message()?;
        Ok(())
    }
}

impl<T: ADBMessageTransport> Drop for ADBMessageDevice<T> {
    fn drop(&mut self) {
        // Best effort here
        let _ = self.get_transport_mut().disconnect();
    }
}
