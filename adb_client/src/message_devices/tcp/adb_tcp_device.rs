use std::io::Write;
use std::path::Path;
use std::{io::Read, net::SocketAddr};

use crate::message_devices::adb_message_device::ADBMessageDevice;
use crate::message_devices::dispatched_device::DispatchedADBMessageDevice;
use crate::models::RemountInfo;
use crate::tcp::tcp_transport::TcpTransport;
use crate::utils::get_default_adb_key_path;
use crate::{ADBDeviceExt, ADBListItemType, Result};

/// Represent a device reached and available over TCP.
#[derive(Debug)]
pub struct ADBTcpDevice {
    inner: ADBMessageDevice<TcpTransport>,
}

/// A wireless ADB device whose packets are routed by one shared dispatcher.
#[derive(Debug)]
pub struct ADBDispatchedTCPDevice {
    inner: DispatchedADBMessageDevice,
}

impl ADBTcpDevice {
    /// Instantiate a new [`ADBTcpDevice`]
    pub fn new<A: Into<SocketAddr>>(address: A) -> Result<Self> {
        Self::new_with_custom_private_key(address, get_default_adb_key_path()?)
    }

    /// Instantiate a new [`ADBTcpDevice`] using a custom private key path
    pub fn new_with_custom_private_key<P: AsRef<Path>, A: Into<SocketAddr>>(
        address: A,
        private_key_path: P,
    ) -> Result<Self> {
        Ok(Self {
            inner: ADBMessageDevice::new(
                TcpTransport::new(address, &private_key_path),
                private_key_path,
            )?,
        })
    }

    /// Transfers this authenticated wireless connection to a packet dispatcher.
    #[must_use]
    pub fn into_dispatched(self) -> ADBDispatchedTCPDevice {
        ADBDispatchedTCPDevice {
            inner: self.inner.into_dispatched(),
        }
    }
}

impl ADBDispatchedTCPDevice {
    /// Runs a shell-v2 command and propagates the remote exit status.
    pub fn shell_command(
        &self,
        command: &str,
        output: Option<&mut dyn std::io::Write>,
    ) -> Result<()> {
        self.inner.shell_command(command, output)
    }

    /// Uploads a file through the authenticated dispatcher.
    pub fn push<R: std::io::Read>(&self, input: R, path: &str) -> Result<()> {
        self.inner.push(input, path)
    }

    /// Downloads a file through the authenticated dispatcher.
    pub fn pull(&self, path: &str, output: &mut dyn std::io::Write) -> Result<()> {
        self.inner.pull(path, output)
    }
    /// Serves a local TCP port and forwards accepted connections to `remote`.
    pub fn serve_forward(self: std::sync::Arc<Self>, local: String, remote: String) -> Result<()> {
        self.inner.serve_forward(local, remote, None)
    }

    /// Signals successful listener binding before serving connections.
    pub fn serve_forward_ready(
        self: std::sync::Arc<Self>,
        local: String,
        remote: String,
        ready: std::sync::mpsc::Sender<std::result::Result<(), String>>,
    ) -> Result<()> {
        let result = self.inner.serve_forward(local, remote, Some(&ready));
        if let Err(error) = &result {
            let _ = ready.send(Err(error.to_string()));
        }
        result
    }

    /// Lists local-to-remote forwarding rules owned by this connection.
    #[must_use]
    pub fn forward_routes(&self) -> Vec<(String, String)> {
        self.inner.forward_routes()
    }

    /// Stops one local forwarding rule.
    pub fn remove_forward(&self, local: &str) -> bool {
        self.inner.remove_forward(local)
    }

    /// Stops all local forwarding rules.
    pub fn remove_all_forwards(&self) -> usize {
        self.inner.remove_all_forwards()
    }

    /// Whether the wireless transport remains connected.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }
}

impl ADBDeviceExt for ADBTcpDevice {
    #[inline]
    fn reverse_forward(&mut self, remote: String, local: String) -> Result<()> {
        self.inner.reverse_forward(remote, local)
    }

    #[inline]
    fn run_reverse_relay(&mut self, remote: String, local: String) -> Result<()> {
        self.inner.run_reverse_relay(remote, local)
    }

    #[inline]
    fn remove_reverse_forward(&mut self, remote: String) -> Result<()> {
        self.inner.remove_reverse_forward(remote)
    }

    #[inline]
    fn shell_command(
        &mut self,
        command: &dyn AsRef<str>,
        stdout: Option<&mut dyn Write>,
        stderr: Option<&mut dyn Write>,
    ) -> Result<Option<u8>> {
        self.inner.shell_command(command, stdout, stderr)
    }

    #[inline]
    fn shell(&mut self, reader: &mut dyn Read, writer: Box<dyn Write + Send>) -> Result<()> {
        self.inner.shell(reader, writer)
    }

    #[inline]
    fn stat(&mut self, remote_path: &dyn AsRef<str>) -> Result<crate::AdbStatResponse> {
        self.inner.stat(remote_path)
    }

    #[inline]
    fn pull(&mut self, source: &dyn AsRef<str>, output: &mut dyn Write) -> Result<()> {
        self.inner.pull(source, output)
    }

    #[inline]
    fn push(&mut self, stream: &mut dyn Read, path: &dyn AsRef<str>) -> Result<()> {
        self.inner.push(stream, path)
    }

    #[inline]
    fn reboot(&mut self, reboot_type: crate::RebootType) -> Result<()> {
        self.inner.reboot(reboot_type)
    }

    #[inline]
    fn remount(&mut self) -> Result<Vec<RemountInfo>> {
        self.inner.remount()
    }

    #[inline]
    fn root(&mut self) -> Result<()> {
        self.inner.root()
    }

    #[inline]
    fn install(&mut self, apk_path: &dyn AsRef<Path>, user: Option<&str>) -> Result<()> {
        self.inner.install(apk_path, user)
    }

    #[inline]
    fn uninstall(&mut self, package: &dyn AsRef<str>, user: Option<&str>) -> Result<()> {
        self.inner.uninstall(package, user)
    }

    #[inline]
    fn enable_verity(&mut self) -> Result<()> {
        self.inner.enable_verity()
    }

    #[inline]
    fn disable_verity(&mut self) -> Result<()> {
        self.inner.disable_verity()
    }

    #[inline]
    #[cfg(feature = "framebuffer")]
    fn framebuffer_inner(&mut self) -> Result<image::ImageBuffer<image::Rgba<u8>, Vec<u8>>> {
        self.inner.framebuffer_inner()
    }

    #[inline]
    fn list(&mut self, path: &dyn AsRef<str>) -> Result<Vec<ADBListItemType>> {
        self.inner.list(path)
    }

    #[inline]
    fn exec(
        &mut self,
        command: &str,
        reader: &mut dyn Read,
        writer: Box<dyn Write + Send>,
    ) -> Result<()> {
        self.inner.exec(command, reader, writer)
    }
}
