use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::ADBDeviceExt;
use crate::ADBListItemType;
use crate::Result;
use crate::RustADBError;
use crate::message_devices::adb_message_device::ADBMessageDevice;
use crate::message_devices::dispatched_device::DispatchedADBMessageDevice;
use crate::models::RemountInfo;
use crate::usb::usb_transport::USBTransport;
use crate::usb::utils;
use crate::utils::get_default_adb_key_path;

/// Represent a device reached and available over USB.
#[derive(Debug)]
pub struct ADBUSBDevice {
    inner: ADBMessageDevice<USBTransport>,
    vendor_id: u16,
    product_id: u16,
}

/// A direct USB device whose packets are routed by one shared dispatcher.
#[derive(Debug)]
pub struct ADBDispatchedUSBDevice {
    inner: DispatchedADBMessageDevice,
    vendor_id: u16,
    product_id: u16,
}

impl ADBUSBDevice {
    /// Instantiate a new [`ADBUSBDevice`]
    pub fn new(vendor_id: u16, product_id: u16) -> Result<Self> {
        Self::new_with_custom_private_key(vendor_id, product_id, get_default_adb_key_path()?)
    }

    /// Instantiate a new [`ADBUSBDevice`] using a custom private key path
    pub fn new_with_custom_private_key<P: AsRef<Path>>(
        vendor_id: u16,
        product_id: u16,
        private_key_path: P,
    ) -> Result<Self> {
        Self::new_from_transport_inner(USBTransport::new(vendor_id, product_id)?, private_key_path)
    }

    /// Instantiate a new [`ADBUSBDevice`] from a [`USBTransport`] and an optional private key path.
    pub fn new_from_transport(
        transport: USBTransport,
        private_key_path: Option<PathBuf>,
    ) -> Result<Self> {
        let private_key_path = match private_key_path {
            Some(private_key_path) => private_key_path,
            None => get_default_adb_key_path()?,
        };

        Self::new_from_transport_inner(transport, &private_key_path)
    }

    fn new_from_transport_inner<P: AsRef<Path>>(
        transport: USBTransport,
        private_key_path: P,
    ) -> Result<Self> {
        let vendor_id = transport.vendor_id()?;
        let product_id = transport.product_id()?;

        Ok(Self {
            inner: ADBMessageDevice::new(transport, private_key_path)?,
            vendor_id,
            product_id,
        })
    }

    /// Returns the vendor ID of the device
    #[must_use]
    pub const fn vendor_id(&self) -> u16 {
        self.vendor_id
    }

    /// Returns the product ID of the device
    #[must_use]
    pub const fn product_id(&self) -> u16 {
        self.product_id
    }

    /// Autodetect connected ADB devices and establish a connection with the first device found
    ///
    /// # Errors
    ///
    /// Returns an error if multiple devices or none are connected.
    pub fn autodetect() -> Result<Self> {
        Self::autodetect_with_custom_private_key(get_default_adb_key_path()?)
    }

    /// Autodetect connected ADB devices and establish a connection with the first device found using a custom private key path
    ///
    /// # Errors
    ///
    /// Returns an error if multiple devices are connected or if none can be detected.
    pub fn autodetect_with_custom_private_key(private_key_path: PathBuf) -> Result<Self> {
        match utils::get_single_connected_adb_device()? {
            Some(device_info) => Self::new_with_custom_private_key(
                device_info.vendor_id,
                device_info.product_id,
                private_key_path,
            ),
            _ => Err(RustADBError::DeviceNotFound(
                "cannot find USB devices matching the signature of an ADB device".into(),
            )),
        }
    }

    /// Installs a direct-USB reverse socket rule on the Android device.
    ///
    /// `remote` is the device-side endpoint (for example
    /// `localabstract:scrcpy`) and `local` is the Mac TCP endpoint.
    pub fn reverse_forward(&mut self, remote: String, local: String) -> Result<()> {
        self.inner.reverse_forward(remote, local)
    }

    /// Register and serve one direct-USB reverse route until its transport is
    /// disconnected. This is the data plane used by the scrcpy socket relay.
    pub fn run_reverse_relay(&mut self, remote: String, local: String) -> Result<()> {
        self.inner.run_reverse_relay(remote, local)
    }

    /// Remove a previously registered direct-USB reverse rule.
    pub fn remove_reverse_forward(&mut self, remote: String) -> Result<()> {
        self.inner.remove_reverse_forward(remote)
    }

    /// Transfers the authenticated USB connection to the one-reader dispatcher.
    pub fn into_dispatched(self) -> ADBDispatchedUSBDevice {
        ADBDispatchedUSBDevice {
            inner: self.inner.into_dispatched(),
            vendor_id: self.vendor_id,
            product_id: self.product_id,
        }
    }
}

impl ADBDispatchedUSBDevice {
    /// Serves local TCP forwarding through the authenticated USB transport.
    pub fn serve_forward(self: std::sync::Arc<Self>, local: String, remote: String) -> Result<()> {
        self.inner.serve_forward(local, remote)
    }
    /// Lists local-to-remote TCP forwarding rules owned by this connection.
    pub fn forward_routes(&self) -> Vec<(String, String)> { self.inner.forward_routes() }
    /// Stops a local TCP forwarding rule and returns whether it existed.
    pub fn remove_forward(&self, local: &str) -> bool { self.inner.remove_forward(local) }
    /// Returns reverse routes registered on this device.
    pub fn reverse_routes(&self) -> Result<Vec<(String, String)>> { self.inner.reverse_routes() }
    /// Removes all reverse routes registered by this client.
    pub fn remove_all_reverse_routes(&self) -> Result<()> { self.inner.remove_all_reverse_routes() }
    /// Requests an adbd restart with root privileges.
    pub fn root(&self) -> Result<()> { self.inner.root() }
    /// Requests a remount of writable partitions.
    pub fn remount(&self) -> Result<()> { self.inner.remount() }
    /// Whether the USB reader is still connected.
    pub fn is_alive(&self) -> bool { self.inner.is_alive() }

    /// Downloads a file through the shared USB sync transport.
    pub fn pull(&self, path: &str, output: &mut dyn Write) -> Result<()> {
        self.inner.pull(path, output)
    }

    /// Streams raw command output through the shared USB transport.
    pub fn exec_out(&self, command: &str, output: &mut dyn Write) -> Result<()> {
        self.inner.exec_out(command, output)
    }

    /// Executes a shell command through a routed ADB session.
    pub fn shell_command(&self, command: &str, stdout: Option<&mut dyn Write>) -> Result<()> {
        self.inner.shell_command(command, stdout)
    }

    /// Uploads a file through a routed sync session.
    pub fn push<R: Read>(&self, input: R, path: &str) -> Result<()> {
        self.inner.push(input, path)
    }

    /// Registers a reverse route through the shared transport.
    pub fn reverse_forward(&self, remote: String, local: String) -> Result<()> {
        self.inner.reverse_forward(remote, local)
    }

    /// Removes a reverse route through the shared transport.
    pub fn remove_reverse_forward(&self, remote: String) -> Result<()> {
        self.inner.remove_reverse_forward(remote)
    }
}

impl ADBDeviceExt for ADBUSBDevice {
    #[inline]
    fn reverse_forward(&mut self, remote: String, local: String) -> Result<()> {
        self.reverse_forward(remote, local)
    }

    #[inline]
    fn run_reverse_relay(&mut self, remote: String, local: String) -> Result<()> {
        self.run_reverse_relay(remote, local)
    }

    #[inline]
    fn remove_reverse_forward(&mut self, remote: String) -> Result<()> {
        self.remove_reverse_forward(remote)
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
    fn shell<'a>(&mut self, reader: &mut dyn Read, writer: Box<dyn Write + Send>) -> Result<()> {
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
