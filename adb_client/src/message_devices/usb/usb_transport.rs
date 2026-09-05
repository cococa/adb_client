use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use nusb::{DeviceInfo, MaybeFuture};

use super::utils::is_adb_device;
use crate::{
    Result, RustADBError,
    adb_transport::ADBTransport,
    message_devices::{
        adb_message_transport::ADBMessageTransport,
        adb_transport_message::{ADBTransportMessage, ADBTransportMessageHeader},
        message_commands::MessageCommand,
    },
};

// nusb discovers USB devices reliably on macOS. Its device-level IOKit open
// fails for some Android composite devices, whereas AOSP adb opens ff:42:01
// directly. The native bridge follows that public IOKit interface strategy.
#[cfg(target_os = "macos")]
mod macos_iokit {
    use std::ffi::c_void;
    #[repr(C)]
    pub struct Handle {
        _private: [u8; 0],
    }
    unsafe extern "C" {
        pub fn macadb_open(vendor_id: u16, product_id: u16, output: *mut *mut Handle) -> i32;
        pub fn macadb_read(
            handle: *mut Handle,
            buffer: *mut c_void,
            length: *mut u32,
            timeout_ms: u32,
        ) -> i32;
        pub fn macadb_write(
            handle: *mut Handle,
            buffer: *const c_void,
            length: u32,
            timeout_ms: u32,
        ) -> i32;
        pub fn macadb_max_packet_size(handle: *const Handle) -> u16;
        pub fn macadb_close(handle: *mut Handle);
    }
}

#[cfg(target_os = "macos")]
struct MacOSConnection {
    handle: *mut macos_iokit::Handle,
}
#[cfg(target_os = "macos")]
unsafe impl Send for MacOSConnection {}
#[cfg(target_os = "macos")]
impl Drop for MacOSConnection {
    fn drop(&mut self) {
        unsafe { macos_iokit::macadb_close(self.handle) };
    }
}

/// Direct USB transport. Device discovery is nusb; macOS transfer is through
/// AOSP-compatible, interface-level IOKit calls.
pub struct USBTransport {
    vendor_id: u16,
    product_id: u16,
    #[cfg(target_os = "macos")]
    connection: Option<Arc<Mutex<MacOSConnection>>>,
}

impl Clone for USBTransport {
    fn clone(&self) -> Self {
        Self {
            vendor_id: self.vendor_id,
            product_id: self.product_id,
            #[cfg(target_os = "macos")]
            connection: self.connection.clone(),
        }
    }
}
impl std::fmt::Debug for USBTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("USBTransport")
            .field("vendor_id", &format_args!("{:04x}", self.vendor_id))
            .field("product_id", &format_args!("{:04x}", self.product_id))
            .field("connected", &self.is_connected())
            .finish()
    }
}

impl USBTransport {
    /// Creates a transport for a discovered ADB USB device.
    pub fn new(vendor_id: u16, product_id: u16) -> Result<Self> {
        let device_info = nusb::list_devices()
            .wait()?
            .find(|device| {
                device.vendor_id() == vendor_id
                    && device.product_id() == product_id
                    && is_adb_device(device)
            })
            .ok_or(RustADBError::USBDeviceNotFound(vendor_id, product_id))?;
        Self::new_from_device(device_info)
    }
    /// Creates a transport from a device returned by USB discovery.
    pub fn new_from_device(device_info: DeviceInfo) -> Result<Self> {
        if !is_adb_device(&device_info) {
            return Err(RustADBError::USBNoDescriptorFound);
        }
        Ok(Self {
            vendor_id: device_info.vendor_id(),
            product_id: device_info.product_id(),
            #[cfg(target_os = "macos")]
            connection: None,
        })
    }
    pub(crate) fn vendor_id(&self) -> Result<u16> {
        Ok(self.vendor_id)
    }
    pub(crate) fn product_id(&self) -> Result<u16> {
        Ok(self.product_id)
    }

    #[cfg(target_os = "macos")]
    fn connection(&self) -> Result<std::sync::MutexGuard<'_, MacOSConnection>> {
        self.connection
            .as_ref()
            .ok_or_else(|| {
                RustADBError::IOError(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "ADB USB interface is not open",
                ))
            })?
            .lock()
            .map_err(Into::into)
    }
    #[cfg(target_os = "macos")]
    fn timeout_ms(timeout: Duration) -> u32 {
        if timeout == Duration::MAX {
            0
        } else {
            timeout.as_millis().min(u32::MAX as u128) as u32
        }
    }
    #[cfg(target_os = "macos")]
    fn iokit_error(operation: &str, status: i32) -> RustADBError {
        // kIOReturnTimeout (iokit_common_err(0x2d6)). A reverse relay uses
        // short reads to multiplex pending local-TCP writes with idle USB;
        // model that normal condition as an I/O timeout instead of a failed
        // ADB connection.
        if status == 0xe000_02d6u32 as i32 || status == 0xe000_4051u32 as i32 {
            return RustADBError::IOError(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("macOS IOKit USB {operation} timed out"),
            ));
        }
        RustADBError::ADBRequestFailed(format!(
            "macOS IOKit USB {operation} failed ({status:#010x})"
        ))
    }
    #[cfg(target_os = "macos")]
    fn write_bulk_data(&mut self, data: &[u8], timeout: Duration) -> Result<()> {
        let connection = self.connection()?;
        let result = unsafe {
            macos_iokit::macadb_write(
                connection.handle,
                data.as_ptr().cast(),
                data.len().try_into()?,
                Self::timeout_ms(timeout),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(Self::iokit_error("write", result))
        }
    }
    #[cfg(target_os = "macos")]
    fn read_exact(&mut self, data: &mut [u8], timeout: Duration) -> Result<()> {
        let connection = self.connection()?;
        let mut offset = 0;
        while offset < data.len() {
            let mut length: u32 = (data.len() - offset).try_into()?;
            let result = unsafe {
                macos_iokit::macadb_read(
                    connection.handle,
                    data[offset..].as_mut_ptr().cast(),
                    &mut length,
                    Self::timeout_ms(timeout),
                )
            };
            if result != 0 {
                return Err(Self::iokit_error("read", result));
            }
            if length == 0 {
                return Err(RustADBError::IOError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "ADB USB interface returned no data",
                )));
            }
            offset += length as usize;
        }
        Ok(())
    }
    fn is_connected(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.connection.is_some()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
}

impl ADBTransport for USBTransport {
    fn connect(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            if self.connection.is_some() {
                return Ok(());
            }
            let mut handle = std::ptr::null_mut();
            let result =
                unsafe { macos_iokit::macadb_open(self.vendor_id, self.product_id, &mut handle) };
            if result != 0 || handle.is_null() {
                return Err(Self::iokit_error("open", result));
            }
            let max_packet_size = unsafe { macos_iokit::macadb_max_packet_size(handle) } as usize;
            self.connection = Some(Arc::new(Mutex::new(MacOSConnection { handle })));
            log::debug!(
                "opened ADB USB interface for {:04x}:{:04x} (max packet size {max_packet_size})",
                self.vendor_id,
                self.product_id
            );
            return Ok(());
        }
        #[cfg(not(target_os = "macos"))]
        Err(RustADBError::ADBRequestFailed(
            "direct USB transport currently requires macOS".into(),
        ))
    }
    fn disconnect(&mut self) -> Result<()> {
        if self.is_connected() {
            if let Ok(message) = ADBTransportMessage::try_new(MessageCommand::Clse, 0, 0, &[]) {
                if let Err(error) = self.write_message(message) {
                    log::debug!("USB close message failed: {error}");
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            self.connection = None;
        }
        Ok(())
    }
}

impl ADBMessageTransport for USBTransport {
    fn write_message_with_timeout(
        &mut self,
        message: ADBTransportMessage,
        timeout: Duration,
    ) -> Result<()> {
        log::trace!(
            "sending ADB message {:?}, arg0={}, arg1={}, payload={} bytes",
            message.header().command(),
            message.header().arg0(),
            message.header().arg1(),
            message.payload().len()
        );
        self.write_bulk_data(&message.header().as_bytes(), timeout)?;
        let payload = message.into_payload();
        if !payload.is_empty() {
            self.write_bulk_data(&payload, timeout)?;
        }
        Ok(())
    }
    fn read_message_with_timeout(&mut self, timeout: Duration) -> Result<ADBTransportMessage> {
        let mut header_bytes = [0u8; 24];
        self.read_exact(&mut header_bytes, timeout)?;
        let header = ADBTransportMessageHeader::try_from(header_bytes)?;
        log::trace!(
            "received ADB message {:?}, arg0={}, arg1={}, payload={} bytes",
            header.command(),
            header.arg0(),
            header.arg1(),
            header.data_length()
        );
        let mut payload = vec![0; header.data_length() as usize];
        if !payload.is_empty() {
            // Once a header has been consumed, a payload timeout is fatal;
            // treating it as an idle poll would parse payload as the next header.
            self.read_exact(&mut payload, Duration::from_secs(5)).map_err(|error| {
                RustADBError::ADBRequestFailed(format!("incomplete USB packet: {error}"))
            })?;
        }
        let message = ADBTransportMessage::from_header_and_payload(header, payload);
        if !message.check_message_integrity() {
            return Err(RustADBError::InvalidIntegrity(
                ADBTransportMessageHeader::compute_crc32(message.payload()),
                message.header().data_crc32(),
            ));
        }
        Ok(message)
    }
}
