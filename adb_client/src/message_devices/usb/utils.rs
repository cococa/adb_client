use nusb::{DeviceInfo, MaybeFuture};

use crate::{Result, RustADBError};

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacADBDeviceInfo {
    vendor_id: u16,
    product_id: u16,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn macadb_list(output: *mut *mut MacADBDeviceInfo, count: *mut usize) -> i32;
    fn macadb_list_free(devices: *mut MacADBDeviceInfo);
}

/// Represents an Android device connected via USB.
#[derive(Clone, Debug)]
pub struct ADBDeviceInfo {
    /// USB vendor identifier.
    pub vendor_id: u16,
    /// USB serial descriptor used for device selection.
    pub serial: Option<String>,
    /// USB product identifier.
    pub product_id: u16,
    /// Human-readable manufacturer and product description when available.
    pub device_description: String,
}

/// Lists USB devices exposing the standard ADB vendor interface (ff:42:01).
pub fn find_all_connected_adb_devices() -> Result<Vec<ADBDeviceInfo>> {
    #[cfg(target_os = "macos")]
    {
        let mut devices = std::ptr::null_mut();
        let mut count = 0;
        let result = unsafe { macadb_list(&mut devices, &mut count) };
        if result != 0 {
            return Err(RustADBError::ADBRequestFailed(format!(
                "macOS IOKit USB discovery failed ({result:#010x})"
            )));
        }
        let found = if devices.is_null() {
            Vec::new()
        } else {
            let entries = unsafe { std::slice::from_raw_parts(devices, count) };
            entries
                .iter()
                .map(|device| ADBDeviceInfo {
                    vendor_id: device.vendor_id,
                    product_id: device.product_id,
                    serial: None,
                    device_description: String::new(),
                })
                .collect()
        };
        unsafe { macadb_list_free(devices) };
        return Ok(found);
    }

    #[cfg(not(target_os = "macos"))]
    let devices = nusb::list_devices().wait()?.collect::<Vec<_>>();
    #[cfg(not(target_os = "macos"))]
    log::debug!("nusb enumerated {} USB device(s)", devices.len());

    #[cfg(not(target_os = "macos"))]
    Ok(devices
        .into_iter()
        .filter(is_adb_device)
        .map(|device| ADBDeviceInfo {
            vendor_id: device.vendor_id(),
            serial: device.serial_number().map(str::to_owned),
            product_id: device.product_id(),
            device_description: [device.manufacturer_string(), device.product_string()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" "),
        })
        .collect())
}

pub fn get_single_connected_adb_device() -> Result<Option<ADBDeviceInfo>> {
    let found_devices = find_all_connected_adb_devices()?;
    match (found_devices.first(), found_devices.get(1)) {
        (None, _) => Ok(None),
        (Some(device_info), None) => Ok(Some(device_info.clone())),
        (Some(first), Some(second)) => Err(RustADBError::DeviceNotFound(format!(
            "Found two Android devices {:04x}:{:04x} and {:04x}:{:04x}",
            first.vendor_id, first.product_id, second.vendor_id, second.product_id
        ))),
    }
}

pub(crate) fn is_adb_device(device: &DeviceInfo) -> bool {
    const ADB_CLASS: u8 = 0xff;
    const ADB_SUBCLASS: u8 = 0x42;
    const ADB_PROTOCOL: u8 = 0x01;

    device.interfaces().any(|interface| {
        log::debug!(
            "USB {:04x}:{:04x} interface {}: class={:02x}, subclass={:02x}, protocol={:02x}",
            device.vendor_id(),
            device.product_id(),
            interface.interface_number(),
            interface.class(),
            interface.subclass(),
            interface.protocol()
        );
        interface.class() == ADB_CLASS
            && interface.subclass() == ADB_SUBCLASS
            && interface.protocol() == ADB_PROTOCOL
    })
}
