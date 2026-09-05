#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    IOUSBInterfaceInterface500 **interface;
    UInt8 bulk_in;
    UInt8 bulk_out;
    UInt16 max_packet_size;
} macadb_interface;

static int property_u16(io_registry_entry_t service, CFStringRef key, UInt16 *value) {
    CFTypeRef property = IORegistryEntrySearchCFProperty(
        service, kIOServicePlane, key, kCFAllocatorDefault,
        kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (!property) return 0;
    int ok = CFGetTypeID(property) == CFNumberGetTypeID()
        && CFNumberGetValue((CFNumberRef)property, kCFNumberSInt16Type, value);
    CFRelease(property);
    return ok;
}

int macadb_open(uint16_t wanted_vendor, uint16_t wanted_product, macadb_interface **output) {
    *output = NULL;
    CFMutableDictionaryRef matching = IOServiceMatching(kIOUSBInterfaceClassName);
    io_iterator_t iterator = 0;
    IOReturn result = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (result != kIOReturnSuccess) return result;
    IOReturn last_error = kIOReturnNotFound;

    io_service_t service;
    while ((service = IOIteratorNext(iterator))) {
        UInt16 vendor = 0, product = 0;
        if (!property_u16(service, CFSTR("idVendor"), &vendor)
            || !property_u16(service, CFSTR("idProduct"), &product)
            || vendor != wanted_vendor || product != wanted_product) {
            IOObjectRelease(service);
            continue;
        }
        IOCFPlugInInterface **plugin = NULL;
        SInt32 score = 0;
        result = IOCreatePlugInInterfaceForService(service, kIOUSBInterfaceUserClientTypeID,
            kIOCFPlugInInterfaceID, &plugin, &score);
        IOObjectRelease(service);
        if (result != kIOReturnSuccess || !plugin) {
            last_error = result;
            continue;
        }

        IOUSBInterfaceInterface500 **interface = NULL;
        HRESULT query = (*plugin)->QueryInterface(plugin,
            CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID500), (LPVOID)&interface);
        (*plugin)->Release(plugin);
        if (query || !interface) {
            last_error = query ? (IOReturn)query : kIOReturnError;
            continue;
        }

        UInt8 klass = 0, subclass = 0, protocol = 0;
        (*interface)->GetInterfaceClass(interface, &klass);
        (*interface)->GetInterfaceSubClass(interface, &subclass);
        (*interface)->GetInterfaceProtocol(interface, &protocol);
        if (klass != 0xff || subclass != 0x42 || protocol != 0x01) {
            (*interface)->Release(interface);
            continue;
        }
        result = (*interface)->USBInterfaceOpen(interface);
        if (result != kIOReturnSuccess) {
            last_error = result;
            (*interface)->Release(interface);
            continue;
        }

        UInt8 endpoint_count = 0;
        result = (*interface)->GetNumEndpoints(interface, &endpoint_count);
        if (result != kIOReturnSuccess) {
            last_error = result;
            (*interface)->USBInterfaceClose(interface);
            (*interface)->Release(interface);
            continue;
        }
        UInt8 bulk_in = 0, bulk_out = 0;
        UInt16 max_packet_size = 0;
        for (UInt8 pipe = 1; pipe <= endpoint_count; pipe++) {
            UInt8 direction = 0, number = 0, transfer_type = 0, interval = 0;
            UInt16 packet_size = 0;
            if ((*interface)->GetPipeProperties(interface, pipe, &direction, &number,
                    &transfer_type, &packet_size, &interval) != kIOReturnSuccess
                || transfer_type != kUSBBulk) continue;
            if (direction == kUSBIn) bulk_in = pipe;
            if (direction == kUSBOut) { bulk_out = pipe; max_packet_size = packet_size; }
        }
        if (!bulk_in || !bulk_out) {
            last_error = kIOReturnNoResources;
            (*interface)->USBInterfaceClose(interface);
            (*interface)->Release(interface);
            continue;
        }
        macadb_interface *handle = calloc(1, sizeof(*handle));
        handle->interface = interface;
        handle->bulk_in = bulk_in;
        handle->bulk_out = bulk_out;
        handle->max_packet_size = max_packet_size;
        *output = handle;
        IOObjectRelease(iterator);
        return kIOReturnSuccess;
    }
    IOObjectRelease(iterator);
    return last_error;
}

int macadb_read(macadb_interface *handle, void *buffer, uint32_t *length, uint32_t timeout_ms) {
    return (*handle->interface)->ReadPipeTO(handle->interface, handle->bulk_in, buffer, length,
        timeout_ms, timeout_ms);
}

int macadb_write(macadb_interface *handle, const void *buffer, uint32_t length, uint32_t timeout_ms) {
    IOReturn result = (*handle->interface)->WritePipeTO(handle->interface, handle->bulk_out,
        (void *)buffer, length, timeout_ms, timeout_ms);
    // Like the platform adb client, terminate an exact full-size bulk transfer
    // with a zero-length packet so the device does not wait for another packet.
    if (result == kIOReturnSuccess && length && length % handle->max_packet_size == 0) {
        result = (*handle->interface)->WritePipeTO(handle->interface, handle->bulk_out,
            (void *)buffer, 0, timeout_ms, timeout_ms);
    }
    return result;
}

uint16_t macadb_max_packet_size(const macadb_interface *handle) { return handle->max_packet_size; }

void macadb_close(macadb_interface *handle) {
    if (!handle) return;
    (*handle->interface)->USBInterfaceClose(handle->interface);
    (*handle->interface)->Release(handle->interface);
    free(handle);
}
