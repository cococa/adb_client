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

typedef struct {
    uint16_t vendor_id;
    uint16_t product_id;
    uint64_t location_id;
} macadb_device_info;

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

static int property_u32(io_registry_entry_t service, CFStringRef key, UInt32 *value) {
    CFTypeRef property = IORegistryEntrySearchCFProperty(
        service, kIOServicePlane, key, kCFAllocatorDefault,
        kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (!property) return 0;
    int ok = CFGetTypeID(property) == CFNumberGetTypeID()
        && CFNumberGetValue((CFNumberRef)property, kCFNumberSInt32Type, value);
    CFRelease(property);
    return ok;
}

// locationID identifies the physical USB topology (hub/port path) and remains
// stable while a phone stays on that port. Registry entry ID is a per-attach
// fallback for unusual devices whose IORegistry tree omits locationID.
static uint64_t device_location_id(io_registry_entry_t service) {
    UInt32 location = 0;
    if (property_u32(service, CFSTR("locationID"), &location) && location != 0) {
        return location;
    }
    uint64_t registry_id = 0;
    if (IORegistryEntryGetRegistryEntryID(service, &registry_id) == kIOReturnSuccess) {
        return registry_id | (UINT64_C(1) << 63);
    }
    return 0;
}

// nusb can enumerate a composite Android device on macOS without retaining its
// interface descriptors.  Discover through IOKit instead, which is also the
// API used for the actual interface open below.
int macadb_list(macadb_device_info **output, size_t *count) {
    *output = NULL;
    *count = 0;
    CFMutableDictionaryRef matching = IOServiceMatching(kIOUSBInterfaceClassName);
    io_iterator_t iterator = 0;
    IOReturn result = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (result != kIOReturnSuccess) return result;

    macadb_device_info *devices = NULL;
    size_t capacity = 0;
    io_service_t service;
    while ((service = IOIteratorNext(iterator))) {
        UInt16 vendor = 0, product = 0;
        uint64_t location = device_location_id(service);
        UInt16 klass = 0, subclass = 0, protocol = 0;
        int is_adb = property_u16(service, CFSTR("bInterfaceClass"), &klass)
            && property_u16(service, CFSTR("bInterfaceSubClass"), &subclass)
            && property_u16(service, CFSTR("bInterfaceProtocol"), &protocol)
            && klass == 0xff && subclass == 0x42 && protocol == 0x01
            && property_u16(service, CFSTR("idVendor"), &vendor)
            && property_u16(service, CFSTR("idProduct"), &product);
        IOObjectRelease(service);
        if (!is_adb) continue;

        int duplicate = 0;
        for (size_t index = 0; index < *count; index++) {
            if (location != 0 && devices[index].location_id == location) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) continue;
        if (*count == capacity) {
            size_t next_capacity = capacity ? capacity * 2 : 4;
            macadb_device_info *next = realloc(devices, next_capacity * sizeof(*devices));
            if (!next) {
                free(devices);
                IOObjectRelease(iterator);
                return kIOReturnNoMemory;
            }
            devices = next;
            capacity = next_capacity;
        }
        devices[*count] = (macadb_device_info) { vendor, product, location };
        *count += 1;
    }
    IOObjectRelease(iterator);
    *output = devices;
    return kIOReturnSuccess;
}

void macadb_list_free(macadb_device_info *devices) { free(devices); }

int macadb_open(uint16_t wanted_vendor, uint16_t wanted_product,
        uint64_t wanted_location, macadb_interface **output) {
    *output = NULL;
    CFMutableDictionaryRef matching = IOServiceMatching(kIOUSBInterfaceClassName);
    io_iterator_t iterator = 0;
    IOReturn result = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (result != kIOReturnSuccess) return result;
    IOReturn last_error = kIOReturnNotFound;

    io_service_t service;
    while ((service = IOIteratorNext(iterator))) {
        UInt16 vendor = 0, product = 0;
        uint64_t location = device_location_id(service);
        if (!property_u16(service, CFSTR("idVendor"), &vendor)
            || !property_u16(service, CFSTR("idProduct"), &product)
            || vendor != wanted_vendor || product != wanted_product
            || (wanted_location != 0 && location != wanted_location)) {
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
