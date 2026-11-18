// ============================================================================
// Shared IOCTL definitions - the glassbox-mcp <-> driver contract.
//
// Your driver must implement these CTL codes and struct layouts
// byte-for-byte. These structs cross the user/kernel boundary; the full
// reference lives in docs/DRIVER-CONTRACT.md.
//
// The device name below is only the DEFAULT: set GLASSBOX_DEVICE to talk to
// a device with any name without rebuilding.
// ============================================================================
#pragma once
#include <Windows.h>

#define DEVICE_NAME_USERMODE  "\\\\.\\GlassBox"

#define IOCTL_DISPATCH_READ     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA17, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_WRITE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_MODBASE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD62, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_PROTECT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xEB5, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_ALLOC    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF38, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _DISPATCH_RW_REQUEST {
    ULONGLONG src;
    ULONG     pid;
    ULONGLONG dst;
    ULONGLONG size;
} DISPATCH_RW_REQUEST, *PDISPATCH_RW_REQUEST;

typedef struct _DISPATCH_MODBASE_REQUEST {
    WCHAR     name[260];
    ULONG     pid;
    ULONGLONG handle;       // OUT: module base
} DISPATCH_MODBASE_REQUEST, *PDISPATCH_MODBASE_REQUEST;

typedef struct _DISPATCH_ALLOC_REQUEST {
    ULONGLONG addr;            // IN  - 0 = let kernel pick; OUT - actual VA
    ULONG     pid;
    ULONG     allocation_type; // MEM_COMMIT | MEM_RESERVE
    SIZE_T    size;
    ULONG     protect;         // PAGE_READWRITE etc.
} DISPATCH_ALLOC_REQUEST, *PDISPATCH_ALLOC_REQUEST;

typedef struct _DISPATCH_PROTECT_REQUEST {
    ULONGLONG addr;
    ULONG     pid;
    SIZE_T    size;
    ULONG     protect;
} DISPATCH_PROTECT_REQUEST, *PDISPATCH_PROTECT_REQUEST;
