# glassbox driver contract

glassbox-mcp is a pure usermode client. It performs exactly one kind of kernel
interaction:

```c
HANDLE h = CreateFileA(device_name, GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       nullptr, OPEN_EXISTING, 0, nullptr);
DeviceIoControl(h, <CTL_CODE>, &req, sizeof(req), &req, sizeof(req), &ret, nullptr);
```

Everything else — the actual memory access — happens inside **your** driver.
This document specifies what your driver must expose for glassbox-mcp to work.

## 1. Device

- One device with a **user-visible symlink** (`\\.\Name`), created after your
  driver loads. glassbox-mcp never loads, unloads, or maps anything — the
  driver must already be resident when the server starts.
- The client resolves the device name at runtime:
  1. `GLASSBOX_DEVICE` environment variable, if set (any `\\.\Name` works)
  2. built-in default: `\\.\GlassBox`
- The device must be opened with `GENERIC_READ | GENERIC_WRITE`; a restrictive
  ACL that denies admin results in Win32 error 5 at the client.

## 2. IOCTL codes

All five are buffered IOCTLs (`METHOD_BUFFERED`) defined as:

```c
CTL_CODE(FILE_DEVICE_UNKNOWN, <function>, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
```

| IOCTL | Function constant | Purpose |
|---|---|---|
| `IOCTL_DISPATCH_READ` | `0xA17` | Read memory from a target process |
| `IOCTL_DISPATCH_WRITE` | `0xC49` | Write memory into a target process |
| `IOCTL_DISPATCH_MODBASE` | `0xD62` | Resolve a module's base address in a target process |
| `IOCTL_DISPATCH_PROTECT` | `0xEB5` | Change memory protection in a target process |
| `IOCTL_DISPATCH_ALLOC` | `0xF38` | Allocate memory in a target process |

Example expansion (must match exactly):

```c
#define IOCTL_DISPATCH_READ     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA17, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_WRITE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xC49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_MODBASE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xD62, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_PROTECT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xEB5, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DISPATCH_ALLOC    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xF38, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
```

If your existing driver uses different codes, you have two options: adjust the
codes in `ioctl_defs.h` and rebuild glassbox-mcp, or add these codes on the
driver side. No other part of the contract is affected.

## 3. Request structs

x64-only. The client builds these on the stack with zero-init; the driver
reads them from `SystemBuffer` and (where noted) writes results back into the
same buffer. Sizes are exact — do not pad or reorder.

### DISPATCH_RW_REQUEST — READ / WRITE

```c
typedef struct _DISPATCH_RW_REQUEST {
    ULONGLONG src;    // READ: source VA in target. WRITE: source VA in *caller* (client buffer)
    ULONG     pid;    // target process id
    ULONGLONG dst;    // READ: destination VA in *caller*. WRITE: destination VA in target
    ULONGLONG size;   // byte count
} DISPATCH_RW_REQUEST, *PDISPATCH_RW_REQUEST;
```

Semantics: copy `size` bytes between the target process (`pid`) and the
caller's context, in the `src` → `dst` direction the IOCTL name implies. A
typical implementation attaches to the target (`KeStackAttachProcess`) and uses
`MmCopyVirtualMemory` (or probes + direct copy) against the caller's buffer,
which is already locked down by `METHOD_BUFFERED`.

### DISPATCH_MODBASE_REQUEST — MODBASE

```c
typedef struct _DISPATCH_MODBASE_REQUEST {
    WCHAR     name[260];  // IN : module file name, e.g. L"kernel32.dll"
    ULONG     pid;        // IN : target process id
    ULONGLONG handle;     // OUT: module base address (0 on failure)
} DISPATCH_MODBASE_REQUEST, *PDISPATCH_MODBASE_REQUEST;
```

Semantics: walk the target's PEB loader list (or `PsGetProcessPeb` +
`Ldr->InLoadOrderModuleList`), match `BaseDllName` case-insensitively against
`name`, return the DllBase in `handle`. Returning 0 is the documented failure
value; the client treats it as "module not found".

### DISPATCH_ALLOC_REQUEST — ALLOC

```c
typedef struct _DISPATCH_ALLOC_REQUEST {
    ULONGLONG addr;            // IN : 0 = kernel picks the base; OUT: actual base VA
    ULONG     pid;             // IN : target process id
    ULONG     allocation_type; // IN : MEM_COMMIT | MEM_RESERVE (0x3000)
    SIZE_T    size;            // IN : allocation size in bytes
    ULONG     protect;         // IN : PAGE_* constant, e.g. PAGE_READWRITE
} DISPATCH_ALLOC_REQUEST, *PDISPATCH_ALLOC_REQUEST;
```

Semantics: allocate `size` bytes of `allocation_type` memory with `protect`
protection inside the target process (`ZwAllocateVirtualMemory` against a
handle opened for the target, or the equivalent attached call). On success
write the chosen base address back into `addr`. On failure the IOCTL itself
should fail (the client reports the Win32 error).

### DISPATCH_PROTECT_REQUEST — PROTECT

```c
typedef struct _DISPATCH_PROTECT_REQUEST {
    ULONGLONG addr;     // IN: region start VA in target
    ULONG     pid;      // IN: target process id
    SIZE_T    size;     // IN: region size in bytes
    ULONG     protect;  // IN: new PAGE_* protection
} DISPATCH_PROTECT_REQUEST, *PDISPATCH_PROTECT_REQUEST;
```

Semantics: change the protection of `[addr, addr+size)` in the target process
(`ZwProtectVirtualMemory` equivalent).

## 4. Behavior expectations

- **Buffered I/O both ways.** The client passes the same buffer for in/out
  (`sizeof(req)` each way), so keep `DO_BUFFERED_IO` on the device.
- **Fail with a Win32-ish status.** Non-success `NTSTATUS` surfaces to the
  agent as a clean in-band error with the mapped Win32 code — that is the
  expected, handled path. Crashing the machine is not.
- **PAGE_* mapping.** The client translates `"r"/"rw"/"rx"/"rwx"` to
  `PAGE_READWRITE / PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE / PAGE_READONLY`
  before building the request; your driver receives raw `PAGE_*` values.
- **`ping` smoke test.** On startup (and on every `ping` tool call) the client
  resolves its *own* module base via MODBASE and kernel-reads 2 bytes from it,
  expecting the `MZ` header. If your MODBASE or READ is broken, `ping` fails
  with a precise message — this is your integration test.

## 5. Minimal integration checklist

- [ ] Driver loaded, device + symlink created (`\\.\YourName`)
- [ ] Five CTL codes match `ioctl_defs.h` (or you rebuilt the client to match)
- [ ] Four request structs match byte-for-byte (x64, no packing pragmas)
- [ ] READ/WRITE honor the `src`/`dst` direction table above
- [ ] MODBASE fills `handle` with the DllBase (0 on miss)
- [ ] Device ACL allows admin (the host terminal runs elevated)
- [ ] `ping` returns `kernel_read_smoke: "PASS (MZ)"` against a live target

Once `ping` passes, all 21 tools work against any process your driver can
access.
