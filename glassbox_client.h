// ============================================================================
// glassbox_client.h - usermode wrapper for YOUR kernel driver.
//
// Your driver exposes \Device\<name> + a symlink; this client talks to it via
// plain CreateFile + DeviceIoControl. The device name defaults to
// \\.\GlassBox and can be overridden at runtime with the GLASSBOX_DEVICE
// environment variable (no rebuild needed). See docs/DRIVER-CONTRACT.md for
// the exact IOCTL contract your driver must implement.
// ============================================================================
#pragma once
#include <cstdint>
#include <Windows.h>
#include <string>
#include <vector>
#include <initializer_list>
#include <cstring>

namespace glassbox {

// ----------------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------------
bool Open();
void Close();
bool IsOpen();  // true while the driver device handle is open

// Resolved device name: GLASSBOX_DEVICE env override, else the built-in
// default (\\.\GlassBox). Valid after Open(); empty string before.
const std::string& DeviceName();

// ----------------------------------------------------------------------------
// Core IOCTL wrappers (talk directly to the driver)
// ----------------------------------------------------------------------------
uint64_t GetModuleBase     (DWORD pid, const std::wstring& module_name);
bool     ReadProcessMemory (DWORD pid, uint64_t addr, void*       buf, size_t size);
bool     WriteProcessMemory(DWORD pid, uint64_t addr, const void* buf, size_t size);
uint64_t AllocateMemory    (DWORD pid, size_t size, ULONG protect);
bool     ProtectMemory     (DWORD pid, uint64_t addr, size_t size, ULONG protect);

// ----------------------------------------------------------------------------
// Typed reads - sit on top of ReadProcessMemory. Use whichever form you like:
//
//   float value = glassbox::Read<float>(pid, addr);     // value form, 0 on fail
//   float value;
//   if (glassbox::Read(pid, addr, value)) { ... }        // status form
// ----------------------------------------------------------------------------
template <typename T>
inline bool Read(DWORD pid, uint64_t addr, T& out) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Read<T> requires a trivially-copyable T (POD-like)");
    return ReadProcessMemory(pid, addr, &out, sizeof(T));
}

template <typename T>
inline T Read(DWORD pid, uint64_t addr) {
    T v{};
    ReadProcessMemory(pid, addr, &v, sizeof(T));
    return v;
}

// Convenience aliases (no template typing at the call site).
inline uint8_t  ReadByte   (DWORD pid, uint64_t a) { return Read<uint8_t>(pid, a); }
inline uint16_t ReadUShort (DWORD pid, uint64_t a) { return Read<uint16_t>(pid, a); }
inline int16_t  ReadShort  (DWORD pid, uint64_t a) { return Read<int16_t>(pid, a); }
inline uint32_t ReadUInt   (DWORD pid, uint64_t a) { return Read<uint32_t>(pid, a); }
inline int32_t  ReadInt    (DWORD pid, uint64_t a) { return Read<int32_t>(pid, a); }
inline uint64_t ReadUInt64 (DWORD pid, uint64_t a) { return Read<uint64_t>(pid, a); }
inline int64_t  ReadInt64  (DWORD pid, uint64_t a) { return Read<int64_t>(pid, a); }
inline float    ReadFloat  (DWORD pid, uint64_t a) { return Read<float>(pid, a); }
inline double   ReadDouble (DWORD pid, uint64_t a) { return Read<double>(pid, a); }
inline bool     ReadBool   (DWORD pid, uint64_t a) { return Read<uint8_t>(pid, a) != 0; }
inline uint64_t ReadPointer(DWORD pid, uint64_t a) { return Read<uint64_t>(pid, a); }

// Raw bytes (length specified explicitly).
std::vector<uint8_t> ReadBytes(DWORD pid, uint64_t addr, size_t size);

// Null-terminated ASCII string. Stops at the first '\0' or after max_len bytes.
std::string  ReadString (DWORD pid, uint64_t addr, size_t max_len = 256);

// Null-terminated wide string. Stops at the first L'\0' or after max_chars wchars.
std::wstring ReadWString(DWORD pid, uint64_t addr, size_t max_chars = 256);

// ----------------------------------------------------------------------------
// Typed writes - mirror of the read helpers.
// ----------------------------------------------------------------------------
template <typename T>
inline bool Write(DWORD pid, uint64_t addr, const T& val) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Write<T> requires a trivially-copyable T (POD-like)");
    return WriteProcessMemory(pid, addr, &val, sizeof(T));
}

inline bool WriteByte   (DWORD pid, uint64_t a, uint8_t  v) { return Write(pid, a, v); }
inline bool WriteInt    (DWORD pid, uint64_t a, int32_t  v) { return Write(pid, a, v); }
inline bool WriteInt64  (DWORD pid, uint64_t a, int64_t  v) { return Write(pid, a, v); }
inline bool WriteFloat  (DWORD pid, uint64_t a, float    v) { return Write(pid, a, v); }
inline bool WriteDouble (DWORD pid, uint64_t a, double   v) { return Write(pid, a, v); }
inline bool WritePointer(DWORD pid, uint64_t a, uint64_t v) { return Write(pid, a, v); }

bool WriteBytes   (DWORD pid, uint64_t addr, const std::vector<uint8_t>& bytes);
bool WriteString  (DWORD pid, uint64_t addr, const std::string& s, bool include_null = true);
bool WriteWString (DWORD pid, uint64_t addr, const std::wstring& s, bool include_null = true);

// ----------------------------------------------------------------------------
// Pointer-chain read: follow a chain of pointers to a final value.
//
//   float v = glassbox::ReadChain<float>(pid, base, {0x10, 0x20, 0x8, 0xC4});
//
// Walks: addr0 = base + offsets[0]
//        addr1 = *addr0 + offsets[1]
//        addr2 = *addr1 + offsets[2]
//        ...
//        result = *(*(... + offsets[N-1]))  read as T
//
// In words: dereference at each step except the last, then read T.
// Returns default-constructed T on any failure.
// ----------------------------------------------------------------------------
template <typename T>
inline T ReadChain(DWORD pid, uint64_t base, std::initializer_list<int64_t> offsets) {
    if (offsets.size() == 0) return T{};
    uint64_t addr = base;
    auto it = offsets.begin();
    auto last = offsets.end() - 1;
    while (it != last) {
        uint64_t next = 0;
        if (!Read(pid, addr + *it, next) || !next) return T{};
        addr = next;
        ++it;
    }
    return Read<T>(pid, addr + *last);
}

// ----------------------------------------------------------------------------
// Signature / AOB scanning.
//
// Pattern format is IDA-style: "48 8B 0D ?? ?? ?? ?? E8" -- whitespace
// between tokens, "??" or "?" for a wildcard byte. Returns the first match VA,
// or 0 if not found.
// ----------------------------------------------------------------------------

// Scan a fixed VA range.
uint64_t SignatureScan(DWORD pid, uint64_t start, size_t size, const char* ida_pattern);

// Scan every executable section of a loaded module.  Pass the module base
// returned by GetModuleBase().
uint64_t SignatureScanModule(DWORD pid, uint64_t module_base, const char* ida_pattern);

// Collect ALL matches in a VA range (up to max_results), straddle-safe across
// the internal 256 KB chunk boundaries. Returns the number of hits written.
size_t SignatureScanAll(DWORD pid, uint64_t start, size_t size, const char* ida_pattern,
                        size_t max_results, std::vector<uint64_t>& out_hits);

// Same, across every PE section of a loaded module (headers, exec, then data).
size_t SignatureScanModuleAll(DWORD pid, uint64_t module_base, const char* ida_pattern,
                              size_t max_results, std::vector<uint64_t>& out_hits);

} // namespace glassbox
