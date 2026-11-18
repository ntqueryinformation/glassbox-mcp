// ============================================================================
// glassbox_client.cpp - IOCTLs, all METHOD_BUFFERED.
//
// Shipped with glassbox-mcp. This repository contains NO kernel driver and NO
// driver-loading code. The client only opens the device your (own) driver
// exposes and issues raw IOCTLs to it.
//
// Device name resolution:
//   1. GLASSBOX_DEVICE environment variable (e.g. "\\.\MyDriver"), if set
//   2. built-in default: \\.\GlassBox
//
// Your driver does the KeStackAttachProcess + MmCopyVirtualMemory dance for
// us; we just hand it (pid, source, destination, size). See
// docs/DRIVER-CONTRACT.md for the full contract.
//
// NOTE: all diagnostics go to STDERR. glassbox-mcp's stdout is the MCP
// stdio transport and must never receive log output.
// ============================================================================

#include "glassbox_client.h"
#include "ioctl_defs.h"
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>

namespace {
    HANDLE g_dev = INVALID_HANDLE_VALUE;
    std::string g_device_name;
}

// stderr-only logging, printf-compatible.
static void glassboxlog(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

// GLASSBOX_DEVICE env var wins over the built-in default; result is cached.
static const std::string& resolve_device_name() {
    if (g_device_name.empty()) {
        const char* env = std::getenv("GLASSBOX_DEVICE");
        g_device_name = (env && *env) ? std::string(env)
                                      : std::string(DEVICE_NAME_USERMODE);
    }
    return g_device_name;
}

const std::string& glassbox::DeviceName() {
    return resolve_device_name();
}

bool glassbox::Open() {
    if (g_dev != INVALID_HANDLE_VALUE) return true;
    const std::string& device = resolve_device_name();
    g_dev = CreateFileA(device.c_str(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        glassboxlog("[glassbox] CreateFile %s failed: %lu "
              "(driver not resident? wrong GLASSBOX_DEVICE? or not elevated?)",
              device.c_str(), GetLastError());
        return false;
    }
    return true;
}

bool glassbox::IsOpen() { return g_dev != INVALID_HANDLE_VALUE; }

void glassbox::Close() {
    if (g_dev != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dev);
        g_dev = INVALID_HANDLE_VALUE;
    }
}

uint64_t glassbox::GetModuleBase(DWORD pid, const std::wstring& module_name) {
    if (g_dev == INVALID_HANDLE_VALUE) return 0;
    DISPATCH_MODBASE_REQUEST req{};
    req.pid = pid;
    wcsncpy_s(req.name, module_name.c_str(), _TRUNCATE);

    DWORD ret = 0;
    if (!DeviceIoControl(g_dev, IOCTL_DISPATCH_MODBASE,
                         &req, sizeof(req), &req, sizeof(req),
                         &ret, nullptr)) {
        glassboxlog("[glassbox] MODBASE ioctl failed: %lu", GetLastError());
        return 0;
    }
    return req.handle;
}

bool glassbox::ReadProcessMemory(DWORD pid, uint64_t addr, void* buf, size_t size) {
    if (g_dev == INVALID_HANDLE_VALUE) return false;
    DISPATCH_RW_REQUEST req{};
    req.pid  = pid;
    req.src  = addr;
    req.dst  = (ULONGLONG)buf;
    req.size = size;

    DWORD ret = 0;
    return !!DeviceIoControl(g_dev, IOCTL_DISPATCH_READ,
                             &req, sizeof(req), &req, sizeof(req),
                             &ret, nullptr);
}

bool glassbox::WriteProcessMemory(DWORD pid, uint64_t addr, const void* buf, size_t size) {
    if (g_dev == INVALID_HANDLE_VALUE) return false;
    DISPATCH_RW_REQUEST req{};
    req.pid  = pid;
    req.src  = (ULONGLONG)buf;
    req.dst  = addr;
    req.size = size;

    DWORD ret = 0;
    return !!DeviceIoControl(g_dev, IOCTL_DISPATCH_WRITE,
                             &req, sizeof(req), &req, sizeof(req),
                             &ret, nullptr);
}

uint64_t glassbox::AllocateMemory(DWORD pid, size_t size, ULONG protect) {
    if (g_dev == INVALID_HANDLE_VALUE) return 0;
    DISPATCH_ALLOC_REQUEST req{};
    req.pid             = pid;
    req.addr            = 0;                       // 0 = kernel picks
    req.allocation_type = MEM_COMMIT | MEM_RESERVE;
    req.size            = size;
    req.protect         = protect;

    DWORD ret = 0;
    if (!DeviceIoControl(g_dev, IOCTL_DISPATCH_ALLOC,
                         &req, sizeof(req), &req, sizeof(req),
                         &ret, nullptr)) {
        glassboxlog("[glassbox] ALLOC ioctl failed: %lu", GetLastError());
        return 0;
    }
    return req.addr;
}

bool glassbox::ProtectMemory(DWORD pid, uint64_t addr, size_t size, ULONG protect) {
    if (g_dev == INVALID_HANDLE_VALUE) return false;
    DISPATCH_PROTECT_REQUEST req{};
    req.addr    = addr;
    req.pid     = pid;
    req.size    = size;
    req.protect = protect;

    DWORD ret = 0;
    if (!DeviceIoControl(g_dev, IOCTL_DISPATCH_PROTECT,
                         &req, sizeof(req), &req, sizeof(req),
                         &ret, nullptr)) {
        glassboxlog("[glassbox] PROTECT ioctl failed: %lu", GetLastError());
        return false;
    }
    return true;
}

// ============================================================================
// Read helpers
// ============================================================================
std::vector<uint8_t> glassbox::ReadBytes(DWORD pid, uint64_t addr, size_t size) {
    std::vector<uint8_t> out(size);
    if (!ReadProcessMemory(pid, addr, out.data(), size)) out.clear();
    return out;
}

std::string glassbox::ReadString(DWORD pid, uint64_t addr, size_t max_len) {
    // Pull in chunks so we don't waste IOCTLs on the common 16- or 32-char case
    // but also handle long strings cleanly. 64-byte chunks are a good trade-off.
    std::string out;
    out.reserve(max_len < 64 ? max_len : 64);
    constexpr size_t kChunk = 64;
    char buf[kChunk];

    for (size_t pos = 0; pos < max_len; pos += kChunk) {
        size_t want = (std::min)(kChunk, max_len - pos);
        if (!ReadProcessMemory(pid, addr + pos, buf, want)) break;
        for (size_t i = 0; i < want; ++i) {
            if (buf[i] == '\0') return out;
            out.push_back(buf[i]);
        }
    }
    return out;
}

std::wstring glassbox::ReadWString(DWORD pid, uint64_t addr, size_t max_chars) {
    std::wstring out;
    out.reserve(max_chars < 64 ? max_chars : 64);
    constexpr size_t kChunk = 64;
    wchar_t buf[kChunk];

    for (size_t pos = 0; pos < max_chars; pos += kChunk) {
        size_t want_chars = (std::min)(kChunk, max_chars - pos);
        if (!ReadProcessMemory(pid, addr + pos * sizeof(wchar_t),
                               buf, want_chars * sizeof(wchar_t))) break;
        for (size_t i = 0; i < want_chars; ++i) {
            if (buf[i] == L'\0') return out;
            out.push_back(buf[i]);
        }
    }
    return out;
}

// ============================================================================
// Write helpers
// ============================================================================
bool glassbox::WriteBytes(DWORD pid, uint64_t addr, const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return true;
    return WriteProcessMemory(pid, addr, bytes.data(), bytes.size());
}

bool glassbox::WriteString(DWORD pid, uint64_t addr, const std::string& s, bool include_null) {
    return WriteProcessMemory(pid, addr, s.data(), s.size() + (include_null ? 1 : 0));
}

bool glassbox::WriteWString(DWORD pid, uint64_t addr, const std::wstring& s, bool include_null) {
    const size_t bytes = (s.size() + (include_null ? 1 : 0)) * sizeof(wchar_t);
    return WriteProcessMemory(pid, addr, s.c_str(), bytes);
}

// ============================================================================
// Signature scanning
// ============================================================================
namespace {

// Parse an IDA-style pattern ("48 8B ?? E8 ??") into two parallel buffers:
//   bytes[i] = expected byte value (0 for wildcards, ignored)
//   mask[i]  = true if byte must match, false for wildcard
// Returns false if the input is malformed.
bool ParsePattern(const char* p, std::vector<uint8_t>& bytes, std::vector<bool>& mask) {
    bytes.clear(); mask.clear();
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        if (p[0] == '?') {
            bytes.push_back(0);
            mask.push_back(false);
            ++p;
            if (*p == '?') ++p;
        } else {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hex(p[0]);
            int lo = hex(p[1]);
            if (hi < 0 || lo < 0) return false;
            bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
            mask.push_back(true);
            p += 2;
        }
    }
    return !bytes.empty();
}

// Linear pattern search in a local buffer.
uint64_t ScanLocal(const uint8_t* buf, size_t size,
                   const std::vector<uint8_t>& bytes,
                   const std::vector<bool>& mask) {
    if (bytes.empty() || size < bytes.size()) return 0;
    const size_t end = size - bytes.size();
    for (size_t i = 0; i <= end; ++i) {
        bool ok = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (mask[j] && buf[i + j] != bytes[j]) { ok = false; break; }
        }
        if (ok) return i;  // returns offset within buf
    }
    return (uint64_t)-1;
}

// Append the absolute addresses of every match fully contained in this buffer,
// up to the caller's remaining budget. Matches that straddle the end are left
// for the next chunk (the caller re-reads an overlap of patternLen-1 bytes).
size_t ScanAllLocal(uint64_t start_addr, const uint8_t* buf, size_t size,
                    const std::vector<uint8_t>& bytes, const std::vector<bool>& mask,
                    size_t max_remaining, std::vector<uint64_t>& out) {
    if (bytes.empty() || size < bytes.size() || max_remaining == 0) return 0;
    const size_t end = size - bytes.size();
    size_t found = 0;
    for (size_t i = 0; i <= end && found < max_remaining; ++i) {
        bool ok = true;
        for (size_t j = 0; j < bytes.size(); ++j) {
            if (mask[j] && buf[i + j] != bytes[j]) { ok = false; break; }
        }
        if (ok) { out.push_back(start_addr + i); ++found; }
    }
    return found;
}

} // anonymous

uint64_t glassbox::SignatureScan(DWORD pid, uint64_t start, size_t size, const char* ida_pattern) {
    std::vector<uint8_t> sig_bytes;
    std::vector<bool>    sig_mask;
    if (!ParsePattern(ida_pattern, sig_bytes, sig_mask)) {
        glassboxlog("[glassbox] SignatureScan: bad pattern \"%s\"", ida_pattern);
        return 0;
    }

    // Chunk reads so we don't try to read a 100 MB region in one IOCTL.
    // 256 KB chunks with an overlap of (pattern_len - 1) so a match straddling
    // the boundary is still found.
    constexpr size_t kChunk = 256 * 1024;
    const size_t overlap   = sig_bytes.size() - 1;

    std::vector<uint8_t> buf(kChunk);
    uint64_t pos = 0;
    while (pos < size) {
        size_t want = (std::min)(kChunk, size - pos);
        if (!ReadProcessMemory(pid, start + pos, buf.data(), want)) {
            // Skip unreadable region (page boundary etc.) and try the next chunk
            pos += want;
            continue;
        }
        uint64_t hit = ScanLocal(buf.data(), want, sig_bytes, sig_mask);
        if (hit != (uint64_t)-1) return start + pos + hit;
        if (want < kChunk) break;
        pos += kChunk - overlap;
    }
    return 0;
}

size_t glassbox::SignatureScanAll(DWORD pid, uint64_t start, size_t size, const char* ida_pattern,
                                size_t max_results, std::vector<uint64_t>& out_hits) {
    std::vector<uint8_t> sig_bytes;
    std::vector<bool>    sig_mask;
    if (!ParsePattern(ida_pattern, sig_bytes, sig_mask)) {
        glassboxlog("[glassbox] SignatureScanAll: bad pattern \"%s\"", ida_pattern);
        return 0;
    }
    if (max_results == 0) return 0;

    // Chunked reads with an overlap of (pattern_len - 1) so matches that
    // straddle a boundary are found exactly once (by the next chunk window).
    constexpr size_t kChunk = 256 * 1024;
    const size_t overlap   = sig_bytes.size() - 1;

    std::vector<uint8_t> buf(kChunk);
    uint64_t pos = 0;
    while (pos < size && out_hits.size() < max_results) {
        size_t want = (std::min)(kChunk, size - pos);
        if (ReadProcessMemory(pid, start + pos, buf.data(), want)) {
            ScanAllLocal(start + pos, buf.data(), want, sig_bytes, sig_mask,
                         max_results - out_hits.size(), out_hits);
            if (want < kChunk) break;
            pos += kChunk - overlap;
        } else {
            // Skip unreadable region (page boundary etc.) and try the next chunk.
            pos += want;
        }
    }
    return out_hits.size();
}

size_t glassbox::SignatureScanModuleAll(DWORD pid, uint64_t module_base, const char* ida_pattern,
                                      size_t max_results, std::vector<uint64_t>& out_hits) {
    if (!module_base || max_results == 0) return 0;

    std::vector<uint8_t> sig_bytes;
    std::vector<bool>    sig_mask;
    if (!ParsePattern(ida_pattern, sig_bytes, sig_mask)) {
        glassboxlog("[glassbox] SignatureScanModuleAll: bad pattern \"%s\"", ida_pattern);
        return 0;
    }

    // Read DOS + NT headers to enumerate sections.
    IMAGE_DOS_HEADER dos{};
    if (!ReadProcessMemory(pid, module_base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) {
        glassboxlog("[glassbox] SignatureScanModuleAll: bad DOS header");
        return 0;
    }
    IMAGE_NT_HEADERS64 nt{};
    if (!ReadProcessMemory(pid, module_base + dos.e_lfanew, &nt, sizeof(nt)) ||
        nt.Signature != IMAGE_NT_SIGNATURE) {
        glassboxlog("[glassbox] SignatureScanModuleAll: bad NT header");
        return 0;
    }

    // Read all section headers in one shot.
    std::vector<IMAGE_SECTION_HEADER> sections(nt.FileHeader.NumberOfSections);
    const uint64_t sec_va = module_base
        + dos.e_lfanew
        + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + nt.FileHeader.SizeOfOptionalHeader;
    if (!ReadProcessMemory(pid, sec_va, sections.data(),
                           sections.size() * sizeof(IMAGE_SECTION_HEADER))) {
        glassboxlog("[glassbox] SignatureScanModuleAll: failed to read sections");
        return 0;
    }

    auto scan_region = [&](uint64_t va, size_t rsize) {
        if (out_hits.size() >= max_results) return;
        SignatureScanAll(pid, va, rsize, ida_pattern, max_results, out_hits);
    };

    // Scan the PE header region first (sits between module_base and the first
    // section). The DOS header / NT headers / section table live here, and
    // they're a common target for sigs ("4D 5A", build IDs in the rich
    // header, etc). Exec sections next, then writable ones. Same order as the
    // first-hit variant, so results stay consistent.
    if (uint32_t hdr_size = nt.OptionalHeader.SizeOfHeaders)
        scan_region(module_base, hdr_size);
    for (auto& s : sections)
        if (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
            scan_region(module_base + s.VirtualAddress, s.Misc.VirtualSize);
    for (auto& s : sections)
        if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            scan_region(module_base + s.VirtualAddress, s.Misc.VirtualSize);

    return out_hits.size();
}

uint64_t glassbox::SignatureScanModule(DWORD pid, uint64_t module_base, const char* ida_pattern) {
    std::vector<uint64_t> hits;
    SignatureScanModuleAll(pid, module_base, ida_pattern, 1, hits);
    return hits.empty() ? 0 : hits[0];
}
