// ============================================================================
// mcp_stdio.cpp - glassbox-mcp: an MCP (Model Context Protocol) server that
// exposes YOUR kernel driver's process-memory primitives to LLM agents
// (OpenCode, Claude Desktop, any MCP client).
//
// Transport:
//   stdio. Newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio spec).
//   stdout carries ONLY protocol messages; logs go to stderr.
//
// HARD constraint honored by design:
//   This repository contains NO kernel driver and NO driver-loading code.
//   No loader, no mapper, no kernel allocation of its own. The only kernel
//   interaction is CreateFile(<device>) + DeviceIoControl, where <device> is
//   the GLASSBOX_DEVICE environment variable or the \\.\GlassBox default.
//   Your driver must already be loaded when the server starts. See
//   docs/DRIVER-CONTRACT.md.
//
// Safety:
//   Write/alloc/protect tools are gated behind BOTH:
//     - environment GLASSBOX_ALLOW_WRITE=1 on this process, AND
//     - "confirm": true in each tool call's arguments.
//   Reads/scans/enum are ungated (passive analysis).
//
// Build: VS2022, Release|x64. Run elevated (device ACL typically requires admin).
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "glassbox_client.h"
#include "ioctl_defs.h"

#include <nlohmann/json.hpp>

#include <Windows.h>
#include <TlHelp32.h>

#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <iostream>
#include <algorithm>
#include <io.h>
#include <fcntl.h>

using json = nlohmann::json;

// ----------------------------------------------------------------------------
// Constants / caps -- keep tool output sane for LLM context windows.
// ----------------------------------------------------------------------------
static constexpr const char* kServerName    = "glassbox-mcp";
static constexpr const char* kServerVersion = "1.2.0";
static constexpr const char* kDefaultProto  = "2025-06-18";

static constexpr size_t   kMaxReadBytes  = 256 * 1024;    // read tool cap
static constexpr size_t   kMaxHexdump    = 16 * 1024;     // hexdump tool cap
static constexpr size_t   kMaxStringLen  = 4096;          // read_string cap
static constexpr uint64_t kMaxScanRange  = 0x40000000ull; // 1 GiB scan cap
static constexpr size_t   kMaxWriteBytes = 64 * 1024;     // write_bytes cap
static constexpr size_t   kMaxChainDepth = 16;            // pointer chain max
static constexpr size_t   kMaxPatternLen = 256;           // AOB pattern cap
static constexpr size_t   kMaxProcRows   = 512;           // process_list cap
static constexpr size_t   kMaxModuleRows = 1024;          // module_list cap

// User-space bounds (crash prevention). A driver that copies with KernelMode
// requestor mode skips address probing: a kernel-canonical address reaches raw
// memcpy inside Mm and bugchecks 0x50. Unmapped USER addresses fail cleanly
// as NTSTATUS, so every address we send must be inside [kUserMin, kUserMax]
// and ranges must not wrap past kUserMax.
static constexpr uint64_t kUserMin = 0x0000000000010000ull;
static constexpr uint64_t kUserMax = 0x00007FFFFFFEFFFFull;

// ----------------------------------------------------------------------------
// stderr logging + stdout protocol emit
// ----------------------------------------------------------------------------
static void slog(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

static void send_msg(const json& m) {
    // error_handler_t::replace: memory-derived strings may be invalid UTF-8;
    // replace instead of throwing mid-response.
    std::string s = m.dump(-1, ' ', false, json::error_handler_t::replace);
    fwrite(s.data(), 1, s.size(), stdout);
    fputc('\n', stdout);
    fflush(stdout);
}

// ----------------------------------------------------------------------------
// Small string/format helpers
// ----------------------------------------------------------------------------
static std::string hexs(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof(b), "0x%016llX", (unsigned long long)v);
    return b;
}

static std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static std::string wide_to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n,
                        nullptr, nullptr);
    return s;
}

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

// Replace control / non-printable bytes so memory strings never mangle output.
static std::string sanitize_text(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '\t' || c == '\r' || c == '\n') o.push_back((char)c);
        else if (c >= 0x20 && c != 0x7F)         o.push_back((char)c);
        else                                     o.push_back('.');
    }
    return o;
}

static std::string b64encode(const uint8_t* p, size_t n) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((n + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= n) {
        uint32_t v = (uint32_t(p[i]) << 16) | (uint32_t(p[i+1]) << 8) | p[i+2];
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6)  & 63]; out += tbl[v & 63];
        i += 3;
    }
    if (i + 1 == n) {
        uint32_t v = uint32_t(p[i]) << 16;
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63];
        out += "==";
    } else if (i + 2 == n) {
        uint32_t v = (uint32_t(p[i]) << 16) | (uint32_t(p[i+1]) << 8);
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63]; out += "=";
    }
    return out;
}

// ----------------------------------------------------------------------------
// JSON argument parsing helpers.
// 64-bit values may arrive as JSON numbers or as strings ("0x..." or decimal);
// always accept both so agents can copy addresses straight from prior results.
// ----------------------------------------------------------------------------
static bool json_to_u64(const json& j, uint64_t& out) {
    if (j.is_number_unsigned()) { out = j.get<uint64_t>(); return true; }
    if (j.is_number_integer())  { int64_t v = j.get<int64_t>(); if (v < 0) return false; out = (uint64_t)v; return true; }
    if (j.is_number_float())    { double d = j.get<double>(); if (d < 0 || d > 9007199254740992.0) return false; out = (uint64_t)d; return true; }
    if (j.is_string()) {
        std::string s = j.get<std::string>();
        // trim
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
        if (s.empty()) return false;
        char* end = nullptr;
        unsigned long long v = std::strtoull(s.c_str(), &end, 0);  // handles 0x prefix
        if (end == s.c_str() || (end && *end != '\0')) {
            // retry as raw hex without 0x (e.g. "deadbeef00")
            v = std::strtoull(s.c_str(), &end, 16);
            if (end == s.c_str() || (end && *end != '\0')) return false;
        }
        out = (uint64_t)v;
        return true;
    }
    return false;
}

static bool json_to_i64(const json& j, int64_t& out) {
    if (j.is_number_unsigned()) { uint64_t v = j.get<uint64_t>(); if (v > (uint64_t)INT64_MAX) return false; out = (int64_t)v; return true; }
    if (j.is_number_integer())  { out = j.get<int64_t>(); return true; }
    if (j.is_number_float())    { double d = j.get<double>(); out = (int64_t)d; return true; }
    if (j.is_string()) {
        std::string s = j.get<std::string>();
        while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
        while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.pop_back();
        if (s.empty()) return false;
        char* end = nullptr;
        long long v = std::strtoll(s.c_str(), &end, 0);
        if (end == s.c_str() || (end && *end != '\0')) return false;
        out = (int64_t)v;
        return true;
    }
    return false;
}

static bool json_get_addr(const json& args, const char* key, uint64_t& out, std::string& err) {
    if (!args.contains(key) || args[key].is_null()) { err = std::string("missing argument: ") + key; return false; }
    if (!json_to_u64(args[key], out)) { err = std::string("bad ") + key + " (expected hex string like \"0x7FF6A5B00000\" or a number)"; return false; }
    return true;
}

// ----------------------------------------------------------------------------
// User-space address validation (crash prevention). A driver that copies with
// KernelMode requestor mode skips probing: kernel-canonical addresses (e.g.
// "0xFFFFFFFFFFFFFFEB" - usually a garbage deref) reach raw memcpy inside Mm
// and bugcheck. Unmapped USER addresses fail cleanly as NTSTATUS. Reject
// early, with an explanation the agent can act on.
// ----------------------------------------------------------------------------
static bool user_addr_ok(uint64_t addr, uint64_t size, std::string& err) {
    if (addr < kUserMin || addr > kUserMax) {
        err = "address " + hexs(addr) + " is outside user space - rejected. Kernel-canonical "
              "addresses crash the driver; this address is usually a garbage deref, not a real pointer.";
        return false;
    }
    if (size > 0) {
        uint64_t end = addr + size - 1;
        if (end < addr || end > kUserMax) {
            err = "range " + hexs(addr) + " + " + hexs(size) + " bytes leaves user space";
            return false;
        }
    }
    return true;
}

// ----------------------------------------------------------------------------
// Target resolution: tools accept "pid" or "process_name" (unique substring ok)
// ----------------------------------------------------------------------------
struct ProcInfo { DWORD pid; DWORD parent; std::wstring name; };

static std::vector<ProcInfo> enum_processes() {
    std::vector<ProcInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            out.push_back({ pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile });
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

static bool resolve_target(const json& args, DWORD& pid, std::string& err) {
    if (args.contains("pid") && !args.at("pid").is_null()) {
        uint64_t v = 0;
        if (!json_to_u64(args.at("pid"), v) || v == 0 || v > 0xFFFFFFFFull) {
            err = "invalid pid"; return false;
        }
        pid = (DWORD)v;
        return true;
    }
    std::string name;
    if (args.contains("process_name") && args.at("process_name").is_string())
        name = args.at("process_name").get<std::string>();
    if (name.empty() && args.contains("name") && args.at("name").is_string())
        name = args.at("name").get<std::string>();
    if (name.empty()) { err = "missing target: pass \"pid\" or \"process_name\""; return false; }

    auto procs = enum_processes();
    std::wstring wname = utf8_to_wide(name);
    for (auto& p : procs)
        if (_wcsicmp(p.name.c_str(), wname.c_str()) == 0) { pid = p.pid; return true; }

    // unique substring fallback
    std::string needle = lower_copy(name);
    std::vector<std::pair<DWORD, std::string>> hits;
    for (auto& p : procs) {
        std::string n = lower_copy(wide_to_utf8(p.name));
        if (n.find(needle) != std::string::npos) hits.push_back({ p.pid, wide_to_utf8(p.name) });
    }
    if (hits.empty()) { err = "no process matching \"" + name + "\" (call process_list)"; return false; }
    if (hits.size() > 1) {
        err = "multiple processes match \"" + name + "\": ";
        for (size_t i = 0; i < hits.size() && i < 8; ++i)
            err += hits[i].second + " (pid " + std::to_string(hits[i].first) + ") ";
        err += "-- pass an exact pid";
        return false;
    }
    pid = hits[0].first;
    return true;
}

// ----------------------------------------------------------------------------
// Module enumeration (usermode Toolhelp -- good enough for listing/sizes)
// ----------------------------------------------------------------------------
struct ModInfo { uint64_t base; uint32_t size; std::wstring name; std::wstring path; };

static bool enum_modules(DWORD pid, std::vector<ModInfo>& out, uint32_t& win_err) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) { win_err = GetLastError(); return false; }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap, &me)) { win_err = GetLastError(); CloseHandle(snap); return false; }
    do {
        out.push_back({ (uint64_t)(uintptr_t)me.modBaseAddr, me.modBaseSize, me.szModule, me.szExePath });
    } while (Module32NextW(snap, &me));
    CloseHandle(snap);
    return true;
}

// ----------------------------------------------------------------------------
// Driver connection
// ----------------------------------------------------------------------------
static bool ensure_driver(std::string& err) {
    if (glassbox::IsOpen()) return true;
    if (!glassbox::Open()) {
        err = "cannot open device " + glassbox::DeviceName() +
              " (Win32 error " + std::to_string(GetLastError()) + "). "
              "Your driver must be loaded and its device name must match -- "
              "set GLASSBOX_DEVICE if it differs from \\\\.\\GlassBox. "
              "The MCP server (and its host terminal) must also run elevated "
              "(admin): Win32 error 2 = device not found, 5 = access denied. "
              "See docs/DRIVER-CONTRACT.md.";
        return false;
    }
    slog("[mcp] connected to %s", glassbox::DeviceName().c_str());
    return true;
}

// ----------------------------------------------------------------------------
// Value types (shared by read_value / read_chain / write_value)
// ----------------------------------------------------------------------------
enum class VT { U8, U16, U32, U64, I8, I16, I32, I64, F32, F64, BOOL, PTR, INVALID };

static VT parse_vtype(std::string s) {
    s = lower_copy(s);
    if (s == "u8" || s == "uint8" || s == "byte")        return VT::U8;
    if (s == "u16" || s == "uint16" || s == "ushort")    return VT::U16;
    if (s == "u32" || s == "uint32" || s == "dword" || s == "uint") return VT::U32;
    if (s == "u64" || s == "uint64")                     return VT::U64;
    if (s == "i8" || s == "int8")                        return VT::I8;
    if (s == "i16" || s == "int16" || s == "short")      return VT::I16;
    if (s == "i32" || s == "int32" || s == "int")        return VT::I32;
    if (s == "i64" || s == "int64")                      return VT::I64;
    if (s == "float" || s == "f32")                      return VT::F32;
    if (s == "double" || s == "f64")                     return VT::F64;
    if (s == "bool")                                     return VT::BOOL;
    if (s == "pointer" || s == "ptr")                    return VT::PTR;
    return VT::INVALID;
}

static const char* vtype_name(VT t) {
    switch (t) {
        case VT::U8:   return "u8";
        case VT::U16:  return "u16";
        case VT::U32:  return "u32";
        case VT::U64:  return "u64";
        case VT::I8:   return "i8";
        case VT::I16:  return "i16";
        case VT::I32:  return "i32";
        case VT::I64:  return "i64";
        case VT::F32:  return "float";
        case VT::F64:  return "double";
        case VT::BOOL: return "bool";
        case VT::PTR:  return "pointer";
        default:       return "invalid";
    }
}

static size_t vtype_size(VT t) {
    switch (t) {
        case VT::U8: case VT::I8: case VT::BOOL: return 1;
        case VT::U16: case VT::I16:              return 2;
        case VT::U32: case VT::I32: case VT::F32: return 4;
        case VT::U64: case VT::I64: case VT::F64: case VT::PTR: return 8;
        default: return 0;
    }
}

// Read a typed value into a JSON field (64-bit ints emitted as hex strings to
// survive JSON double precision; everything else is native JSON).
static bool read_typed(DWORD pid, uint64_t addr, VT t, json& value_out, std::string& err) {
    uint8_t buf[8] = {};
    size_t sz = vtype_size(t);
    if (!glassbox::ReadProcessMemory(pid, addr, buf, sz)) {
        char e[160];
        std::snprintf(e, sizeof(e), "READ ioctl failed @ %s (unreadable address, freed memory, or wrong pid)", hexs(addr).c_str());
        err = e;
        return false;
    }
    switch (t) {
        case VT::U8:   value_out = buf[0]; break;
        case VT::U16:  { uint16_t v; std::memcpy(&v, buf, 2); value_out = v; break; }
        case VT::U32:  { uint32_t v; std::memcpy(&v, buf, 4); value_out = v; break; }
        case VT::I8:   { int8_t   v; std::memcpy(&v, buf, 1); value_out = v; break; }
        case VT::I16:  { int16_t  v; std::memcpy(&v, buf, 2); value_out = v; break; }
        case VT::I32:  { int32_t  v; std::memcpy(&v, buf, 4); value_out = v; break; }
        case VT::F32:  { float    v; std::memcpy(&v, buf, 4); value_out = (double)v; break; }
        case VT::F64:  { double   v; std::memcpy(&v, buf, 8); value_out = v; break; }
        case VT::BOOL: value_out = buf[0] != 0; break;
        case VT::U64: case VT::PTR: {
            uint64_t v; std::memcpy(&v, buf, 8);
            value_out = json::object();
            value_out["hex"] = hexs(v);
            value_out["dec"] = std::to_string(v);
            break;
        }
        case VT::I64: {
            int64_t v; std::memcpy(&v, buf, 8);
            value_out = json::object();
            value_out["hex"] = hexs((uint64_t)v);
            value_out["dec"] = std::to_string(v);
            break;
        }
        default: err = "invalid type"; return false;
    }
    return true;
}

static bool write_typed(DWORD pid, uint64_t addr, VT t, const json& value, std::string& err) {
    switch (t) {
        case VT::U8: case VT::BOOL: {
            int64_t v; if (!json_to_i64(value, v)) { err = "bad value for " + std::string(vtype_name(t)); return false; }
            uint8_t b = (uint8_t)(v & 0xFF);
            if (!glassbox::WriteProcessMemory(pid, addr, &b, 1)) { err = "WRITE ioctl failed @ " + hexs(addr); return false; }
            return true;
        }
        case VT::U16: case VT::I16: {
            int64_t v; if (!json_to_i64(value, v)) { err = "bad value"; return false; }
            int16_t w = (int16_t)(v & 0xFFFF);
            if (!glassbox::WriteProcessMemory(pid, addr, &w, 2)) { err = "WRITE ioctl failed @ " + hexs(addr); return false; }
            return true;
        }
        case VT::U32: case VT::I32: {
            int64_t v; if (!json_to_i64(value, v)) { err = "bad value"; return false; }
            int32_t w = (int32_t)(v & 0xFFFFFFFFll);
            if (!glassbox::WriteProcessMemory(pid, addr, &w, 4)) { err = "WRITE ioctl failed @ " + hexs(addr); return false; }
            return true;
        }
        case VT::U64: case VT::PTR: case VT::I64: {
            uint64_t v; if (!json_to_u64(value, v)) { err = "bad value (hex string or number)"; return false; }
            if (!glassbox::WriteProcessMemory(pid, addr, &v, 8)) { err = "WRITE ioctl failed @ " + hexs(addr); return false; }
            return true;
        }
        case VT::F32: {
            if (!value.is_number()) { err = "float value must be a number"; return false; }
            float f = (float)value.get<double>();
            if (!glassbox::WriteProcessMemory(pid, addr, &f, 4)) { err = "WRITE ioctl failed @ " + hexs(addr); return false; }
            return true;
        }
        case VT::F64: {
            if (!value.is_number()) { err = "double value must be a number"; return false; }
            double d = value.get<double>();
            if (!glassbox::WriteProcessMemory(pid, addr, &d, 8)) { err = "WRITE ioctl failed @ " + hexs(addr); return false; }
            return true;
        }
        default: err = "invalid type"; return false;
    }
}

// ----------------------------------------------------------------------------
// Protection flags
// ----------------------------------------------------------------------------
static bool parse_protect(const json& j, ULONG& out, std::string& err) {
    if (j.is_number_integer() || j.is_number_unsigned()) {
        int64_t v = j.get<int64_t>();
        out = (ULONG)v;
        return true;
    }
    if (j.is_string()) {
        std::string s = lower_copy(j.get<std::string>());
        if      (s == "r")        { out = PAGE_READONLY; return true; }
        else if (s == "rw" || s == "wr") { out = PAGE_READWRITE; return true; }
        else if (s == "rx" || s == "xr") { out = PAGE_EXECUTE_READ; return true; }
        else if (s == "rwx" || s == "rxw" || s == "wrx" || s == "xwr") { out = PAGE_EXECUTE_READWRITE; return true; }
        // numeric string fallback ("0x04")
        char* end = nullptr;
        unsigned long v = std::strtoul(s.c_str(), &end, 0);
        if (end != s.c_str() && end && *end == '\0') { out = (ULONG)v; return true; }
    }
    err = "protect must be one of: \"r\", \"rw\", \"rx\", \"rwx\" (or a raw PAGE_* integer)";
    return false;
}

// ----------------------------------------------------------------------------
// Write gate
// ----------------------------------------------------------------------------
static bool g_allow_write = false;

static bool write_gate(const json& args, std::string& err) {
    if (!g_allow_write) {
        err = "writes are disabled: set environment variable GLASSBOX_ALLOW_WRITE=1 "
              "on the glassbox MCP server and restart it to enable write tools";
        return false;
    }
    if (!args.value("confirm", false)) {
        err = "this write tool requires \"confirm\": true in its arguments";
        return false;
    }
    return true;
}

// ----------------------------------------------------------------------------
// Tool implementations
// ----------------------------------------------------------------------------
static json errj(const std::string& e) {
    json r = json::object();
    r["ok"] = false;
    r["error"] = e;
    return r;
}

// ---- process_list -----------------------------------------------------------
static json h_process_list(const json& args) {
    std::string filter = args.value("filter", "");
    std::string fl = lower_copy(filter);
    auto procs = enum_processes();
    json arr = json::array();
    for (auto& p : procs) {
        std::string name = wide_to_utf8(p.name);
        if (!fl.empty() && lower_copy(name).find(fl) == std::string::npos) continue;
        json row = json::object();
        row["pid"] = p.pid;
        row["name"] = name;
        row["parent_pid"] = p.parent;
        arr.push_back(row);
        if (arr.size() >= kMaxProcRows) break;
    }
    json r = json::object();
    r["ok"] = true;
    r["count"] = arr.size();
    r["processes"] = arr;
    return r;
}

// ---- module_list ------------------------------------------------------------
static json h_module_list(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    std::vector<ModInfo> mods;
    uint32_t win_err = 0;
    if (!enum_modules(pid, mods, win_err)) {
        char e[200];
        std::snprintf(e, sizeof(e), "Toolhelp module snapshot failed for pid %lu (Win32 error %lu) -- "
                                    "protected or short-lived process?", (unsigned long)pid, (unsigned long)win_err);
        return errj(e);
    }
    json arr = json::array();
    for (auto& m : mods) {
        if (arr.size() >= kMaxModuleRows) break;
        json row = json::object();
        row["name"] = wide_to_utf8(m.name);
        row["base"] = hexs(m.base);
        row["size"] = m.size;
        row["end"]  = hexs(m.base + m.size);
        row["path"] = wide_to_utf8(m.path);
        arr.push_back(row);
    }
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["count"] = arr.size();
    r["modules"] = arr;
    return r;
}

// ---- module_base (kernel-resolved) ------------------------------------------
static json h_module_base(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    if (!args.contains("module_name") || !args.at("module_name").is_string())
        return errj("missing argument: module_name (e.g. \"kernel32.dll\")");
    std::wstring mod = utf8_to_wide(args.at("module_name").get<std::string>());

    if (!ensure_driver(err)) return errj(err);
    uint64_t base = glassbox::GetModuleBase(pid, mod);
    if (!base) return errj("kernel MODBASE returned 0 -- module not found in target "
                           "(name must match, e.g. \"kernel32.dll\", \"user32.dll\")");

    // best-effort size enrichment from Toolhelp
    uint64_t size = 0;
    std::vector<ModInfo> mods;
    uint32_t we = 0;
    if (enum_modules(pid, mods, we)) {
        for (auto& m : mods) {
            if (_wcsicmp(m.name.c_str(), mod.c_str()) == 0) { size = m.size; break; }
        }
    }
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["module_name"] = wide_to_utf8(mod);
    r["base"] = hexs(base);
    if (size) { r["size"] = size; r["end"] = hexs(base + size); }
    return r;
}

// ---- read -------------------------------------------------------------------
static json h_read(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    size_t size = 64;
    if (args.contains("size") && !args.at("size").is_null()) {
        int64_t v; if (!json_to_i64(args.at("size"), v) || v <= 0) return errj("bad size");
        size = (size_t)v;
    }
    if (size > kMaxReadBytes) {
        char e[160];
        std::snprintf(e, sizeof(e), "size %zu exceeds cap %zu per call", size, kMaxReadBytes);
        return errj(e);
    }
    if (!user_addr_ok(addr, size, err)) return errj(err);
    if (!ensure_driver(err)) return errj(err);
    std::vector<uint8_t> buf(size);
    if (!glassbox::ReadProcessMemory(pid, addr, buf.data(), size))
        return errj("READ ioctl failed @ " + hexs(addr) + " (unreadable address, freed memory, or wrong pid)");

    std::string hex;
    hex.reserve(size * 3 + 16);
    char b[4];
    for (size_t i = 0; i < size; ++i) {
        std::snprintf(b, sizeof(b), "%02X ", buf[i]);
        hex += b;
    }
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["size"] = size;
    r["hex"] = hex;
    r["base64"] = b64encode(buf.data(), size);
    if (size > 4096) r["warning"] = "large read: this hex blob is large in your context; prefer smaller sizes or hexdump";
    return r;
}

// ---- hexdump ----------------------------------------------------------------
static json h_hexdump(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    size_t size = 256;
    if (args.contains("size") && !args.at("size").is_null()) {
        int64_t v; if (!json_to_i64(args.at("size"), v) || v <= 0) return errj("bad size");
        size = (size_t)v;
    }
    if (size > kMaxHexdump) {
        char e[160];
        std::snprintf(e, sizeof(e), "size %zu exceeds hexdump cap %zu per call", size, kMaxHexdump);
        return errj(e);
    }
    if (!user_addr_ok(addr, size, err)) return errj(err);
    if (!ensure_driver(err)) return errj(err);
    std::vector<uint8_t> buf(size);
    if (!glassbox::ReadProcessMemory(pid, addr, buf.data(), size))
        return errj("READ ioctl failed @ " + hexs(addr));

    std::string out;
    out.reserve((size / 16 + 2) * 80);
    char line[64];
    for (size_t i = 0; i < buf.size(); i += 16) {
        int n = std::snprintf(line, sizeof(line), "%016llX  ", (unsigned long long)(addr + i));
        out.append(line, (size_t)n);
        for (int j = 0; j < 16; ++j) {
            if (i + (size_t)j < buf.size()) {
                n = std::snprintf(line, sizeof(line), "%02X ", buf[i + j]);
                out.append(line, (size_t)n);
            } else out += "   ";
            if (j == 7) out += ' ';
        }
        out += " |";
        for (int j = 0; j < 16 && i + (size_t)j < buf.size(); ++j) {
            unsigned char c = buf[i + j];
            out.push_back((c >= 0x20 && c != 0x7F) ? (char)c : '.');
        }
        out += "|";
        if (i + 16 < buf.size()) out += "\n";
    }
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["size"] = size;
    r["dump"] = out;
    return r;
}

// ---- read_value -------------------------------------------------------------
static json h_read_value(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    VT t = VT::U32;
    if (args.contains("type") && args.at("type").is_string()) {
        t = parse_vtype(args.at("type").get<std::string>());
        if (t == VT::INVALID) return errj("bad type: use u8 u16 u32 u64 i8 i16 i32 i64 float double bool pointer");
    }
    if (!ensure_driver(err)) return errj(err);
    if (!user_addr_ok(addr, vtype_size(t), err)) return errj(err);
    json value;
    if (!read_typed(pid, addr, t, value, err)) return errj(err);
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["type"] = vtype_name(t);
    r["value"] = value;
    return r;
}

// ---- read_chain -------------------------------------------------------------
static json h_read_chain(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t base = 0;
    if (!json_get_addr(args, "base", base, err)) return errj(err);
    if (!args.contains("offsets") || !args.at("offsets").is_array() || args.at("offsets").empty())
        return errj("offsets must be a non-empty array of integers (e.g. [0x10, 0x28, 0x8])");
    const json& offs = args.at("offsets");
    if (offs.size() > kMaxChainDepth) return errj("too many offsets (max 16)");
    std::vector<int64_t> off;
    for (auto& o : offs) {
        int64_t v; if (!json_to_i64(o, v)) return errj("bad offset (integers only)");
        off.push_back(v);
    }
    VT t = VT::U64;
    if (args.contains("type") && args.at("type").is_string()) {
        t = parse_vtype(args.at("type").get<std::string>());
        if (t == VT::INVALID) return errj("bad type");
    }
    if (!ensure_driver(err)) return errj(err);
    if (!user_addr_ok(base, 0, err)) return errj(err);

    uint64_t addr = base;
    json chain = json::array();
    for (size_t i = 0; i + 1 < off.size(); ++i) {
        uint64_t probe = addr + (uint64_t)off[i];
        if (!user_addr_ok(probe, 8, err)) {
            err += " (chain step " + std::to_string(i) + ": base+offset walked outside user space)";
            return errj(err);
        }
        uint64_t next = 0;
        if (!glassbox::Read<uint64_t>(pid, probe, next) || !next) {
            char e[200];
            std::snprintf(e, sizeof(e), "chain broken at step %zu: could not read pointer @ %s (base+offsets[0..%zu])",
                          i, hexs(probe).c_str(), i);
            return errj(e);
        }
        // A dereferenced value becomes the next address. If it is kernel-canonical
        // or trivially bogus, stop BEFORE using it - this is exactly how garbage
        // (misinterpreted floats, failed derefs) used to become crashes.
        if (next < kUserMin || next > kUserMax) {
            char e[240];
            std::snprintf(e, sizeof(e), "chain stopped at step %zu: deref @ %s read 0x%llX which is outside user "
                                         "space - the chain is following garbage, not a real pointer",
                          i, hexs(probe).c_str(), (unsigned long long)next);
            return errj(e);
        }
        addr = next;
        chain.push_back(hexs(addr));
    }
    uint64_t final_addr = addr + (uint64_t)off.back();
    if (!user_addr_ok(final_addr, vtype_size(t), err)) {
        err += " (final chain address)";
        return errj(err);
    }
    json value;
    if (!read_typed(pid, final_addr, t, value, err)) return errj(err);
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["base"] = hexs(base);
    r["deref_chain"] = chain;
    r["final_address"] = hexs(final_addr);
    r["type"] = vtype_name(t);
    r["value"] = value;
    return r;
}

// ---- read_string ------------------------------------------------------------
static json h_read_string(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    size_t max_len = 256;
    if (args.contains("max_len") && !args.at("max_len").is_null()) {
        int64_t v; if (!json_to_i64(args.at("max_len"), v) || v <= 0) return errj("bad max_len");
        max_len = (size_t)v;
    }
    if (max_len > kMaxStringLen) max_len = kMaxStringLen;
    std::string enc = args.value("encoding", "ascii");
    if (!ensure_driver(err)) return errj(err);
    if (!user_addr_ok(addr, max_len, err)) return errj(err);

    std::string text;
    if (enc == "utf16" || enc == "unicode" || enc == "wide") {
        text = wide_to_utf8(glassbox::ReadWString(pid, addr, max_len));
    } else if (enc == "ascii" || enc == "utf8" || enc == "ansi") {
        text = glassbox::ReadString(pid, addr, max_len);
    } else {
        return errj("encoding must be \"ascii\" or \"utf16\"");
    }
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["encoding"] = enc;
    r["length"] = text.size();
    r["text"] = sanitize_text(text);
    return r;
}

// ---- scan helpers -----------------------------------------------------------
static json hits_to_json(DWORD pid, const std::vector<uint64_t>& hits,
                         uint64_t offset_base, size_t context) {
    json arr = json::array();
    char b[4];
    for (uint64_t h : hits) {
        json o = json::object();
        o["address"] = hexs(h);
        o["offset"] = h - offset_base;
        if (context) {
            std::vector<uint8_t> cb(context * 2);
            uint64_t cs = h >= (uint64_t)context ? h - context : 0;
            if (cs >= kUserMin && glassbox::ReadProcessMemory(pid, cs, cb.data(), cb.size())) {
                std::string hex;
                for (size_t i = 0; i < cb.size(); ++i) {
                    std::snprintf(b, sizeof(b), "%02X ", cb[i]);
                    hex += b;
                }
                o["context_hex"] = hex;
            }
        }
        arr.push_back(o);
    }
    return arr;
}

// all / max_results / context parsing shared by scan + scan_module
static bool parse_scan_opts(const json& args, bool& all, size_t& max_results,
                            size_t& context, std::string& err) {
    all = args.value("all", false);
    max_results = 64;
    if (args.contains("max_results") && !args.at("max_results").is_null()) {
        int64_t m;
        if (!json_to_i64(args.at("max_results"), m) || m <= 0) { err = "bad max_results"; return false; }
        max_results = (size_t)m;
        if (max_results > 4096) max_results = 4096;
    }
    context = 0;
    if (args.contains("context") && !args.at("context").is_null()) {
        int64_t c;
        if (!json_to_i64(args.at("context"), c) || c < 0) { err = "bad context"; return false; }
        context = (size_t)c;
        if (context > 64) context = 64;
    }
    return true;
}

// module argument (name or base) -> base; driver must be connected for names
static bool resolve_module_base(DWORD pid, const json& m, uint64_t& base, std::string& err) {
    if (m.is_string()) {
        std::string ms = m.get<std::string>();
        uint64_t v = 0;
        if (json_to_u64(m, v) && (ms.rfind("0x", 0) == 0 || ms.find_first_not_of("0123456789 ") == std::string::npos))
            base = v;
        else {
            if (!ensure_driver(err)) return false;
            base = glassbox::GetModuleBase(pid, utf8_to_wide(ms));
            if (!base) { err = "module not found in target (call module_list)"; return false; }
        }
        return true;
    }
    if (!json_to_u64(m, base) || !base) { err = "bad module argument"; return false; }
    return true;
}

static uint64_t module_size_for(DWORD pid, uint64_t base, const std::wstring& name_hint) {
    std::vector<ModInfo> mods;
    uint32_t we = 0;
    if (!enum_modules(pid, mods, we)) return 0;
    for (auto& m : mods) {
        if (m.base == base) return m.size;
        if (!name_hint.empty() && _wcsicmp(m.name.c_str(), name_hint.c_str()) == 0) return m.size;
    }
    return 0;
}

// ---- scan -------------------------------------------------------------------
static json h_scan(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t start = 0;
    if (!json_get_addr(args, "start", start, err)) return errj(err);
    size_t size = 0;
    if (!args.contains("size")) return errj("missing argument: size (bytes to scan)");
    int64_t v; if (!json_to_i64(args.at("size"), v) || v <= 0) return errj("bad size");
    size = (size_t)v;
    if (size > kMaxScanRange) return errj("size exceeds 1 GiB cap");
    if (!user_addr_ok(start, size, err)) return errj(err);
    if (!args.contains("pattern") || !args.at("pattern").is_string())
        return errj("missing argument: pattern (IDA-style, e.g. \"48 8B 0D ?? ?? ?? ??\")");
    std::string pattern = args.at("pattern").get<std::string>();
    if (pattern.size() > kMaxPatternLen * 4) return errj("pattern too long");
    bool all = false; size_t max_results = 64, context = 0;
    if (!parse_scan_opts(args, all, max_results, context, err)) return errj(err);
    if (!all) max_results = 1;
    if (!ensure_driver(err)) return errj(err);

    std::vector<uint64_t> hits;
    if (all) glassbox::SignatureScanAll(pid, start, size, pattern.c_str(), max_results, hits);
    else {
        uint64_t hit = glassbox::SignatureScan(pid, start, size, pattern.c_str());
        if (hit) hits.push_back(hit);
    }
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["start"] = hexs(start);
    r["size"] = size;
    r["pattern"] = pattern;
    r["found"] = !hits.empty();
    r["count"] = hits.size();
    if (!hits.empty()) {
        r["address"] = hexs(hits[0]);
        r["offset"] = hits[0] - start;
    }
    if (all || context) r["hits"] = hits_to_json(pid, hits, start, context);
    return r;
}

// ---- scan_module ------------------------------------------------------------
static json h_scan_module(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    if (!args.contains("pattern") || !args.at("pattern").is_string())
        return errj("missing argument: pattern (IDA-style)");
    std::string pattern = args.at("pattern").get<std::string>();
    if (!args.contains("module") || args.at("module").is_null())
        return errj("missing argument: module (name like \"kernel32.dll\" or base address)");
    if (!ensure_driver(err)) return errj(err);
    uint64_t base = 0;
    if (!resolve_module_base(pid, args.at("module"), base, err)) return errj(err);
    bool all = false; size_t max_results = 64, context = 0;
    if (!parse_scan_opts(args, all, max_results, context, err)) return errj(err);
    if (!all) max_results = 1;

    std::vector<uint64_t> hits;
    if (all) glassbox::SignatureScanModuleAll(pid, base, pattern.c_str(), max_results, hits);
    else {
        uint64_t hit = glassbox::SignatureScanModule(pid, base, pattern.c_str());
        if (hit) hits.push_back(hit);
    }
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["module_base"] = hexs(base);
    r["pattern"] = pattern;
    r["found"] = !hits.empty();
    r["count"] = hits.size();
    if (!hits.empty()) {
        r["address"] = hexs(hits[0]);
        r["module_offset"] = hits[0] - base;
    }
    if (all || context) r["hits"] = hits_to_json(pid, hits, base, context);
    return r;
}

// ---- alloc (gated) ----------------------------------------------------------
static json h_alloc(const json& args) {
    std::string err;
    if (!write_gate(args, err)) return errj(err);
    DWORD pid = 0;
    if (!resolve_target(args, pid, err)) return errj(err);
    if (!args.contains("size")) return errj("missing argument: size");
    int64_t v; if (!json_to_i64(args.at("size"), v) || v <= 0 || v > 0x10000000ll)
        return errj("bad size (1 .. 256 MiB)");
    ULONG protect = PAGE_READWRITE;
    if (args.contains("protect") && !args.at("protect").is_null())
        if (!parse_protect(args.at("protect"), protect, err)) return errj(err);
    if (!ensure_driver(err)) return errj(err);

    uint64_t va = glassbox::AllocateMemory(pid, (size_t)v, protect);
    if (!va) return errj("ALLOC ioctl failed (kernel refused)");
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(va);
    r["size"] = (size_t)v;
    r["protect"] = (int64_t)protect;
    return r;
}

// ---- protect (gated) --------------------------------------------------------
static json h_protect(const json& args) {
    std::string err;
    if (!write_gate(args, err)) return errj(err);
    DWORD pid = 0;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    if (!args.contains("size")) return errj("missing argument: size");
    int64_t v; if (!json_to_i64(args.at("size"), v) || v <= 0) return errj("bad size");
    ULONG protect = 0;
    if (!args.contains("protect")) return errj("missing argument: protect");
    if (!parse_protect(args.at("protect"), protect, err)) return errj(err);
    if (!user_addr_ok(addr, (size_t)v, err)) return errj(err);
    if (!ensure_driver(err)) return errj(err);

    if (!glassbox::ProtectMemory(pid, addr, (size_t)v, protect))
        return errj("PROTECT ioctl failed");
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["size"] = (size_t)v;
    r["protect"] = (int64_t)protect;
    return r;
}

// ---- write_bytes (gated) ----------------------------------------------------
static bool parse_hex_bytes(const std::string& in, std::vector<uint8_t>& out) {
    static const auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    int hi = -1;
    for (char c : in) {
        if (c == ' ' || c == '\t' || c == ',' || c == '\n' || c == '\r') continue;
        if (hi < 0) { hi = hexval(c); if (hi < 0) return false; }
        else {
            int lo = hexval(c);
            if (lo < 0) return false;
            out.push_back((uint8_t)((hi << 4) | lo));
            hi = -1;
        }
    }
    return hi < 0 && !out.empty();
}

static json h_write_bytes(const json& args) {
    std::string err;
    if (!write_gate(args, err)) return errj(err);
    DWORD pid = 0;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    if (!args.contains("hex") || !args.at("hex").is_string())
        return errj("missing argument: hex (e.g. \"DE AD BE EF\" or \"DEADBEEF\")");
    std::vector<uint8_t> bytes;
    if (!parse_hex_bytes(args.at("hex").get<std::string>(), bytes))
        return errj("bad hex: even number of hex digits required");
    if (bytes.size() > kMaxWriteBytes) {
        char e[160];
        std::snprintf(e, sizeof(e), "payload %zu bytes exceeds cap %zu", bytes.size(), kMaxWriteBytes);
        return errj(e);
    }
    if (!user_addr_ok(addr, bytes.size(), err)) return errj(err);
    if (!ensure_driver(err)) return errj(err);

    if (!glassbox::WriteBytes(pid, addr, bytes))
        return errj("WRITE ioctl failed @ " + hexs(addr));
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["written"] = bytes.size();
    // verify by read-back
    std::vector<uint8_t> back(bytes.size());
    if (glassbox::ReadProcessMemory(pid, addr, back.data(), back.size())) {
        r["verified"] = std::memcmp(back.data(), bytes.data(), bytes.size()) == 0;
        std::string hex;
        char b[4];
        for (size_t i = 0; i < back.size() && i < 64; ++i) {
            std::snprintf(b, sizeof(b), "%02X ", back[i]);
            hex += b;
        }
        r["readback_hex"] = hex;
    } else {
        r["verified"] = false;
    }
    return r;
}

// ---- write_value (gated) ----------------------------------------------------
static json h_write_value(const json& args) {
    std::string err;
    if (!write_gate(args, err)) return errj(err);
    DWORD pid = 0;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    if (!args.contains("type") || !args.at("type").is_string()) return errj("missing argument: type");
    VT t = parse_vtype(args.at("type").get<std::string>());
    if (t == VT::INVALID) return errj("bad type");
    if (!args.contains("value")) return errj("missing argument: value");
    if (!ensure_driver(err)) return errj(err);
    if (!user_addr_ok(addr, vtype_size(t), err)) return errj(err);

    if (!write_typed(pid, addr, t, args.at("value"), err)) return errj(err);
    // verify by read-back
    json back;
    bool ok = read_typed(pid, addr, t, back, err);
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["type"] = vtype_name(t);
    r["readback"] = ok ? back : json(nullptr);
    return r;
}

// ---- write_string (gated) ---------------------------------------------------
static json h_write_string(const json& args) {
    std::string err;
    if (!write_gate(args, err)) return errj(err);
    DWORD pid = 0;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t addr = 0;
    if (!json_get_addr(args, "address", addr, err)) return errj(err);
    if (!args.contains("text") || !args.at("text").is_string()) return errj("missing argument: text");
    std::string text = args.at("text").get<std::string>();
    if (text.size() > kMaxWriteBytes) return errj("text too long");
    std::string enc = args.value("encoding", "ascii");
    bool include_null = args.value("include_null", true);
    if (enc != "ascii" && enc != "utf8" && enc != "ansi" &&
        enc != "utf16" && enc != "unicode" && enc != "wide")
        return errj("encoding must be \"ascii\" or \"utf16\"");
    if (!ensure_driver(err)) return errj(err);

    // Pre-compute the write length so validation covers the full range.
    bool wide = (enc == "utf16" || enc == "unicode" || enc == "wide");
    size_t written;
    if (wide) written = (utf8_to_wide(text).size() + (include_null ? 1 : 0)) * 2;
    else      written = text.size() + (include_null ? 1 : 0);
    if (!user_addr_ok(addr, written, err)) return errj(err);

    bool ok;
    if (wide) {
        ok = glassbox::WriteWString(pid, addr, utf8_to_wide(text), include_null);
    } else {
        ok = glassbox::WriteString(pid, addr, text, include_null);
    }
    if (!ok) return errj("WRITE ioctl failed @ " + hexs(addr));
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["address"] = hexs(addr);
    r["encoding"] = enc;
    r["written"] = written;
    return r;
}

// ---- find_string ------------------------------------------------------------
// Literal text search. Chunked reads with patternLen-1 overlap; optional
// case folding for pure-ASCII patterns.
static size_t FindLiteralAll(DWORD pid, uint64_t start, size_t size,
                             const std::vector<uint8_t>& pat_in, bool fold_ascii,
                             size_t max_results, std::vector<uint64_t>& out) {
    if (pat_in.empty() || size < pat_in.size() || max_results == 0) return 0;
    std::vector<uint8_t> p = pat_in;
    bool fold = fold_ascii;
    if (fold) for (uint8_t c : p) if (c >= 0x80) { fold = false; break; }
    if (fold) for (auto& c : p) c = (uint8_t)std::tolower(c);

    constexpr size_t kChunk = 256 * 1024;
    const size_t overlap = p.size() - 1;
    std::vector<uint8_t> buf(kChunk);
    uint64_t pos = 0;
    while (pos < size && out.size() < max_results) {
        size_t want = (std::min)(kChunk, size - pos);
        if (glassbox::ReadProcessMemory(pid, start + pos, buf.data(), want)) {
            const size_t end = want - p.size();
            for (size_t i = 0; i <= end && out.size() < max_results; ++i) {
                bool ok = true;
                for (size_t j = 0; j < p.size(); ++j) {
                    uint8_t a = buf[i + j];
                    if (fold && a < 0x80) a = (uint8_t)std::tolower(a);
                    if (a != p[j]) { ok = false; break; }
                }
                if (ok) out.push_back(start + pos + i);
            }
            if (want < kChunk) break;
            pos += kChunk - overlap;
        } else {
            pos += want;
        }
    }
    return out.size();
}

static json h_find_string(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    if (!args.contains("text") || !args.at("text").is_string())
        return errj("missing argument: text (literal string to search for)");
    std::string text = args.at("text").get<std::string>();
    if (text.empty() || text.size() > 1024) return errj("text must be 1..1024 chars");
    std::string enc = args.value("encoding", "ascii");
    bool fold = !args.value("case_sensitive", true);

    std::vector<uint8_t> pat;
    if (enc == "utf16" || enc == "unicode" || enc == "wide") {
        std::wstring w = utf8_to_wide(text);
        if (w.empty()) return errj("bad text for utf16");
        pat.resize(w.size() * 2);
        for (size_t i = 0; i < w.size(); ++i) {
            pat[i * 2]     = (uint8_t)(w[i] & 0xFF);
            pat[i * 2 + 1] = (uint8_t)((w[i] >> 8) & 0xFF);
        }
        fold = false;  // utf16 compares exact
    } else if (enc == "ascii" || enc == "utf8" || enc == "ansi") {
        pat.assign(text.begin(), text.end());
    } else {
        return errj("encoding must be \"ascii\" or \"utf16\"");
    }

    bool all = true;
    size_t max_results = 64, context = 16;
    if (!parse_scan_opts(args, all, max_results, context, err)) return errj(err);
    if (max_results > 1024) max_results = 1024;
    if (!args.contains("context")) context = 16;  // parse_scan_opts defaults it to 0

    uint64_t start = 0;
    size_t size = 0;
    if (args.contains("module") && !args.at("module").is_null()) {
        if (!ensure_driver(err)) return errj(err);
        if (!resolve_module_base(pid, args.at("module"), start, err)) return errj(err);
        std::wstring name_hint;
        if (args.at("module").is_string()) name_hint = utf8_to_wide(args.at("module").get<std::string>());
        size = (size_t)module_size_for(pid, start, name_hint);
        if (!size) return errj("could not determine module size (call module_list), or pass start+size instead");
    } else {
        if (!json_get_addr(args, "start", start, err)) return errj(err);
        if (!args.contains("size")) return errj("missing argument: size (or pass module instead)");
        int64_t v; if (!json_to_i64(args.at("size"), v) || v <= 0) return errj("bad size");
        size = (size_t)v;
        if (size > kMaxScanRange) return errj("size exceeds 1 GiB cap");
        if (!ensure_driver(err)) return errj(err);
    }

    std::vector<uint64_t> hits;
    if (!user_addr_ok(start, size, err)) return errj(err);
    FindLiteralAll(pid, start, size, pat, fold, max_results, hits);
    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["text"] = text;
    r["encoding"] = enc;
    r["case_sensitive"] = !fold;
    r["start"] = hexs(start);
    r["size"] = size;
    r["found"] = !hits.empty();
    r["count"] = hits.size();
    r["hits"] = hits_to_json(pid, hits, start, context);
    return r;
}

// ---- read_many --------------------------------------------------------------
static json h_read_many(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    if (!args.contains("items") || !args.at("items").is_array() || args.at("items").empty())
        return errj("items must be a non-empty array of {address, type?} (max 64)");
    const json& items = args.at("items");
    if (items.size() > 64) return errj("items cap is 64 per call");
    std::string default_type = "u32";
    if (args.contains("type") && args.at("type").is_string())
        default_type = args.at("type").get<std::string>();
    if (!ensure_driver(err)) return errj(err);

    json results = json::array();
    size_t okc = 0, errc = 0;
    for (size_t i = 0; i < items.size(); ++i) {
        const json& it = items.at(i);
        json row = json::object();
        row["index"] = i;
        uint64_t addr = 0;
        if (!it.contains("address") || !json_to_u64(it.at("address"), addr)) {
            row["ok"] = false;
            row["error"] = "bad address";
            results.push_back(row);
            ++errc;
            continue;
        }
        row["address"] = hexs(addr);
        std::string tname = default_type;
        if (it.contains("type") && it.at("type").is_string()) tname = it.at("type").get<std::string>();
        VT t = parse_vtype(tname);
        if (t == VT::INVALID) {
            row["ok"] = false;
            row["error"] = "bad type: " + tname;
            results.push_back(row);
            ++errc;
            continue;
        }
        if (!user_addr_ok(addr, vtype_size(t), err)) {
            row["ok"] = false;
            row["error"] = err;
            results.push_back(row);
            ++errc;
            continue;
        }
        json value;
        if (read_typed(pid, addr, t, value, err)) {
            row["ok"] = true;
            row["type"] = vtype_name(t);
            row["value"] = value;
            ++okc;
        } else {
            row["ok"] = false;
            row["type"] = vtype_name(t);
            row["error"] = err;
            ++errc;
        }
        results.push_back(row);
    }
    json r = json::object();
    r["ok"] = errc == 0;
    if (errc) r["partial"] = okc > 0;
    r["pid"] = pid;
    r["ok_count"] = okc;
    r["error_count"] = errc;
    r["results"] = results;
    return r;
}

// ---- read_struct ------------------------------------------------------------
static json h_read_struct(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    uint64_t base = 0;
    if (!json_get_addr(args, "base", base, err)) return errj(err);
    if (!args.contains("fields") || !args.at("fields").is_array() || args.at("fields").empty())
        return errj("fields must be a non-empty array of {offset, type?, name?} (max 64)");
    const json& fields = args.at("fields");
    if (fields.size() > 64) return errj("fields cap is 64 per call");
    std::string default_type = "u32";
    if (args.contains("type") && args.at("type").is_string())
        default_type = args.at("type").get<std::string>();
    if (!ensure_driver(err)) return errj(err);
    if (!user_addr_ok(base, 0, err)) return errj(err);

    json rows = json::array();
    size_t okc = 0, errc = 0;
    for (size_t i = 0; i < fields.size(); ++i) {
        const json& f = fields.at(i);
        json row = json::object();
        int64_t off = 0;
        if (!f.contains("offset") || !json_to_i64(f.at("offset"), off)) {
            row["ok"] = false;
            row["error"] = "bad offset";
            rows.push_back(row);
            ++errc;
            continue;
        }
        uint64_t addr = base + (uint64_t)off;
        row["address"] = hexs(addr);
        if (f.contains("name") && f.at("name").is_string()) row["name"] = f.at("name").get<std::string>();
        std::string tname = default_type;
        if (f.contains("type") && f.at("type").is_string()) tname = f.at("type").get<std::string>();
        VT t = parse_vtype(tname);
        if (t == VT::INVALID) {
            row["ok"] = false;
            row["error"] = "bad type: " + tname;
            rows.push_back(row);
            ++errc;
            continue;
        }
        if (!user_addr_ok(addr, vtype_size(t), err)) {
            row["ok"] = false;
            row["error"] = err;
            rows.push_back(row);
            ++errc;
            continue;
        }
        json value;
        if (read_typed(pid, addr, t, value, err)) {
            row["ok"] = true;
            row["type"] = vtype_name(t);
            row["value"] = value;
            ++okc;
        } else {
            row["ok"] = false;
            row["type"] = vtype_name(t);
            row["error"] = err;
            ++errc;
        }
        rows.push_back(row);
    }
    json r = json::object();
    r["ok"] = errc == 0;
    if (errc) r["partial"] = okc > 0;
    r["pid"] = pid;
    r["base"] = hexs(base);
    r["ok_count"] = okc;
    r["error_count"] = errc;
    r["fields"] = rows;
    return r;
}

// ---- watch ------------------------------------------------------------------
static json h_watch(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    json items_raw;
    if (args.contains("items") && args.at("items").is_array()) {
        items_raw = args.at("items");
    } else if (args.contains("address")) {
        json one = json::array();
        json o = json::object();
        o["address"] = args.at("address");
        if (args.contains("type")) o["type"] = args.at("type");
        one.push_back(o);
        items_raw = one;
    } else {
        return errj("missing items array (or single address)");
    }
    if (items_raw.empty() || items_raw.size() > 16)
        return errj("items must be 1..16 entries");

    std::string default_type = "u32";
    if (args.contains("type") && args.at("type").is_string())
        default_type = args.at("type").get<std::string>();

    struct WItem { uint64_t addr; VT t; };
    std::vector<WItem> items;
    for (auto& it : items_raw) {
        uint64_t a = 0;
        if (!it.contains("address") || !json_to_u64(it.at("address"), a))
            return errj("bad item address");
        VT t = parse_vtype(default_type);
        if (it.contains("type") && it.at("type").is_string()) {
            t = parse_vtype(it.at("type").get<std::string>());
            if (t == VT::INVALID) return errj("bad item type");
        } else if (t == VT::INVALID) {
            return errj("bad default type");
        }
        std::string aerr;
        if (!user_addr_ok(a, vtype_size(t), aerr)) return errj(aerr);
        items.push_back({ a, t });
    }

    size_t samples = 5, interval = 100;
    if (args.contains("samples") && !args.at("samples").is_null()) {
        int64_t s; if (!json_to_i64(args.at("samples"), s) || s <= 0) return errj("bad samples");
        samples = (size_t)s;
        if (samples > 32) samples = 32;
    }
    if (args.contains("interval_ms") && !args.at("interval_ms").is_null()) {
        int64_t m; if (!json_to_i64(args.at("interval_ms"), m) || m <= 0) return errj("bad interval_ms");
        interval = (size_t)m;
        if (interval > 500) interval = 500;
    }
    if ((samples - 1) * interval > 8000)
        return errj("watch window exceeds 8 s (samples*interval_ms cap)");

    if (!ensure_driver(err)) return errj(err);

    std::vector<std::vector<json>> series(samples, std::vector<json>(items.size()));
    for (size_t s = 0; s < samples; ++s) {
        for (size_t i = 0; i < items.size(); ++i) {
            json v;
            std::string e;
            if (read_typed(pid, items[i].addr, items[i].t, v, e)) series[s][i] = v;
            else series[s][i] = json(nullptr);
        }
        if (s + 1 < samples) Sleep((DWORD)interval);
    }

    json results = json::array();
    for (size_t i = 0; i < items.size(); ++i) {
        json row = json::object();
        row["address"] = hexs(items[i].addr);
        row["type"] = vtype_name(items[i].t);
        json sarr = json::array();
        bool all_num = true;
        double mn = 0, mx = 0;
        bool have_mm = false;  // min/max have been seeded (separate from have_first!)
        std::map<std::string, size_t> distinct;
        bool have_first = false, have_last = false;
        json first, last;
        size_t read_errors = 0;
        for (size_t s = 0; s < samples; ++s) {
            const json& v = series[s][i];
            sarr.push_back(v);
            if (v.is_null()) { ++read_errors; all_num = false; continue; }
            if (!v.is_number()) all_num = false;
            else {
                double d = v.get<double>();
                if (!have_mm) { mn = mx = d; have_mm = true; }
                else { mn = mn < d ? mn : d; mx = mx > d ? mx : d; }
            }
            std::string key = v.dump(-1, ' ', false, json::error_handler_t::replace);
            ++distinct[key];
            if (!have_first) { first = v; have_first = true; }
            last = v;
            have_last = true;
        }
        row["samples"] = sarr;
        row["changed"] = have_first && have_last &&
            first.dump() != last.dump();
        row["distinct"] = distinct.size();
        if (all_num) {
            row["min"] = mn;
            row["max"] = mx;
        }
        if (read_errors) row["read_errors"] = read_errors;
        results.push_back(row);
    }

    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["samples_taken"] = samples;
    r["interval_ms"] = interval;
    r["results"] = results;
    return r;
}

// ---- region_list ------------------------------------------------------------
static std::string protect_str(DWORD p) {
    std::string s;
    switch (p & 0xFF) {
        case PAGE_NOACCESS:             s = "NA";  break;
        case PAGE_READONLY:             s = "R";   break;
        case PAGE_READWRITE:            s = "RW";  break;
        case PAGE_WRITECOPY:            s = "RWC"; break;
        case PAGE_EXECUTE:              s = "X";   break;
        case PAGE_EXECUTE_READ:         s = "RX";  break;
        case PAGE_EXECUTE_READWRITE:    s = "RWX"; break;
        case PAGE_EXECUTE_WRITECOPY:    s = "XWC"; break;
        default: {
            char b[16];
            std::snprintf(b, sizeof(b), "%08lX", (unsigned long)(p & 0xFF));
            s = b;
        }
    }
    if (p & PAGE_GUARD)         s += "+G";
    if (p & PAGE_NOCACHE)       s += "+NC";
    if (p & PAGE_WRITECOMBINE)  s += "+WC";
    return s;
}

static json h_region_list(const json& args) {
    DWORD pid = 0;
    std::string err;
    if (!resolve_target(args, pid, err)) return errj(err);
    HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!ph) {
        char e[200];
        std::snprintf(e, sizeof(e),
                      "OpenProcess failed (Win32 error %lu) -- protected process, exited, or not elevated?",
                      (unsigned long)GetLastError());
        return errj(e);
    }

    json arr = json::array();
    uint64_t addr = 0;
    const uint64_t kUserMax = 0x7FFFFFFEFFFFull;  // user-space ceiling, x64
    size_t total = 0, img = 0, priv = 0, mapped = 0;
    uint64_t commit_bytes = 0;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < kUserMax && total < 4096) {
        if (!VirtualQueryEx(ph, (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) break;
        const uint64_t rsize = (uint64_t)mbi.RegionSize;
        if (rsize == 0) break;
        if (mbi.State == MEM_COMMIT) {
            json row = json::object();
            row["base"] = hexs((uint64_t)(uintptr_t)mbi.BaseAddress);
            row["size"] = rsize;
            row["end"] = hexs((uint64_t)(uintptr_t)mbi.BaseAddress + rsize);
            row["protect"] = protect_str(mbi.Protect);
            const char* t = mbi.Type == MEM_IMAGE ? "image"
                          : mbi.Type == MEM_MAPPED ? "mapped" : "private";
            row["type"] = t;
            if (mbi.Type == MEM_IMAGE) ++img;
            else if (mbi.Type == MEM_MAPPED) ++mapped;
            else ++priv;
            commit_bytes += rsize;
            ++total;
            arr.push_back(row);
        }
        addr = (uint64_t)(uintptr_t)mbi.BaseAddress + rsize;
    }
    CloseHandle(ph);

    json r = json::object();
    r["ok"] = true;
    r["pid"] = pid;
    r["count"] = total;
    r["commit_bytes"] = commit_bytes;
    r["image"] = img;
    r["private"] = priv;
    r["mapped"] = mapped;
    r["truncated"] = total >= 4096;
    r["regions"] = arr;
    return r;
}

// ---- ping -------------------------------------------------------------------
static json h_ping(const json&) {
    std::string err;
    if (!ensure_driver(err)) return errj(err);
    json r = json::object();
    r["ok"] = true;
    r["driver"] = "resident (" + glassbox::DeviceName() + " open)";
    r["writes_enabled"] = g_allow_write;
    r["server"] = std::string(kServerName) + " " + kServerVersion;
    // smoke test: read our own MZ through the kernel path
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring fname = path;
    size_t slash = fname.find_last_of(L"\\/");
    if (slash != std::wstring::npos) fname = fname.substr(slash + 1);
    DWORD self = GetCurrentProcessId();
    uint64_t base = glassbox::GetModuleBase(self, fname);
    if (base) {
        r["self_pid"] = self;
        r["self_base"] = hexs(base);
        uint8_t mz[2] = {};
        if (glassbox::ReadProcessMemory(self, base, mz, 2)) {
            r["kernel_read_smoke"] = (mz[0] == 'M' && mz[1] == 'Z') ? "PASS (MZ)" : "FAIL (bad magic)";
            r["ok"] = mz[0] == 'M' && mz[1] == 'Z';
            if (r["ok"] == false) r["error"] = "device opened but kernel read returned wrong magic";
        } else {
            r["ok"] = false;
            r["error"] = "device opened but kernel READ failed";
        }
    } else {
        r["ok"] = false;
        r["error"] = "device opened but kernel MODBASE failed for our own image";
    }
    return r;
}

// ----------------------------------------------------------------------------
// Tool registry + schemas
// ----------------------------------------------------------------------------
struct ToolDef {
    const char* name;
    const char* description;
    json schema;
    bool gated;
    std::function<json(const json&)> handler;
};

static json P(const char* type, const char* desc) {
    json p = json::object();
    p["type"] = type;
    p["description"] = desc;
    return p;
}

static json schema2(std::map<std::string, json> props, std::vector<std::string> required) {
    json p = json::object();
    for (auto& kv : props) p[kv.first] = kv.second;
    json req = json::array();
    for (auto& s : required) req.push_back(s);
    json s = json::object();
    s["type"] = "object";
    s["properties"] = p;
    s["required"] = req;
    return s;
}

static json pid_prop() { return P("integer", "Target process id. Provide this OR process_name."); }
static json pname_prop() { return P("string", "Target process name (e.g. \"notepad.exe\"). Case-insensitive, unique substring match allowed. Provide this OR pid."); }

static std::vector<ToolDef>& tools() {
    static std::vector<ToolDef> t = [] {
        std::vector<ToolDef> v;
        v.push_back({ "process_list",
            "List running processes (pid, name, parent). Use filter to narrow, e.g. filter=\"notepad\".",
            schema2({ { "filter", P("string", "Optional case-insensitive substring filter on process name.") } }, {}),
            false, h_process_list });
        v.push_back({ "module_list",
            "List loaded modules of a process: base address, size, path.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() } }, {}),
            false, h_module_list });
        v.push_back({ "module_base",
            "Resolve a module's base address via the kernel driver (bypasses usermode hooks).",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "module_name", P("string", "Module file name, e.g. \"kernel32.dll\" or \"user32.dll\".") } },
                    { "module_name" }),
            false, h_module_base });
        v.push_back({ "read",
            "Read raw memory. Returns hex + base64. Cap 256 KiB/call; keep sizes small (<=4 KiB) to save context.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string like \"0x7FF6A5B00000\" or decimal number.") },
                      { "size", P("integer", "Byte count (default 64, max 262144).") } },
                    { "address" }),
            false, h_read });
        v.push_back({ "hexdump",
            "Read memory and format as a classic hexdump (offset | hex | ascii). Cap 16 KiB/call.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string or number.") },
                      { "size", P("integer", "Byte count (default 256, max 16384).") } },
                    { "address" }),
            false, h_hexdump });
        v.push_back({ "read_value",
            "Read a typed value: u8 u16 u32 u64 i8 i16 i32 i64 float double bool pointer.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string or number.") },
                      { "type", P("string", "Value type (default \"u32\").") } },
                    { "address" }),
            false, h_read_value });
        v.push_back({ "read_chain",
            "Walk a pointer chain: base+offsets[0] -> deref -> +offsets[1] -> deref -> ... -> read typed value. Returns every intermediate address.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "base", P("string", "Chain base, typically a module base or static address.") },
                      { "offsets", P("array", "Offsets between derefs, e.g. [16, 40, 8]. Last offset lands on the final value.") },
                      { "type", P("string", "Final value type (default \"u64\").") } },
                    { "base", "offsets" }),
            false, h_read_chain });
        v.push_back({ "read_string",
            "Read a null-terminated string (ascii or utf16). Stops at first NUL or max_len.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string or number.") },
                      { "max_len", P("integer", "Max chars (default 256, max 4096).") },
                      { "encoding", P("string", "\"ascii\" (default) or \"utf16\".") } },
                    { "address" }),
            false, h_read_string });
        v.push_back({ "scan",
            "Scan a VA range for an IDA-style pattern (\"48 8B 0D ?? ?? ?? ??\", ?? = wildcard). Returns first hit by default; all=all for every match (max_results cap, optional context bytes per hit).",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "start", P("string", "Start address, hex string or number.") },
                      { "size", P("integer", "Bytes to scan (max 1 GiB).") },
                      { "pattern", P("string", "IDA-style byte pattern with ?? wildcards.") },
                      { "all", P("boolean", "Return ALL matches (default false = first only).") },
                      { "max_results", P("integer", "Cap when all=true (default 64, max 4096).") },
                      { "context", P("integer", "Bytes of hex context around each hit, total 2x this (max 64).") } },
                    { "start", "size", "pattern" }),
            false, h_scan });
        v.push_back({ "scan_module",
            "Scan a module's PE sections (exec first, then data) for an IDA-style pattern. Returns first hit by default; all=true returns every match (max_results cap, optional context bytes per hit).",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "module", P("string", "Module name like \"kernel32.dll\" or its base address.") },
                      { "pattern", P("string", "IDA-style byte pattern with ?? wildcards.") },
                      { "all", P("boolean", "Return ALL matches (default false = first only).") },
                      { "max_results", P("integer", "Cap when all=true (default 64, max 4096).") },
                      { "context", P("integer", "Bytes of hex context around each hit, total 2x this (max 64).") } },
                    { "module", "pattern" }),
            false, h_scan_module });
        v.push_back({ "find_string",
            "Find a literal string in memory (ascii or utf16), ALL occurrences. Search a module or a start+size range. Great for locating class names, metadata, config text, and version strings.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "text", P("string", "Literal text to search for (1..1024 chars).") },
                      { "encoding", P("string", "\"ascii\" (default) or \"utf16\".") },
                      { "module", P("string", "Module name or base; omit to use start+size.") },
                      { "start", P("string", "Start address when no module given.") },
                      { "size", P("integer", "Bytes to search when no module given (max 1 GiB).") },
                      { "case_sensitive", P("boolean", "Default true (ascii only; utf16 is always exact).") },
                      { "max_results", P("integer", "Cap (default 64, max 1024).") },
                      { "context", P("integer", "Bytes of hex context around each hit (default 16, max 64).") } },
                    { "text" }),
            false, h_find_string });
        v.push_back({ "read_many",
            "Batch typed reads: up to 64 {address, type?} entries in one call. Per-entry ok/error. Ideal for isolating which candidate address holds a changing value.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "items", P("array", "Entries: {address, type?}. type falls back to the common `type` (default u32).") },
                      { "type", P("string", "Default type for entries without one.") } },
                    { "items" }),
            false, h_read_many });
        v.push_back({ "read_struct",
            "Read a struct layout in one shot: base + fields [{offset, type?, name?}]. Build field lists from the static (Ghidra) struct definition.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "base", P("string", "Struct base address.") },
                      { "fields", P("array", "Entries: {offset, type?, name?} (max 64). type default u32 or common `type`.") },
                      { "type", P("string", "Default type for fields without one.") } },
                    { "base", "fields" }),
            false, h_read_struct });
        v.push_back({ "watch",
            "Sample address(es) over time: N samples every M ms. Returns the series plus min/max/changed/distinct per address. The fast way to confirm which address holds a live value.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "items", P("array", "Entries: {address, type?} (max 16).") },
                      { "address", P("string", "Single-address sugar instead of items.") },
                      { "type", P("string", "Default type (u32).") },
                      { "samples", P("integer", "1..32 (default 5).") },
                      { "interval_ms", P("integer", "1..500 (default 100); total window <= 8 s.") } },
                    {}),
            false, h_watch });
        v.push_back({ "region_list",
            "List committed memory regions of a process (VirtualQueryEx, usermode): base/size/protect/type (image|private|mapped). Use to find heap/private ranges to scan beyond module bounds.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() } }, {}),
            false, h_region_list });
        v.push_back({ "alloc",
            "[WRITE] Allocate memory in the target process (MEM_COMMIT|MEM_RESERVE). Gated: requires GLASSBOX_ALLOW_WRITE=1 and confirm=true.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "size", P("integer", "Allocation size in bytes.") },
                      { "protect", P("string", "\"rw\" (default), \"rx\", \"rwx\", \"r\".") },
                      { "confirm", P("boolean", "Must be true to execute a write operation.") } },
                    { "size", "confirm" }),
            true, h_alloc });
        v.push_back({ "protect",
            "[WRITE] Change memory protection in the target (VirtualProtect via driver). Gated: requires GLASSBOX_ALLOW_WRITE=1 and confirm=true.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string or number.") },
                      { "size", P("integer", "Region size in bytes.") },
                      { "protect", P("string", "\"r\", \"rw\", \"rx\", \"rwx\".") },
                      { "confirm", P("boolean", "Must be true to execute a write operation.") } },
                    { "address", "size", "protect", "confirm" }),
            true, h_protect });
        v.push_back({ "write_bytes",
            "[WRITE] Write raw bytes (hex string) to the target, then verify by read-back. Gated: requires GLASSBOX_ALLOW_WRITE=1 and confirm=true.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string or number.") },
                      { "hex", P("string", "Hex payload, e.g. \"DE AD BE EF\" or \"DEADBEEF\".") },
                      { "confirm", P("boolean", "Must be true to execute a write operation.") } },
                    { "address", "hex", "confirm" }),
            true, h_write_bytes });
        v.push_back({ "write_value",
            "[WRITE] Write a typed value, then verify by read-back. Gated: requires GLASSBOX_ALLOW_WRITE=1 and confirm=true.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string or number.") },
                      { "type", P("string", "u8 u16 u32 u64 i8 i16 i32 i64 float double bool pointer.") },
                      { "value", P("string", "Value (numbers; 64-bit may be hex strings).") },
                      { "confirm", P("boolean", "Must be true to execute a write operation.") } },
                    { "address", "type", "value", "confirm" }),
            true, h_write_value });
        v.push_back({ "write_string",
            "[WRITE] Write a string (ascii or utf16), NUL optional. Gated: requires GLASSBOX_ALLOW_WRITE=1 and confirm=true.",
            schema2({ { "pid", pid_prop() }, { "process_name", pname_prop() },
                      { "address", P("string", "Address, hex string or number.") },
                      { "text", P("string", "Text to write.") },
                      { "encoding", P("string", "\"ascii\" (default) or \"utf16\".") },
                      { "include_null", P("boolean", "Write terminating NUL (default true).") },
                      { "confirm", P("boolean", "Must be true to execute a write operation.") } },
                    { "address", "text", "confirm" }),
            true, h_write_string });
        v.push_back({ "ping",
            "Check the driver: is \\\\.\\GlassBox resident and readable? Does a kernel-mode read of our own MZ header work? Run this first.",
            schema2({}, {}),
            false, h_ping });
        return v;
    }();
    return t;
}

// ----------------------------------------------------------------------------
// MCP protocol handling
// ----------------------------------------------------------------------------
static void respond(const json& id, json result) {
    json m = json::object();
    m["jsonrpc"] = "2.0";
    m["id"] = id;
    m["result"] = result;
    send_msg(m);
}

static void respond_error(const json& id, int code, const std::string& msg) {
    json m = json::object();
    m["jsonrpc"] = "2.0";
    m["id"] = id;
    json e = json::object();
    e["code"] = code;
    e["message"] = msg;
    m["error"] = e;
    send_msg(m);
}

static void respond_text_result(const json& id, const json& payload, bool is_error) {
    json result = json::object();
    json content = json::array();
    json item = json::object();
    item["type"] = "text";
    item["text"] = payload.dump(-1, ' ', false, json::error_handler_t::replace);
    content.push_back(item);
    result["content"] = content;
    result["isError"] = is_error;
    respond(id, result);
}

static void handle_message(const json& req) {
    if (!req.is_object() || !req.contains("method")) {
        respond_error(nullptr, -32600, "invalid request");
        return;
    }
    const bool has_id = req.contains("id") && !req.at("id").is_null();
    const json id = has_id ? req.at("id") : json();
    const std::string method = req.at("method").get<std::string>();

    if (method == "initialize") {
        std::string pv = kDefaultProto;
        if (req.contains("params") && req.at("params").is_object()) {
            const json& p = req.at("params");
            if (p.contains("protocolVersion") && p.at("protocolVersion").is_string())
                pv = p.at("protocolVersion").get<std::string>();
        }
        json result = json::object();
        result["protocolVersion"] = pv;
        json caps = json::object();
        caps["tools"] = json::object();   // no listChanged
        result["capabilities"] = caps;
        json info = json::object();
        info["name"] = kServerName;
        info["version"] = kServerVersion;
        result["serverInfo"] = info;
        respond(id, result);
        return;
    }
    if (method.rfind("notifications/", 0) == 0) return;  // no response to notifications
    if (method == "ping") { respond(id, json::object()); return; }

    if (method == "tools/list") {
        json arr = json::array();
        for (auto& t : tools()) {
            json o = json::object();
            o["name"] = t.name;
            o["description"] = t.description;
            o["inputSchema"] = t.schema;
            arr.push_back(o);
        }
        json result = json::object();
        result["tools"] = arr;
        respond(id, result);
        return;
    }
    if (method == "tools/call") {
        if (!req.contains("params") || !req.at("params").is_object()) {
            respond_text_result(id, errj("missing params"), true);
            return;
        }
        const json& params = req.at("params");
        std::string name = params.contains("name") && params.at("name").is_string()
            ? params.at("name").get<std::string>() : "";
        const ToolDef* td = nullptr;
        for (auto& t : tools()) if (name == t.name) { td = &t; break; }
        if (!td) {
            respond_text_result(id, errj("unknown tool \"" + name + "\" (call tools/list)"), true);
            return;
        }
        json args = json::object();
        if (params.contains("arguments") && params.at("arguments").is_object())
            args = params.at("arguments");

        if (td->gated) {
            std::string err;
            if (!write_gate(args, err)) { respond_text_result(id, errj(err), true); return; }
        }
        slog("[mcp] tools/call %s", name.c_str());
        json payload;
        try {
            payload = td->handler(args);
        } catch (const std::exception& e) {
            payload = errj(std::string("tool exception: ") + e.what());
        } catch (...) {
            payload = errj("unknown tool exception");
        }
        bool is_err = payload.contains("ok") && payload.at("ok") == false;
        respond_text_result(id, payload, is_err);
        return;
    }

    if (has_id) respond_error(id, -32601, "method not found: " + method);
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
int main() {
    // stdio is a binary protocol channel: no CRLF translation anywhere.
    _setmode(_fileno(stdin),  _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);

    char* w = std::getenv("GLASSBOX_ALLOW_WRITE");
    g_allow_write = (w && std::strcmp(w, "1") == 0);
    slog("[mcp] %s %s starting (writes %s)",
         kServerName, kServerVersion, g_allow_write ? "ENABLED" : "disabled");

    // Protocol loop: one JSON-RPC message per line.
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        json req = json::parse(line, nullptr, false);
        if (req.is_discarded()) {
            respond_error(nullptr, -32700, "parse error");
            continue;
        }
        handle_message(req);
    }

    glassbox::Close();
    slog("[mcp] stdin closed, exiting");
    return 0;
}
