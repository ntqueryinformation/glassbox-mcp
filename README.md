# glassbox-mcp

A **Model Context Protocol (MCP) server** that gives LLM agents **kernel-level
process memory access** on Windows. Wire it into OpenCode, Claude Desktop, or
any MCP client and the agent can enumerate, read, scan, watch, and (opt-in)
write the memory of any running process — through your own kernel driver,
without ever touching the Win32 process-memory APIs.

```
┌──────────┐  MCP stdio (JSON-RPC)  ┌────────────────┐  IOCTL  ┌──────────────────┐
│  LLM     │ <--------------------> │  glassbox-mcp  │ ------> │  YOUR driver     │
│  agent   │                        │  (this exe)    │         │  (already loaded)│
└──────────┘                        └────────────────┘         └──────────────────┘
```

## Why kernel-backed?

Every classic memory tool bottoms out in the same two calls: `OpenProcess` +
`ReadProcessMemory`/`WriteProcessMemory`. Those calls live in usermode, which
means they can be **hooked, restricted, or stripped** long before they reach
the kernel — missing handles, narrowed access rights, and API-level
interception all degrade or break them.

glassbox-mcp takes a different path: the agent's requests become raw
`DeviceIoControl` calls to **a kernel driver that you supply**, and the driver
performs the access from kernel space. What that buys you in practice:

| Capability | Usermode API path | Kernel-backed path (this project) |
|---|---|---|
| Read/write any committed page of any process | Can fail when the handle is stripped or rights are narrowed | One uniform contract, same result for every process the driver can see |
| Resolve a module's base address | `Toolhelp`/`PSAPI` snapshots, hookable and incomplete | Single `MODBASE` IOCTL, resolved in kernel |
| Whole-process reach | Often limited to the opening process's view | Scan any VA range, including private/heap regions beyond module bounds |
| One consistent tool surface per target | Behavior varies with API availability | The agent uses the same 21 tools against any target |

Combined with the MCP layer, the agent gets tooling usermode scripts never
had: **LLM-shaped output** (hex + base64, hexdumps, typed values, hex-string
addresses that survive JSON's 53-bit integer limit), **context-window caps**
on every response, **batched reads**, **pointer-chain walks with every
intermediate address reported**, **in-band errors that never crash the
server**, and a **time-sampling tool** that replaces dozens of round trips.

> **This repository ships NO kernel driver.** There is no `.sys` binary here,
> no driver-loading code, no mapper, no loader — the server is a pure client.
> You plug in **your own** driver (see
> [Driver contract](#you-supply-the-driver)) and glassbox-mcp talks to it.

## You supply the driver

**No driver is included with this project, and none will be.** glassbox-mcp is
the usermode client half: it opens your driver's device with `CreateFile` and
speaks raw IOCTLs to it. Nothing more.

To use it you need a driver that:

1. Is already **loaded and running** on the machine when the server starts
   (glassbox-mcp contains no loading logic whatsoever).
2. Exposes a device whose name matches the server's expectation —
   `\\.\GlassBox` by default, or **any name you choose** via the
   `GLASSBOX_DEVICE` environment variable. No rebuild needed.
3. Implements the five IOCTLs and struct layouts documented in
   **[docs/DRIVER-CONTRACT.md](docs/DRIVER-CONTRACT.md)**, byte-for-byte.

If you can already read a process's memory through your driver, making it
glassbox-compatible is usually a matter of matching the five CTL codes and
four request structs — every one is spelled out in the contract document.

**You are responsible for your driver.** Use this project only on systems you
own or have explicit authorization to analyze.

## Prerequisites

- Windows 10/11 x64
- **Your own kernel driver**, loaded and serving the device (see above)
- The MCP host terminal running **elevated** (admin) — the device ACL
  typically requires it
- VS2022 (v143 toolset) + Windows SDK to build

## Build

Open `glassbox-mcp.sln` → `Release | x64` → build. Output:
`bin\Release\glassbox-mcp.exe`. No runtime dependencies (nlohmann/json is
vendored in `third_party/`, static CRT).

Or from a VS dev shell:

```sh
msbuild glassbox-mcp.sln /p:Configuration=Release /p:Platform=x64 /m
```

## Configuration

Two environment variables control everything:

| Variable | Default | Effect |
|---|---|---|
| `GLASSBOX_DEVICE` | `\\.\GlassBox` | Device path of your driver. Point it at any device name — no rebuild. |
| `GLASSBOX_ALLOW_WRITE` | *(unset)* | Set to `1` to arm the write tools. Without it the server is **read-only**. |

### OpenCode

Add to `opencode.json` (project or global `~/.config/opencode/`):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "glassbox": {
        "type": "local",
        "command": ["C:\\path\\to\\glassbox-mcp\\bin\\Release\\glassbox-mcp.exe"],
        "environment": {
          "GLASSBOX_DEVICE": "\\\\.\\YourDriver",
          "GLASSBOX_ALLOW_WRITE": "1"
        }
      }
    }
  }
}
```

- Tools appear as `glassbox_read`, `glassbox_scan_module`, ... (Code Mode:
  `tools.glassbox.read(...)`).
- Remove the `environment` block (or set it to `{}`) to run **read-only**.
- OpenCode reloads config on save — verify with `opencode mcp list`.

### Any other MCP client

The server is a plain stdio JSON-RPC MCP server, so any client that launches
stdio servers works. Example for `mcpServers`-style configs:

```jsonc
{
  "mcpServers": {
    "glassbox": {
      "command": "C:\\path\\to\\glassbox-mcp\\bin\\Release\\glassbox-mcp.exe",
      "env": { "GLASSBOX_ALLOW_WRITE": "1" }
    }
  }
}
```

See [examples/](examples/) for raw request/response transcripts of a session.

## Safety model

Writes are dangerous, so they are locked behind **two independent gates**:
the `GLASSBOX_ALLOW_WRITE=1` environment variable on the server process **and**
`"confirm": true` in each individual tool call. Reads never need arming.

| Layer | Mechanism |
|---|---|
| Read tools (read / hexdump / scan / enum / watch / find_string) | ungated — passive analysis |
| Write tools (`alloc`, `protect`, `write_*`) | require `GLASSBOX_ALLOW_WRITE=1` env **AND** `"confirm": true` per call; every write verifies by read-back |
| Address validation | every address, range, pointer-chain step, and dereferenced value is checked against user space (`0x10000`..`0x7FFFFFFFEFFFF`) **before** any IOCTL — kernel-canonical garbage that would crash a KernelMode-copy driver is rejected cleanly instead |
| Context safety | read cap 256 KiB/call, hexdump cap 16 KiB, string cap 4 KiB, scan cap 1 GiB, chain depth 16, batch/watch item caps |
| Failure mode | every tool returns `{ok, error}` JSON in-band — never crashes, never loads anything, missing-driver is a clean message with the Win32 error code |

## Tool reference

Universal conventions:

- Every tool takes **`pid` or `process_name`** (case-insensitive, unique
  substring match).
- Addresses accept hex strings (`"0x7FF6A5B00000"`) or numbers; 64-bit results
  come back as hex strings to survive JSON precision.
- Errors: `{ok: false, error: "guidance"}` + MCP `isError: true`. Nothing throws.

### Status

| Tool | What it does |
|---|---|
| `ping` | Device reachable? Performs a kernel-mode read smoke test (reads the server's own MZ header). **Call this first.** |

### Enumeration

| Tool | What it does |
|---|---|
| `process_list` | Processes (pid/name/parent), optional substring filter |
| `module_list` | Loaded modules: base, size, path (usermode Toolhelp) |
| `region_list` | Committed memory regions with protect/type (image/private/mapped) — use to find heap ranges to scan |
| `module_base` | Kernel-resolved module base (single IOCTL, no snapshot) |

### Kernel-backed reads

| Tool | What it does |
|---|---|
| `read` | Raw bytes → hex + base64 (cap 256 KiB) |
| `hexdump` | Classic `addr  hex  \|ascii\|` dump (cap 16 KiB) |
| `read_value` | Typed read: u8..u64, i8..i64, float, double, bool, pointer |
| `read_chain` | Pointer-chain walk; returns every intermediate address and names the broken link |
| `read_string` | NUL-terminated ascii or utf16 string |
| `read_many` | Batch up to 64 typed reads in one call, per-entry ok/error |
| `read_struct` | Read a struct layout in one shot: base + `{offset, type, name}` fields |

### Scanning & strings

| Tool | What it does |
|---|---|
| `scan` | IDA-pattern AOB scan over a VA range (`48 8B 0D ?? ?? ?? ??`), first-hit or all-matches with hex context |
| `scan_module` | AOB scan across a module's PE sections (headers → exec → data) |
| `find_string` | Find ALL occurrences of a literal string (ascii/utf16), in a module or a range, with context bytes |

### Time sampling

| Tool | What it does |
|---|---|
| `watch` | Sample address(es) N times at M ms intervals; per-address series, min/max, `changed`/`distinct` flags — one call replaces dozens of round trips |

### Writes — gated, verify by read-back

| Tool | What it does |
|---|---|
| `alloc` | *[WRITE]* `MEM_COMMIT\|MEM_RESERVE` in the target, protection `"r"/"rw"/"rx"/"rwx"` |
| `protect` | *[WRITE]* Change memory protection in the target |
| `write_bytes` | *[WRITE]* Hex payload + read-back verification |
| `write_value` | *[WRITE]* Typed value + read-back verification |
| `write_string` | *[WRITE]* ascii/utf16 string, NUL optional |

## Typical session

```
glassbox_ping                          → driver reachable? kernel read works?
glassbox_process_list {filter:"note"}  → pid
glassbox_module_list  {pid}            → module bases and sizes
glassbox_hexdump      {pid, address:"<base>", size:64}   → MZ sanity check
glassbox_scan_module  {pid, module:"target.dll", pattern:"48 8B 0D ?? ?? ?? ??"} → locate code
glassbox_read_chain   {pid, base:"<base>", offsets:[16, 40, 8], type:"float"} → walk to data
glassbox_watch        {pid, address:"<addr>", samples:10, interval_ms:100} → is it live?
```

A full raw transcript lives in [examples/](examples/).

## The companion skill

[`skills/glassbox-re/`](skills/glassbox-re/) ships an OpenCode skill that
teaches an agent the full dynamic + static analysis loop with these tools:
recon → static structure (Ghidra) → bridging static offsets to live addresses
→ reading live state.

Install: copy the folder to `~/.config/opencode/skills/glassbox-re/` (global)
or `<project>/.opencode/skills/glassbox-re/` (project-local), then reload.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cannot open device \\.\GlassBox` + Win32 error 2 | Device not found — your driver isn't loaded, or its device name differs. Set `GLASSBOX_DEVICE` to match. A reboot also unloads manually-loaded drivers. |
| Same error + Win32 error 5 | Device exists but access is denied — the host terminal isn't elevated. Restart the agent host from an admin shell. |
| `address 0x... is outside user space - rejected` | The validation gate caught a kernel-canonical/garbage address (usually a stale pointer or misparsed value). Don't retry it — re-derive the address one step earlier. |
| `chain stopped at step N: deref @ ... outside user space` | The pointer chain dereferenced into garbage. Stop following that chain; re-validate the last good link. |
| `READ ioctl failed @ 0x...` | Unreadable/freed address, or wrong pid. |
| `writes are disabled` | Set `GLASSBOX_ALLOW_WRITE=1` in the server env and reconnect. |
| `Toolhelp module snapshot failed` | Protected/short-lived process — use `module_base` (kernel path) instead. |
| `multiple processes match` | Ambiguous `process_name` substring — pass the exact `pid`. |

## Repository layout

| Path | Role |
|---|---|
| `mcp_stdio.cpp` | MCP server: JSON-RPC loop, tool dispatch, schemas. Read this first. |
| `glassbox_client.h/.cpp` | IOCTL wrappers (`GLASSBOX_DEVICE` resolution lives here) |
| `ioctl_defs.h` | The IOCTL contract — your driver must match byte-for-byte |
| `docs/DRIVER-CONTRACT.md` | Full driver-side reference: device, CTL codes, structs, semantics |
| `skills/glassbox-re/` | Agent skill: the dynamic + static analysis loop |
| `examples/` | Raw JSON-RPC session transcripts |
| `third_party/nlohmann/json.hpp` | v3.11.3, vendored single header |

## License

[MIT](LICENSE) — use it, fork it, ship it. You supply the driver; you own the
responsibility for how you use both.
