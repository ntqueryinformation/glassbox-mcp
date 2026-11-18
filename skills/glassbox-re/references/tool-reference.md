# GlassBox MCP — Full Tool Reference (21 tools, v1.2.0)

Universal conventions:

- Target: every tool takes `pid` (integer) OR `process_name` (case-insensitive substring, must be unique).
- Addresses: hex strings (`"0x7FF604270000"`) or numbers in; 64-bit results OUT as hex strings (JSON precision).
- Address validation: every address (and address+size range, incl. write length and pointer-chain steps) must land in user space (`0x10000`..`0x7FFFFFFFEFFFF`). Out-of-range or wrapping values are rejected client-side with a clean `{ok:false}` — they never reach the driver, because kernel-canonical garbage derefs bugcheck typical drivers.
- Errors: `{ok: false, error: "guidance"}` + MCP `isError: true`. Nothing throws.
- Caps: read 256 KiB · hexdump 16 KiB · string 4096 chars · scan 1 GiB · chain depth 16 · write payload 64 KiB · batch items 64 · watch 16 items / 32 samples / 8 s window.

## Status

| Tool | Arguments | Returns |
|---|---|---|
| `ping` | — | `driver`, `kernel_read_smoke: "PASS (MZ)"`, `self_pid`, `self_base`, `writes_enabled` |

## Enumeration

| Tool | Arguments | Returns |
|---|---|---|
| `process_list` | `filter?` | `processes: [{pid, name, parent_pid}]` (≤512 rows) — usermode |
| `module_list` | `pid`/`process_name` | `modules: [{name, base, size, end, path}]` (≤1024) — Toolhelp; fails on protected processes |
| `region_list` | `pid`/`process_name` | `regions: [{base, size, end, protect, type}]` (≤4096), counts, `commit_bytes` — VirtualQueryEx; type = image\|private\|mapped. Use for heap/private scan ranges |

## Kernel-backed reads

| Tool | Arguments | Returns / notes |
|---|---|---|
| `module_base` | `pid`/`process_name`, `module_name` (exact) | `base` (+ best-effort `size`, `end`) via kernel IOCTL |
| `read` | target, `address`, `size?` (default 64, ≤256 KiB) | `hex` + `base64`; >4 KiB adds a context warning |
| `hexdump` | target, `address`, `size?` (default 256, ≤16 KiB) | `dump` — `address  hex \|ascii\|` rows |
| `read_value` | target, `address`, `type?` (default `u32`) | types: `u8 u16 u32 u64 i8 i16 i32 i64 float double bool pointer`; 64-bit → `{hex, dec}` |
| `read_chain` | target, `base`, `offsets` (int[], ≤16, negatives ok), `type?` (default `u64`) | `deref_chain[]`, `final_address`, `value`; single offset = plain field read, no deref |
| `read_string` | target, `address`, `max_len?` (≤4096), `encoding?` (`ascii`\|`utf16`) | `text` (sanitized, UTF-16 → UTF-8) |
| `read_many` | target, `items` `[{address, type?}]` (≤64), `type?` default | per-entry `ok`/`value`/`error`, `ok_count`, `error_count` |
| `read_struct` | target, `base`, `fields` `[{offset, type?, name?}]` (≤64), `type?` default | per-field `value` at `base+offset`, names echoed |

Pattern syntax: IDA-style, `"48 8B 0D ?? ?? ?? ??"` (`?`/`??` = wildcard byte).

## Scanning

| Tool | Arguments | Returns |
|---|---|---|
| `scan` | target, `start`, `size` (≤1 GiB), `pattern`, `all?`, `max_results?` (≤4096), `context?` (≤64) | `found`, `count`, first `address`/`offset`; when `all` or `context`: `hits: [{address, offset, context_hex?}]` |
| `scan_module` | target, `module` (name or base), `pattern`, same `all`/`max_results`/`context` | same shape, plus `module_offset` per hit |
| `find_string` | target, `text` (≤1024), `encoding?`, `module?` xor `start`+`size`, `case_sensitive?`, `max_results?` (≤1024), `context?` (default 16) | `hits: [{address, offset, context_hex}]` — ALL occurrences; utf16 exact-match |

`all` defaults false everywhere (backward compat): first hit only. Pass `all: true` when you need every reference — for xref mapping, structure arrays, or metadata sweeps.

## Time sampling

| Tool | Arguments | Returns |
|---|---|---|
| `watch` | target, `items` `[{address, type?}]` (≤16) or single `address` + `type`; `samples?` (≤32, default 5), `interval_ms?` (≤500, default 100; window ≤8 s) | per address: `samples[]`, `changed`, `distinct`, `min`/`max` (numeric types), `read_errors` |

## Writes — require `GLASSBOX_ALLOW_WRITE=1` env AND `confirm: true`; all verify by read-back

| Tool | Arguments | Returns |
|---|---|---|
| `alloc` | target, `size` (≤256 MiB), `protect?` (`r`,`rw`* ,`rx`,`rwx`), `confirm` | new `address` |
| `protect` | target, `address`, `size`, `protect`, `confirm` | ok |
| `write_bytes` | target, `address`, `hex` (`"DE AD BE EF"`), `confirm` | `verified`, `readback_hex` |
| `write_value` | target, `address`, `type`, `value`, `confirm` | `readback` |
| `write_string` | target, `address`, `text`, `encoding?`, `include_null?` (default true), `confirm` | `written` |

## Error decode

| Message | Meaning → action |
|---|---|
| `cannot open device \\.\X` + Win32 err 2 | device not found — driver not loaded (a reboot unloads it) or wrong name → set `GLASSBOX_DEVICE` to match |
| same + Win32 err 5 | device exists, token not admin → restart OpenCode elevated (`opencode service restart` from admin terminal) |
| `address 0x... is outside user space - rejected` | validation gate: kernel-canonical/garbage address — a stale deref or misparsed value; do NOT retry it, go back one step and re-derive the address |
| `range 0x... + N bytes leaves user space` | start was fine but the read/write/scan runs past the user-space ceiling — shrink the size |
| `chain stopped at step N: deref @ ... outside user space` | the chain dereferenced into garbage — stop following it; re-validate the previous link instead of pushing on |
| `READ ioctl failed @ 0x...` | unreadable/freed address, wrong pid, or protected process |
| `chain broken at step N` | pointer dead at that link — back up one step, re-validate |
| `writes are disabled` | env var missing on the server — user must set it in config |
| `multiple processes match` | ambiguous substring — pass exact `pid` |
| `OpenProcess failed` (region_list) | protected process or not elevated |
