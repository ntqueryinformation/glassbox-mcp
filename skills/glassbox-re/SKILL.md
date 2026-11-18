---
name: Senior RE — GlassBox Dynamic + Ghidra Static
description: Expert reverse-engineering loop combining the glassbox MCP (live kernel-backed memory reads of any running process) with static analysis via Ghidra headless or any decompiler MCP. Use when asked to analyze, reverse, read memory of, or dump a running process/module, bridge static addresses to live ones, or find where data lives in a target.
---

# Dynamic + Static RE with GlassBox + Ghidra

You are the expert in the seat. The loop: **static gives structure, dynamic gives state.**

## Hard rules

1. The glassbox MCP never loads a driver. It expects your kernel driver's device (`\\.\GlassBox` by default, or `GLASSBOX_DEVICE`) to already be resident. Never look for, suggest, or attempt a loading path — the project ships none by design. If the device is missing, tell the user to load their driver per the project README. A reboot unloads it.
2. All of OpenCode (its background service) must run **elevated** or kernel tools fail. Win32 error **2** = device not found, **5** = not elevated.
3. Read-only by default. Write tools (`alloc`, `protect`, `write_*`) require `GLASSBOX_ALLOW_WRITE=1` AND `confirm: true` per call — never fabricate confirm for the user.
4. Context hygiene: hexdumps ≤ 2 KiB/call, strings ≤ 256, reads ≤ 64 KiB. The caps exist so the conversation survives the session.

## The four-phase loop

### Phase 1 — Recon (dynamic)
```
tools.glassbox.ping()                                  → PASS (MZ) = go
tools.glassbox.process_list({filter})                  → pid
tools.glassbox.module_list({pid})                      → bases, sizes, paths
tools.glassbox.hexdump({pid, address: base, size:64})  → MZ sanity check
```

### Phase 2 — Static (Ghidra headless, or any decompiler MCP you have)
Analyze the on-disk module (clean PE) or a memory dump (loop `tools.glassbox.read` in 256 KiB chunks over `base..base+size`, write to disk).
⚠ Memory dumps have **virtual** section layout — import as raw binary with the runtime base, not as PE.
Use your static toolchain (Ghidra headless, or a decompiler MCP — discover its tools with `search()`, don't guess names) for decompilation, xrefs, strings, structures.

### Phase 3 — Bridge static → live
```
live_VA = runtime_module_base + static_offset
```
Never trust arithmetic alone: take 8–16 instruction bytes from the decompiler, wildcard relative-operand bytes as `??`, and `tools.glassbox.scan_module({module, pattern})` — the hit must equal `base + offset`.

### Phase 4 — Read state (dynamic)
- Struct fields: `tools.glassbox.read_struct({base, fields})` or `tools.glassbox.read_chain({base, offsets, type})` (offsets from the static struct layout)
- Isolate changing values: `tools.glassbox.watch({items, samples, interval_ms})` — one call replaces N `read_value` round trips; `changed`/`distinct` flag the live ones
- Batch candidate checks: `tools.glassbox.read_many({items})`
- vtables: `read_value` pointer → `read_chain` slots → bridge back to decompiled functions
- Strings/metadata: `tools.glassbox.find_string({module, text, encoding})` — all occurrences; many managed runtimes keep an i32 length header just before the string pointer (e.g. at `ptr-0x8`) — verify before relying on it
- Heap scanning beyond modules: `tools.glassbox.region_list` → pick `private` ranges → `scan` with `all: true`

## Full tool reference

Read `references/tool-reference.md` for all 21 tools, arguments, caps, and return shapes — do not guess argument names.

## Static-side notes

Read `references/static-side.md` for choosing/dumping the analysis binary and the bridge-verification loop.

## Workflow discipline

- Start every session with `ping`. Re-check after the driver re-loads.
- Name modules exactly (their real file names, e.g. `kernel32.dll`); `scan_module` takes a name or a base.
- Prefer `read_chain` over nested reads — it returns every intermediate address and names the broken link.
- When an address errors, suspect: stale offset (re-scan), freed memory (re-check module_list), wrong pid (re-list).
- Report findings as static-offset + runtime-base pairs so the user can reproduce after restarts.
