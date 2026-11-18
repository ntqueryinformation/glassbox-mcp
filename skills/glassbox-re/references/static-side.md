# Static side — Ghidra (or any decompiler MCP) notes

Use Ghidra headless directly, or any static-analysis/decompiler MCP you have
configured — discover its tools with Code Mode `search()` first; do not guess
tool names.

## Choosing the analysis binary

| Source | When | Gotcha |
|---|---|---|
| On-disk PE (next to the target exe) | Default. Clean headers, exports, Ghidra imports natively | File section layout ≠ memory layout; disk offsets ≠ virtual offsets |
| Memory dump (via glassbox `read` loop) | Packed/decrypted images, or when disk differs from memory | Sections laid out at **VirtualAddress**, not `PointerToRawData`. Import as **raw binary** and set the base, or fix section offsets first |

## Dumping a module from memory (glassbox side)

1. `tools.glassbox.module_base` (or `module_list`) → `base`, `size`.
2. Loop `tools.glassbox.read({pid, address: base + n * 0x40000, size: 0x40000})` until `size` is covered (0x40000 = 256 KiB cap per call). Decode the `base64` field (hex works too but is 2× larger).
3. Concatenate in order → `ModuleName.bin`. Track the runtime base — the dump starts at it.
4. Unreadable chunks (guard pages, unmapped gaps) fail with `READ ioctl failed` — record the gap offset, continue; tell Ghidra later.

## Ghidra headless import choices

- On-disk PE → import as PE (language x86:LE:64:default, image base from `ImageBase` header field).
- Memory dump → import as **Raw Binary**, language x86:LE:64, base address = **runtime module base** (then live addresses match Ghidra addresses 1:1, no rebase math needed).
- After analysis: export function list, structs, strings; decompile targets found via phase-3 signature bridging.

## Managed runtimes

- Compiled managed binaries are often stripped of source-level names. Pair the dump with a runtime metadata dumper run offline against the on-disk binary, then script the resulting address map into Ghidra to name functions before decompiling.
- Interpreted/JIT runtimes: assembly/class/method names are plainly in memory (ascii or utf16). `find_string` for literal type/method names from the target's own files, then `read_string` around hits.
- Runtime version strings usually sit near the start of the main runtime module's `.rdata` — `scan_module` for version-shaped literals, `read_string` the hit.

## Bridge verification loop (per finding)

1. Pick 8–16 instruction bytes at the static target (bytes view, not disassembly text).
2. Wildcard relative operands: displacement/immediate bytes that encode addresses → `??`.
3. `tools.glassbox.scan_module({module, pattern})` → hit must equal `base + static_offset`.
4. If it differs: stale offset, patched binary, or the bytes were not unique — lengthen the pattern around non-relative instructions.
