# Examples

Raw transcripts of a glassbox-mcp session over stdio. One JSON-RPC 2.0 message
per line — this is exactly what crosses the wire between an MCP client and
this server.

- [`01-initialize-and-ping.jsonl`](01-initialize-and-ping.jsonl) — handshake,
  then `ping` against a live driver (device `\\.\GlassBox` in this example).
- [`02-recon-and-read.jsonl`](02-recon-and-read.jsonl) — find a target
  process, list its modules, hexdump a module header, walk a pointer chain.

Addresses are from a real session with a 64-bit test target; expect different
values on your machine (ASLR). All calls are read-only — no
`GLASSBOX_ALLOW_WRITE` involved.
