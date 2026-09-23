> **FROZEN 2026-09-24** — this crate now lives in the conch monorepo
> (`shared/mosh_client` — underscores since the 2026-09-24 rename, full history preserved via git subtree). This
> standalone repo is archived; no further work happens here.

# mosh-client

A from-scratch, embeddable Rust client for the
[mosh](https://mosh.org/) mobile-shell protocol — UDP + AES-128-OCB3 +
the SSP state-sync protocol — verified against stock mosh-server 1.4.0.

This is the protocol engine of a mosh client, not upstream's whole
`mosh-client` binary: no C++ bindings, no terminal emulator inside —
the crate speaks the wire protocol and drives **your** display. Born
inside [at-least/conch](https://github.com/at-least/conch); maintained
here as a standalone library.

## Layer map

| module | role |
|---|---|
| `crypto` | AES-128-OCB3 datagram seal/open, key codec, direction-bit nonces, replay gates |
| `wire` | proto2-subset codec for mosh's three schemas (total on hostile bytes) |
| `fragment` | fragment framing + zlib over the transport diff |
| `ssp` | the state-synchronization engine (sender timers, receiver idempotency) |
| `bootstrap` | `mosh-server new` command builder + `MOSH CONNECT` parser |
| `session` | the UDP session: sockets, timers, roaming, shutdown, driving your display |

## Embedding

```rust
use mosh_client::{Base64Key, MoshSession, MoshDisplay};

// 1. dial SSH yourself, exec `mosh-server new` (see bootstrap), parse
//    the `MOSH CONNECT <port> <key>` line.
// 2. build the session over your display (anything implementing
//    MoshDisplay — feed/resize/cols/rows/cursor):
let session = MoshSession::<MyDisplay>::connect_deferred(
    display, &target_addr, &key, |event| { /* ScreenChanged / Ended */ },
    cols, rows, /* prediction: */ true,
)?;
// 3. start the loop from a plain synchronous context.
session.start();
```

Conservative local echo (predicted keystrokes, retired by the server's
echo-ack) is built in and on by default; toggle with
`set_prediction(false)`.

## Memory profile

Two buffers grow with the session, and the embedder decides what to do
about each:

- the **host-byte capture** behind `take_host_bytes()` — unbounded by
  design so a linear consumer stays correct; drain it regularly, or
  turn it off with `set_host_bytes_capture(false)` if you render
  through the display alone;
- the **synchronized host log** itself, an append-only event log with
  structural sharing: a session keeps one copy of all its host traffic
  resident (per-state snapshots are O(1) clones), which is the price of
  cheap branch rebuilds.

## Server requirements

`mosh-server` 1.3.2 or newer (the byte-stream model and the three proto
schemas are unchanged since then; the client checks `protocol_version`
= 2 and is tested against 1.4.0), UDP ports 60000–61000 reachable.

## Oracles

- draft-krovetz-ocb-03 Appendix-A vectors (the same set mosh's own
  suite runs)
- a committed golden transcript of a real stock 1.4.0 session
  (`tests/fixtures/mosh/`)
- live interop against `mosh-server` 1.4 in conch's docker matrix

## License

GPL-3.0-or-later (derives from the mosh protocol references; see
SPEC.md for the source-of-truth annotations).
