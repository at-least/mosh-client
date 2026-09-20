# Fuzzing

Targets the **decrypted plaintext** layer: the OCB3 tag stops
arbitrary ciphertext bytes cold, so the hostile surface starts at the
fragment/instruction layer (SPEC §4-§6).

| target | surface |
|---|---|
| `wire_decode` | the three proto2 schema decoders on raw bytes |
| `fragment_assembly` | framing + zlib + transport decode, as fragment sequences (multi-fragment reassembly, duplicates, conflicts, hole resets) |
| `ssp_receive` | everything above into BOTH SSP receivers (`UserStream` and `HostStreamState`) — idempotency rules on hostile field numbers |

## Run

```sh
rustup toolchain install nightly   # once
cargo run --manifest-path fuzz/Cargo.toml --example gen_seeds
cargo +nightly fuzz run <target>            # or: -- -max_total_time=600
```

Corpora are regenerable via `gen_seeds` and gitignored; libFuzzer
grows them in `fuzz/corpus/`.

## When a crash is found

The artifact under `fuzz/artifacts/` is machine-local and gitignored.
Reduce it (`cargo +nightly fuzz fmt <target> <artifact>`), then pin it
as a unit test in the main crate with the crashing input inline — a
committed corpus file is not a regression test.
