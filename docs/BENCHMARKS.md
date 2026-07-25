# HermodSSH — performance baseline

BenchmarkDotNet baseline (M10), plus the first optimisation attempt and what it taught us.

Two headlines:

1. **SFTP does not meet the PLAN §8 target.** ~30–58 MiB/s on loopback against the stated ≥ 100 MB/s.
2. **The obvious culprit was the wrong one.** ChaCha20-Poly1305 allocated ~5× the payload per record; that
   was fixed and the allocation is gone — **and throughput did not move.** The bottleneck is the ChaCha20
   core itself, not memory traffic.

Reproduce with:

```bash
dotnet run --project HermodSSHBenchmarks -c Release -- --filter "*" --job short
```

Release is required — BenchmarkDotNet refuses a debug build.

## Reading these numbers

They come from a **short run** (3 warmup + 3 iterations). Allocation figures are stable and repeatable;
**timings are not** — error margins reach ±10 % and occasionally far more. Only order-of-magnitude
differences below should be treated as real.

A concrete warning from this data: the first run reported AES-GCM allocating **630 B** per 32 KiB record,
and a later run of the *same unmodified code* reported **96.2 KB**. 630 B is impossible for an operation
that must allocate the returned payload — it was an artifact. An earlier version of this document drew a
conclusion from it ("AES-GCM allocates ~265× less"); that claim was wrong and has been removed. Take a
single short-run figure as a hint, never as evidence.

## Environment

| | |
|---|---|
| Runtime | .NET 10.0.10, X64 RyuJIT x86-64-v3 (AES-NI available) |
| Host | Windows, ZBOOK3 |
| Job | ShortRun — 3 warmup, 3 iterations, 1 launch |

---

## 1. Per-cipher record throughput

One SSH record through the transport (framing, padding, encryption, MAC/AEAD) and back.

| Cipher | 32 KiB record | Throughput | Allocated |
|---|---:|---:|---:|
| `aes256-gcm@openssh.com` | 48 µs | **≈ 683 MB/s** | 96.2 KB |
| `chacha20-poly1305@openssh.com` | 700 µs | **≈ 47 MB/s** | 98.8 KB |
| `aes256-ctr` + `hmac-sha2-256-etm` | 3,827 µs | **≈ 9 MB/s** | 448.7 KB |

**AES-GCM is ~14× faster than ChaCha20 and ~80× faster than AES-CTR.** AES-GCM delegates to the BCL's
`AesGcm`, which uses AES-NI; the other two are our own constructions over BouncyCastle primitives.

Note that AES-GCM and ChaCha20 now allocate the *same* ~96–99 KB per record. That is the shared framing
cost (plaintext staging + output buffer + returned payload), not the cipher — see §3.

## 2. SFTP throughput (loopback, in-memory file system)

Full stack: encrypted transport → multiplexer → session channel → SFTP subsystem. In-memory file system
on purpose, so the number describes the protocol stack rather than a disk.

| Direction | Size | Mean | Throughput |
|---|---|---:|---:|
| Upload | 8 MiB | 200 ms | ≈ 40 MiB/s |
| Download | 8 MiB | 268 ms | ≈ 30 MiB/s |
| Upload | 32 MiB | 774 ms | ≈ 41 MiB/s |
| Download | 32 MiB | 556 ms | ≈ 58 MiB/s |

**Against the §8 target of ≥ 100 MB/s: we reach roughly 30–58 MiB/s.** The spread across directions and
sizes is mostly run-to-run noise.

SFTP negotiates ChaCha20-Poly1305 — it is our first preference in `KexInitMessage`, and the façade
exposes no cipher knob — and ChaCha20's record throughput (≈ 47 MB/s) sits squarely inside that range.
**The cipher, not SFTP or the multiplexer, sets the ceiling.**

## 3. The ChaCha20 allocation fix — what it did and did not do

`ChaCha20Poly1305Cipher` allocated a full copy of every packet twice: once as a `ciphertext` array on
encrypt (then copied into the output) and once via `ciphertext.ToArray()` on decrypt, plus per-record
arrays for the nonce, the Poly1305 key block and the tag. BouncyCastle 2.6.2 turned out to expose span
overloads (`ProcessBytes(ReadOnlySpan, Span)`, `Poly1305.DoFinal(Span)`), so the cipher now encrypts
straight into the output buffer and decrypts straight into the result, with `stackalloc` for the small
buffers.

**Allocation — fixed, exactly as predicted:**

| | Before | After | Saved |
|---|---:|---:|---:|
| Per 32 KiB record | 163 KB | 98.8 KB | **−64 KB** |
| Per 32 MiB SFTP transfer | 476 MB | 410 MB | **−66 MB** |

The end-to-end saving is the arithmetic confirmation: a 32 MiB transfer is 1024 records, and
1024 × 64 KB = 67 MB predicted against 66 MB measured.

**Throughput — unchanged:**

| | Before | After |
|---|---:|---:|
| ChaCha20, 32 KiB record | 711 µs | 700 µs |
| SFTP, 32 MiB | 44 / 43 MiB/s | 41 / 58 MiB/s |

Both differences are inside the noise. **So the hypothesis in the first baseline — that per-record
allocation was throttling throughput — was wrong.** Removing ~40 % of the allocation changed the timing
not at all, which localises the cost to the ChaCha20 keystream itself: BouncyCastle's `ChaChaEngine` is a
scalar managed implementation, competing against AES-NI.

The fix is kept regardless: 66 MB less garbage per 32 MiB transfer is worth having, and it removed Gen1
pressure. It is simply not a throughput fix.

---

## What this says to do next

1. **A faster ChaCha20 core.** The 14× gap to AES-GCM is the keystream, and a vectorised (SIMD)
   ChaCha20 is the known remedy. This is the only change that would move SFTP throughput materially
   while ChaCha20 stays the default.
2. **Or reconsider the default cipher order.** On hardware with AES-NI, `aes256-gcm` is ~14× faster and
   would clear the 100 MB/s target with headroom. ChaCha20-first is the right default on machines
   *without* AES acceleration, which is why OpenSSH chose it — so this is a policy decision about the
   target fleet, not an obvious win, and it is left open deliberately.
3. **`aes256-ctr` + EtM at ~9 MB/s** is by far the worst path and entirely unoptimised.
4. **`sntrup761x25519` handshakes cost ~85 ms** (§4) while being a listed default.

## 4. Handshake latency by key exchange

| Key exchange | Mean | vs X25519 |
|---|---:|---:|
| `curve25519-sha256` | 0.96 ms | 1.0× |
| `mlkem768x25519-sha256` | 1.29 ms | **1.3×** |
| `ecdh-sha2-nistp256` | 12.10 ms | 12.6× |
| `sntrup761x25519-sha512` | 84.63 ms | **88×** |

**Post-quantum is nearly free with ML-KEM** — ~34 % over classical X25519, a good argument for keeping it
the default. `sntrup761x25519` at 85 ms per connection is a different matter, and it is also a listed
default.

## Legend

Throughput is payload ÷ mean. "Allocated" is managed allocation per operation from `MemoryDiagnoser`,
counting every intermediate buffer.
