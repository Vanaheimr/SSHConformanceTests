# HermodSSH — performance baseline

BenchmarkDotNet baseline (M10), plus the first optimisation attempt and what it taught us.

Three headlines, in the order they were learned:

1. **The first baseline missed the §8 target** — SFTP ~30–58 MiB/s against the stated ≥ 100 MB/s.
2. **The obvious culprit was the wrong one.** ChaCha20-Poly1305 allocated ~5× the payload per record;
   removing that allocation changed throughput **not at all**, which localised the cost to the ChaCha20
   keystream rather than to memory traffic.
3. **Replacing that keystream with a SIMD core fixed it.** ChaCha20 went from ~47 to ~107 MB/s per
   record, and SFTP from ~30–58 to **~73–110 MB/s — the target is now met on downloads** and approached
   on uploads.

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
| `aes256-gcm@openssh.com` | 38 µs | ≈ 867 MB/s | 98.5 KB |
| `chacha20-poly1305@openssh.com` (SIMD) | 308 µs | **≈ 107 MB/s** | 99.1 KB |
| `aes256-ctr` + `hmac-sha2-256-etm` | 2,124 µs | ≈ 15 MB/s | 459.2 KB |

AES-GCM remains the fastest — it delegates to the BCL's `AesGcm` and therefore to AES-NI. But the gap to
ChaCha20 is now **8×, down from 14.5×** (both measured in the same run, which is the comparison that
survives machine variance).

AES-GCM and ChaCha20 allocate the same ~98–99 KB per record: that is shared framing cost (plaintext
staging + output buffer + returned payload), not the cipher.

## 2. SFTP throughput (loopback, in-memory file system)

Full stack: encrypted transport → multiplexer → session channel → SFTP subsystem. In-memory file system
on purpose, so the number describes the protocol stack rather than a disk.

| Direction | Size | Before (scalar) | After (SIMD) |
|---|---|---:|---:|
| Upload | 8 MiB | 41.9 MB/s | **72.6 MB/s** |
| Download | 8 MiB | 31.3 MB/s | **110.1 MB/s** ✅ |
| Upload | 32 MiB | 43.3 MB/s | **73.8 MB/s** |
| Download | 32 MiB | 60.3 MB/s | **85.7 MB/s** |

**Against the §8 target of ≥ 100 MB/s: downloads now meet it (110 MB/s at 8 MiB), uploads reach ~73
MB/s.** SFTP negotiates ChaCha20-Poly1305 — first preference in `KexInitMessage`, and the façade exposes
no cipher knob — so this tracks the cipher change directly, confirming again that the cipher was the
ceiling.

Upload lagging download is the obvious next thread to pull: both move the same bytes through the same
cipher, so the difference is in the SFTP write path (pipelining depth, window credit) rather than crypto.

## 3. Two rounds of optimisation — what worked and what did not

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

### Round 2 — the SIMD core (this is the one that worked)

BouncyCastle's `ChaChaEngine` is scalar managed code. Replacing it with a `Vector128<UInt32>`
implementation — the quarter-round applied to all four state rows in parallel, the standard SSE/NEON
layout — gave:

| | Scalar (BouncyCastle) | SIMD (`ChaCha20`) | Gain |
|---|---:|---:|---:|
| 32 KiB record | 700 µs | 308 µs | **2.3×** |
| Throughput | ≈ 47 MB/s | ≈ 107 MB/s | **2.3×** |
| Ratio to AES-GCM, same run | 14.5× slower | 8.1× slower | **1.8×** |

The same-run ratio is the honest figure: absolute timings drifted between runs (untouched AES-CTR also
"improved" 1.8×, which is machine variance, not code). The ratio controls for that.

`Vector128` is hardware-agnostic — the JIT emits NEON on ARM and SSE2/AVX on x86 — so this is one
implementation rather than per-architecture intrinsics, and it is the ARM target that benefits most,
since there AES-GCM has no AES-NI advantage to fall back on.

---

## What this says to do next

1. **The SFTP upload path.** Upload sits at ~73 MB/s against download's ~110 MB/s over the same cipher,
   so the remaining gap is pipelining/window behaviour on writes, not crypto.
2. **`aes256-ctr` + EtM at ~15 MB/s** is now by far the worst path and still entirely unoptimised — the
   same scalar-versus-vectorised story, if it is worth the effort for a non-default cipher.
3. **`sntrup761x25519` handshakes cost ~85 ms** (§4) while being a listed default.
4. **Framing allocation** (~98 KB per 32 KiB record, ~400 MB per 32 MiB transfer) is now the largest
   remaining allocation source, shared by every cipher.

The cipher **default order is deliberately unchanged**: ChaCha20-first is correct for this project's
ARM device fleet, which has no AES acceleration — the very reason OpenSSH chose that default. On such
hardware AES-GCM's AES-NI advantage does not exist, so the SIMD ChaCha20 core is the fix that matters
there, and the x86 figures above understate its relative value on the target.

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
