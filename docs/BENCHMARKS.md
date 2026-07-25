# HermodSSH — performance

Full-fidelity BenchmarkDotNet results (M10), after two rounds of optimisation. Every figure here comes
from a **default-job run** — proper warmup, ~15 iterations per case, statistical outlier removal, on an
otherwise idle machine. It replaces an earlier set of short-run numbers that proved unreliable; see
*Reading these numbers*.

Where things stand:

- **SFTP: 87–111 MB/s.** The PLAN §8 target of ≥ 100 MB/s is met on 8 MiB downloads and approached
  elsewhere — up from ~30–58 MB/s at the first baseline.
- **ChaCha20 is now 6.6× off AES-GCM**, down from 14.5×, after replacing BouncyCastle's scalar engine
  with a SIMD core. That is the ratio that matters for the ARM target, where AES-GCM has no AES-NI
  advantage to fall back on.
- **Two hypotheses were wrong along the way**, and both are documented below rather than quietly fixed.

Reproduce with:

```bash
dotnet run --project HermodSSHBenchmarks -c Release -- --filter "*"
```

Release is required — BenchmarkDotNet refuses a debug build. Add `--job short` for a quick look, but see
the warning below before trusting what it prints.

## Reading these numbers

Timings on this machine have a **high noise floor**, and short runs are not sufficient to see through
it. Three concrete lessons from this session, all of which cost real conclusions:

1. A short run reported AES-GCM allocating **630 B** per 32 KiB record; the *same unmodified code* later
   measured **96.2 KB**. 630 B is impossible for an operation that must allocate the returned payload.
   A conclusion drawn from it ("AES-GCM allocates ~265× less") was wrong and has been removed.
2. A short run showed **download throughput dropping 27–41 % in code that was never touched** — the tell
   that the whole run, not the change, was slower.
3. A short run put the ML-KEM handshake at 1.3× X25519; the full job puts it at **2.35×**. The
   "post-quantum is nearly free" framing that produced is corrected below.

**Allocation figures are exact and repeatable; timings are not.** Prefer within-run comparisons (e.g. a
cipher against AES-GCM in the same run) over across-run ones, and treat any difference smaller than the
error margin as no result.

## Environment

| | |
|---|---|
| Runtime | .NET 10.0.10, X64 RyuJIT x86-64-v3 (AES-NI available) |
| Host | Windows, ZBOOK3 |
| Job | Default — full warmup, ~15 iterations, outlier removal |

---

## 1. Per-cipher record throughput

One SSH record through the transport (framing, padding, encryption, MAC/AEAD) and back.

| Cipher | 32 KiB record | Throughput | vs AES-GCM | Allocated |
|---|---:|---:|---:|---:|
| `aes256-gcm@openssh.com` | 37.3 µs ±1.8 % | **878 MB/s** | 1.0× | 96.2 KB |
| `chacha20-poly1305@openssh.com` (SIMD) | 247.9 µs ±10.4 % | **132 MB/s** | **6.6×** | 96.8 KB |
| `aes256-ctr` + `hmac-sha2-256-etm` | 2,417 µs ±14.2 % | 13.6 MB/s | 64.7× | 448.9 KB |

AES-GCM leads because it delegates to the BCL's `AesGcm`, i.e. to AES-NI. **The ChaCha20 gap is now
6.6×, down from 14.5× before the SIMD core** — and on the ARM devices this project targets that
comparison inverts, since there is no AES acceleration there for AES-GCM to exploit.

`aes256-ctr` + EtM is the outlier at 64.7× slower: correctness-complete, entirely unoptimised, and the
same scalar-versus-vectorised story that ChaCha20 just went through.

## 2. SFTP throughput (loopback, in-memory file system)

Full stack: encrypted transport → multiplexer → session channel → SFTP subsystem. In-memory file system
on purpose, so the number describes the protocol stack rather than a disk. Runs on ChaCha20-Poly1305,
our first preference.

| Direction | Size | Mean | Throughput | Allocated |
|---|---|---:|---:|---:|
| Upload | 8 MiB | 90.6 ms ±3.5 % | 92.6 MB/s | 75.1 MB |
| Download | 8 MiB | 75.6 ms ±5.0 % | **111.0 MB/s** ✅ | *(see anomaly)* |
| Upload | 32 MiB | 383.8 ms ±6.0 % | 87.4 MB/s | 300.0 MB |
| Download | 32 MiB | 349.9 ms ±22.2 % | 95.9 MB/s | 427.7 MB |

**Against the §8 target of ≥ 100 MB/s: met on 8 MiB downloads (111 MB/s), 87–96 MB/s elsewhere** — from
~30–58 MB/s at the first baseline.

**The upload/download gap has closed from ~34 % to 9–17 %.** That gap was the motivation for removing
three per-chunk copies from the write path (§3, round 3); what remains is small enough to be partly the
measurement noise above.

> **Anomaly, recorded rather than reported as fact:** the 8 MiB download run reports **3,253 MB**
> allocated per operation. That is inconsistent with the 32 MiB download's 428 MB — four times the data
> allocating an eighth as much — and impossible on its face. Treat it as a measurement artifact
> (`MemoryDiagnoser` interacting with a full GC mid-measurement is the likely cause) and re-measure
> before drawing anything from it. The other three allocation figures are mutually consistent and match
> the arithmetic in §3.

## 3. Three rounds of optimisation

### Round 1 — remove ChaCha20's per-record copies (worked, but not for throughput)

The cipher copied every packet twice: a `ciphertext` array on encrypt then copied to the output, and
`ciphertext.ToArray()` on decrypt. BouncyCastle 2.6.2 exposes span overloads, so it now encrypts
straight into the output buffer and decrypts straight into the result.

| | Before | After | Saved |
|---|---:|---:|---:|
| Per 32 KiB record | 163 KB | 98.8 KB | −64 KB |
| Per 32 MiB transfer | 476 MB | 410 MB | −66 MB |

Predicted 1024 records × 64 KB = 67 MB against 66 MB measured. **Throughput did not move at all** —
which disproved the first baseline's hypothesis that allocation was throttling SFTP, and localised the
cost to the keystream instead. Kept anyway for the reduced GC pressure.

### Round 2 — SIMD ChaCha20 core (this is the one that moved throughput)

BouncyCastle's `ChaChaEngine` is scalar managed code. `ChaCha20` replaces it with a
`Vector128<UInt32>` implementation — the quarter-round applied to all four state rows in parallel, the
standard SSE/NEON layout. `Vector128` is hardware-agnostic, so the JIT emits **NEON on ARM** and SSE2/AVX
on x86 from one implementation.

| | Scalar | SIMD |
|---|---:|---:|
| Ratio to AES-GCM, same run | 14.5× slower | **6.6× slower** |
| 32 KiB record throughput | ≈ 47 MB/s | **132 MB/s** |

Validated against RFC 8439 §2.3.2 and §2.4.2 before anything else — a round-trip test passes just as
happily with a wrong-but-symmetric keystream. That was necessary but **not sufficient**: the first
wiring passed all 305 non-interop tests *and* all four RFC vectors while failing 10 interop tests, every
one a `chacha20-poly1305` case. The nonce parameter was a `UInt64`, and OpenSSH reads the 8-byte IV as
two little-endian words while the sequence number is written big-endian into those bytes — so the
numeric form silently changed both byte order and word placement. The API now takes bytes.

### Round 3 — remove the SFTP write path's per-chunk copies

Every 30 KiB WRITE chunk was copied four times on the way out, while a READ request is ~30 bytes and
paid none of it. Three were removed: `Data.ToArray()` on the caller's chunk, `WrittenSpan.ToArray()`
when building the packet, and the `new Byte[4 + len]` framing buffer (now pooled).

| | Before | After | Saved |
|---|---:|---:|---:|
| Upload, per 32 MiB | 396 MB | 300 MB | **−96 MB** |
| Download, per 32 MiB | 460 MB | 428 MB | −32 MB |

Predicted 3 copies × 32 MiB = 96 MB for upload against 95.7 MB measured; download saves ~32 MB from the
server-side framing buffer alone, which is exactly right since downloads send no large payloads.

## 4. Handshake latency by key exchange

| Key exchange | Mean | vs X25519 | Allocated |
|---|---:|---:|---:|
| `curve25519-sha256` | 0.64 ms ±2.5 % | 1.0× | 57.6 KB |
| `mlkem768x25519-sha256` | 1.50 ms ±27 % | **2.35×** | 85.8 KB |
| `ecdh-sha2-nistp256` | 6.74 ms ±24 % | 10.6× | 60.4 KB |
| `sntrup761x25519-sha512` | 75.3 ms ±29 % | **118×** | 305.3 KB |

**Correction:** an earlier short run put ML-KEM at 1.3× X25519 and this document called post-quantum
"nearly free". The full job puts it at **2.35×** (1.50 ms vs 0.64 ms). The conclusion survives — 1.5 ms
per connection is cheap in absolute terms, and it is 50× cheaper than the other PQ hybrid — but the
"nearly free" framing was an artifact and is withdrawn.

**`sntrup761x25519` costs 75 ms per handshake**, 118× X25519, while being a listed default. That is the
standout number in this table.

---

## What to do next

1. **`aes256-ctr` + EtM at 13.6 MB/s** — 64.7× off AES-GCM, and the same scalar-versus-vectorised
   situation ChaCha20 was in. Worth it only if a non-default cipher justifies the effort.
2. **`sntrup761x25519` at 75 ms/handshake**, still a listed default.
3. **Framing allocation** — ~96 KB per 32 KiB record and ~300–430 MB per 32 MiB transfer is now the
   largest remaining allocation source, shared by every cipher.
4. **Re-measure the 8 MiB download allocation** anomaly in §2.

The cipher **default order is deliberately unchanged**: ChaCha20-first is correct for this project's ARM
device fleet, which has no AES acceleration — the very reason OpenSSH chose that default. The x86
figures above understate the SIMD core's relative value on the actual target.

## Legend

Throughput is payload ÷ mean. "Allocated" is managed allocation per operation from `MemoryDiagnoser`,
counting every intermediate buffer. Percentages after a mean are the reported error as a fraction of it.
