# HermodSSH — performance baseline

First BenchmarkDotNet baseline (M10). A baseline exists to say where we actually are, so the headline is
stated plainly: **SFTP throughput does not meet the target in PLAN §8 — and the benchmarks identify why.**

Reproduce with:

```bash
dotnet run --project HermodSSHBenchmarks -c Release -- --filter "*" --job short
```

Release is required — BenchmarkDotNet refuses a debug build. Drop `--job short` for a full statistical
run. The numbers below come from a short run (3 warmup + 3 iterations), so the error margins are wide;
treat single figures as indicative. The differences that matter here are order-of-magnitude ones, far
outside that noise.

## Environment

| | |
|---|---|
| Runtime | .NET 10.0.10, X64 RyuJIT x86-64-v3 |
| Host | Windows, ZBOOK3 |
| Job | ShortRun — 3 warmup, 3 iterations, 1 launch |

---

## 1. SFTP throughput (loopback, in-memory file system)

The full stack: encrypted transport → connection multiplexer → session channel → SFTP subsystem. The
file system is in-memory deliberately, so the number describes the protocol stack, not a disk.

| Direction | Size | Mean | Throughput | Allocated |
|---|---|---:|---:|---:|
| Upload   |  8 MiB | 240.0 ms | ≈ 33 MiB/s | 119.6 MB |
| Download |  8 MiB | 196.4 ms | ≈ 41 MiB/s | 135.2 MB |
| Upload   | 32 MiB | 720.8 ms | ≈ 44 MiB/s | 475.9 MB |
| Download | 32 MiB | 740.3 ms | ≈ 43 MiB/s | 538.8 MB |

**Against the §8 target of ≥ 100 MB/s: we reach ≈ 33–44 MiB/s, about 40 %.**

Note the allocation: moving 32 MiB allocates ~476 MB — roughly **15× the payload**, with Gen1 and Gen2
collections during a transfer.

## 2. Per-cipher record throughput — where the SFTP number comes from

One SSH record all the way through the transport (framing, padding, encryption, MAC/AEAD) and out the
other end. Unlike the SFTP benchmark, the cipher can be pinned here.

| Cipher | 1 KiB record | 32 KiB record | Throughput @32 KiB | Allocated @32 KiB |
|---|---:|---:|---:|---:|
| `aes256-gcm@openssh.com` | 3.5 µs | 65.0 µs | **≈ 504 MB/s** | 630 B |
| `chacha20-poly1305@openssh.com` | 23.6 µs | 711.5 µs | **≈ 46 MB/s** | 166,992 B |
| `aes256-ctr` + `hmac-sha2-256-etm` | 114.0 µs | 4,480.6 µs | **≈ 7 MB/s** | 459,172 B |

This explains the SFTP result almost exactly. **The SFTP transfer runs on ChaCha20-Poly1305** — it is
our first preference in `KexInitMessage`, and the façade exposes no cipher knob — and ChaCha20's record
throughput (≈ 46 MB/s) lands right on the measured SFTP throughput (≈ 43 MiB/s). **The cipher is the
bottleneck, not SFTP, the multiplexer or the channel window.**

Three findings follow:

- **AES-GCM is ~11× faster than our default** (504 vs 46 MB/s) and allocates ~265× less per record
  (630 B vs 167 KB). It delegates to the BCL's hardware-accelerated `AesGcm`; the other two are our own
  constructions, and their allocation per record is what costs them.
- **`aes256-ctr` + EtM is ~69× slower than AES-GCM** (7 MB/s). It is a correctness-complete but entirely
  unoptimised path.
- **The §8 target looks reachable without touching SFTP at all** — on AES-GCM's record throughput there
  is ~10× headroom over the 100 MB/s goal. The work is in the ChaCha20 and CTR implementations
  (allocation per record), and possibly in the default preference order.

## 3. Handshake latency by key exchange

Version exchange → KEXINIT → key exchange → host-key signature → NEWKEYS, both roles, over an in-memory
pipe. No network, so this is our asymmetric maths and KDF.

| Key exchange | Mean | vs X25519 | Allocated |
|---|---:|---:|---:|
| `curve25519-sha256` | 0.96 ms | 1.0× | 59.6 KB |
| `mlkem768x25519-sha256` | 1.29 ms | **1.3×** | 87.7 KB |
| `ecdh-sha2-nistp256` | 12.10 ms | 12.6× | 62.3 KB |
| `sntrup761x25519-sha512` | 84.63 ms | **88×** | 307.5 KB |

- **Post-quantum is nearly free — with ML-KEM.** The `mlkem768x25519` hybrid costs only ~34 % more than
  classical X25519 (1.29 ms vs 0.96 ms), which is a strong argument for keeping it the default.
- **`sntrup761x25519` costs ~85 ms per handshake**, 88× X25519 and ~65× the other PQ hybrid. It sits in
  our default preference list, so a peer that selects it pays that on every connection.
- **NIST P-256 ECDH at 12 ms** is 12× X25519 — worth a look, since it is the common fallback for peers
  without curve25519.

---

## What this baseline says to do next

Nothing here has been optimised; the point was to get numbers to optimise against. In priority order:

1. **Per-record allocation in ChaCha20-Poly1305 and AES-CTR** — the single change that would move SFTP
   throughput, since the cipher is provably the bottleneck.
2. **`sntrup761x25519` handshake cost** — 85 ms per connection is a real cost for a listed default.
3. **SFTP-level allocation** (~15× payload) — secondary to the cipher, but the same class of problem.

## Legend

Throughput is payload ÷ mean. "Allocated" is managed allocation per operation from `MemoryDiagnoser`,
counting every intermediate buffer — the clearest signal of avoidable copying.
