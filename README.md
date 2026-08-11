# SSH Conformance & Interoperability Test Suite

A modern, fully asynchronous **SSH2 client and server** implementation for **C# / .NET 10**,
including **SFTP**, **post-quantum hybrid key exchange**, **public-key authentication** and
**OpenSSH certificates**. Part of the [Vanaheimr Hermod](https://www.github.com/Vanaheimr/Hermod)
ecosystem.

> **Status:** milestones **M0–M8 are complete** — transport, post-quantum key exchange, authentication,
> keys and certificates, the connection layer, SFTP v3 and forwarding, all validated against real
> implementations. **M9** (hardening, audit stream, fuzz suite, security review) and **M10** (demo CLI,
> benchmarks) are in place bar the nightly CI matrix, which needs a runner decision. The full design,
> feature set and the interoperability test program live in [PLAN.md](PLAN.md); repository conventions
> are in [CLAUDE.md](CLAUDE.md). Progress is tracked with ✅ / 🔶 / ⬜ markers.

## Interoperability

Every feature has to work against implementations that share no code with ours. Nine do —
**91 checks pass, none fail** — and the generated per-test detail is in
[docs/INTEROP-MATRIX.md](docs/INTEROP-MATRIX.md). What is *not* covered is listed just as plainly,
because a matrix that only shows green teaches nothing.

Both directions matter and both are covered: peers drive our server, and **our client drives OpenSSH,
Dropbear and TinySSH** — including our SFTP client against OpenSSH's own `sftp-server`.

| Peer | Version | Direction | Covered | Not covered yet |
|---|---|---|---|---|
| **OpenSSH** | 10.2p1 / 10.0p2 | **both** | *their client → our server:* transport matrix (11 combinations), auth (ed25519/ecdsa/rsa), certificates, key formats, SFTP, SSHFP records, host-key rotation. *our client → their `sshd`:* 5-method key-exchange matrix, exec + exit status, host-key refusal, **our SFTP client against their `sftp-server`** | ssh-agent needs a running agent, else skipped; finite-field DH is untestable in the client role since OpenSSH 10 dropped it from the server defaults |
| **Dropbear** | 2025.89 | **both** | 6 key exchanges, exec + exit status, host-key refusal, key format via `dropbearconvert`, **our client runs a command on their server** | no SFTP (Dropbear ships no SFTP client) |
| **PuTTY** (`plink`) | 0.83 | their client → our server | 6 key exchanges incl. ML-KEM, exec, host-key pinning, key format via `puttygen`, 256 KB through their flow control | `psftp`; the `winadj` quirk is watched for but plink 0.83 does not send one — the contract itself is pinned in the library's own suite |
| **AsyncSSH** | 2.24.0 | their client → our server | post-quantum `mlkem768x25519-sha256`, exec, SFTP, host-key refusal | certificates, which AsyncSSH could also issue |
| **Paramiko** | 5.0.0 | their client → our server | classical key exchange, exec, SFTP, host-key refusal, **clean failure when no algorithm is shared** | no post-quantum support exists in Paramiko to test |
| **SSH.NET** | 2026.0.0 | their client → our server (**in-process**) | ML-KEM negotiation, exec, SFTP, host-key refusal, several sessions on one connection | — (runs everywhere, so it gates every commit) |
| **TinySSH** | 20250601 | **our client** → their server | `sntrup761x25519-sha512` and `curve25519-sha256` on the most minimal server there is, host-key verification | authentication: TinySSH only reads the real `~/.ssh/authorized_keys`, and no test may write a usable key into a developer's account |
| **Go `x/crypto/ssh`** | v0.54.0 | their client → our server | post-quantum `mlkem768x25519-sha256`, exec + exit status, host-key refusal, and our `openssh-key-v1` read with **no conversion step** | SFTP (a separate module), certificates; the harness in `Tests/interop/go/` needs a Go toolchain and is compiled on demand |
| **curl / libssh2** | 8.14.1 / 1.11.1 | their client → our server | SFTP upload + download byte-for-byte through a third C lineage, host-key pinning via `--hostpubsha256` | no exec — curl speaks SFTP, not sessions |

**Known gaps.** Certificates are so far only proven against OpenSSH, and only in the direction where we
validate theirs. WinSCP, FileZilla and Apache MINA SSHD are candidates but not wired in. Everything above runs on a
developer machine today; the **nightly CI matrix is the one piece still missing**, waiting on a runner
decision (PLAN §13.5). Peers that are absent are **skipped with a precise reason**, never silently
counted as passing — the matrix distinguishes "disagreed" from "no evidence either way".

## Features

- ✅ **Transport** — version exchange, KEXINIT negotiation, strict-KEX (Terrapin), rekeying;
  ciphers `chacha20-poly1305@openssh.com` / AES-GCM / AES-CTR+EtM-HMAC; ext-info / server-sig-algs
- ✅ **Post-quantum hybrid KEX** — `mlkem768x25519-sha256` (BCL ML-KEM) + `sntrup761x25519-sha512` (BC),
  plus curve25519, NIST ECDH and classic DH; OpenSSH-validated
- ✅ **Authentication** — public-key (query-then-sign), password, keyboard-interactive, **TOTP 2FA**
  (RFC 6238), method chaining, pre-auth banner, **ssh-agent** client
- ✅ **Keys & trust** — openssh-key-v1 (incl. bcrypt_pbkdf) / PKCS#8 / RFC 4716, `SshKeyGenerator`,
  authorized_keys & known_hosts with validity windows, host-key pinning; **SSHFP DNS** (RFC 4255)
- ✅ **OpenSSH certificates** — full validator (§6 check order), a built-in mini-CA, user **and** host certs
- ✅ **Connection** — remote exec (capture stdout/stderr/exit), streaming `SshCommand` (stdin/pty),
  keepalive + idle timeouts, session recording (asciicast v2 + SFTP transcript)
- ✅ **SFTP v3** — client + server, pipelined transfers, seekable `SftpFileStream`, root-jailed local FS,
  least-privilege **access profiles** (upload-only / download-only), **quotas & bandwidth** limits,
  OpenSSH extensions (posix-rename / statvfs / fstatvfs / fsync / limits@…); validated against the real `sftp` CLI
- ✅ **Port forwarding** — `direct-tcpip` tunnels and remote `-R` (`tcpip-forward`) with a **NetworkAcl**
  engine + `ForwardingPolicy` presets (loopback / private / subnet, DNS-rebinding safe),
  **ProxyJump** (SSH-over-SSH)
- ✅ **Hardening & observability** — typed audit event stream (SIEM-ready), keystroke-timing obfuscation,
  `TimeProvider`-driven timeouts, constant-time comparisons
- ✅ **High-level façade** — `SshClient`/`SshServer` over a connection multiplexer: exec, SFTP,
  `direct-tcpip` and remote `-R` all concurrent on one connection; host-key rotation (`hostkeys-00@openssh.com`)
- ✅ **IPv6 first-class**, and interoperability against eight independent implementations (see above)

## Projects

The SSH implementation itself lives in the **Hermod submodule** — it is a folder of the `Hermod`
project, like `DNS/`, `HTTP/` and `TCP/`, and ships inside the `org.GraphDefined.Vanaheimr.Hermod`
assembly. This repository is the harness around it: demo CLI, benchmarks and the conformance report.

| Location                         | Description                                                     |
|----------------------------------|-----------------------------------------------------------------|
| [`libs/Hermod/Hermod/SSH/`](libs/Hermod/Hermod/SSH/README.md) | The implementation — wire format, crypto, keys, transport, SFTP, plus `Client/` and `Server/` |
| `libs/Hermod/HermodTests/SSH/` | Hermetic tests: unit + loopback, needing nothing but the code   |
| `Tests/interop/`               | Conformance tests against real peers, plus the drivers that run them |
| `Demo/`                        | The `hermod-ssh` CLI to set up a server and connect clients     |
| `Benchmarks/`                  | BenchmarkDotNet suite (see [docs/BENCHMARKS.md](docs/BENCHMARKS.md)) |
| `InteropReport/`               | Turns an interop test run into [docs/INTEROP-MATRIX.md](docs/INTEROP-MATRIX.md) |
| `libs/Hermod`                  | Vanaheimr Hermod submodule (SSH, DNS, TCP, PKI, logging; BouncyCastle) |
| `libs/Styx`                    | Vanaheimr Styx submodule (base utilities; BouncyCastle)         |

## Build & test

```bash
git clone --recurse-submodules <repo-url>
dotnet build SSH.slnx
dotnet test  SSH.slnx
```

Cloning **must** use `--recurse-submodules`: the implementation and its tests live in `libs/Hermod`,
which also provides BouncyCastle and Hermod's DNS/TCP/PKI/logging.

There are two suites. The hermetic one lives with the library and runs anywhere:

```bash
dotnet test libs/Hermod/HermodTests/HermodTests.csproj --filter FullyQualifiedName~Hermod.SSH.Tests
```

The conformance suite drives real third-party implementations and needs them present — see
[interop/README.md](Tests/interop/README.md). Whatever is missing is **skipped with a precise
reason**, never failed:

```bash
dotnet test Tests/Tests.csproj
```

## Demo CLI

The `hermod-ssh` tool (project `Demo`) drives the library from a terminal:

```bash
# Generate a key, inspect it, issue a certificate
hermod-ssh keygen -t ed25519 -f ./id_ed25519 -C me@laptop
hermod-ssh scan   -f ./id_ed25519.pub -n host.example.        # fingerprints + SSHFP records
hermod-ssh keygen -t ecdsa-sha2-nistp256 -f ./ca
hermod-ssh ca --ca ./ca -s ./id_ed25519.pub -I me@2026 -n me,admin   # → id_ed25519-cert.pub

# Run a demo server, then log in and run a command through it
printf '%s\n' "$(cat ./id_ed25519.pub)" > ./authorized_keys
hermod-ssh serve -a ./authorized_keys -p 2222 &
hermod-ssh exec  -i ./id_ed25519 -p 2222 demo@127.0.0.1 "uname -a"
```

`connect`, `sftp`, `forward` and `play` work too: an interactive session, SFTP put/ls/get, a local
`-L` tunnel, and replaying a recorded session with its original timing.

```bash
hermod-ssh connect -i ./id_ed25519 -p 2222 demo@127.0.0.1
hermod-ssh sftp    -i ./id_ed25519 -p 2222 demo@127.0.0.1 put ./firmware.bin /firmware.bin
hermod-ssh forward -i ./id_ed25519 -p 2222 -L 8080:example.com:80 demo@127.0.0.1
hermod-ssh play    ./session.cast --speed 2
```

## License

Apache License 2.0 — the full text is in [LICENSE](LICENSE), and every source file carries the matching
header. © 2010-2026 GraphDefined GmbH.
