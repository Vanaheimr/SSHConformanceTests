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
  OpenSSH extensions (posix-rename / statvfs / limits@…); validated against the real `sftp` CLI
- ✅ **Port forwarding** — `direct-tcpip` tunnels and remote `-R` (`tcpip-forward`) with a **NetworkAcl**
  engine + `ForwardingPolicy` presets (loopback / private / subnet, DNS-rebinding safe),
  **ProxyJump** (SSH-over-SSH)
- ✅ **Hardening & observability** — typed audit event stream (SIEM-ready), keystroke-timing obfuscation,
  `TimeProvider`-driven timeouts, constant-time comparisons
- ✅ **High-level façade** — `SshClient`/`SshServer` over a connection multiplexer: exec, SFTP,
  `direct-tcpip` and remote `-R` all concurrent on one connection; host-key rotation (`hostkeys-00@openssh.com`)
- ✅ **IPv6 first-class**, and **interoperability testing against six independent implementations** —
  OpenSSH, AsyncSSH, Paramiko and SSH.NET drive our server; our client drives TinySSH; Dropbear does
  both (see [docs/INTEROP-MATRIX.md](docs/INTEROP-MATRIX.md))

## Projects

The SSH implementation itself lives in the **Hermod submodule** — it is a folder of the `Hermod`
project, like `DNS/`, `HTTP/` and `TCP/`, and ships inside the `org.GraphDefined.Vanaheimr.Hermod`
assembly. This repository is the harness around it: demo CLI, benchmarks and the conformance report.

| Location                         | Description                                                     |
|----------------------------------|-----------------------------------------------------------------|
| `libs/Hermod/Hermod/SSH/`        | The implementation — wire format, crypto, keys, transport, SFTP, plus `Client/` and `Server/` |
| `libs/Hermod/HermodTests/SSH/`   | Hermetic tests: unit + loopback, needing nothing but the code    |
| `HermodSSHDemo/`                 | The `hermod-ssh` CLI to set up a server and connect clients     |
| `HermodSSHTests/interop/`        | Conformance tests against real peers — OpenSSH, Dropbear, TinySSH, AsyncSSH, Paramiko, SSH.NET |
| `HermodSSHBenchmarks/`           | BenchmarkDotNet suite (see [docs/BENCHMARKS.md](docs/BENCHMARKS.md)) |
| `HermodSSHInteropReport/`        | Turns an interop test run into [docs/INTEROP-MATRIX.md](docs/INTEROP-MATRIX.md) |
| `libs/Hermod`                    | Vanaheimr Hermod submodule (SSH, DNS, TCP, PKI, logging; BouncyCastle) |
| `libs/Styx`                      | Vanaheimr Styx submodule (base utilities; BouncyCastle)         |

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
[interop/README.md](HermodSSHTests/interop/README.md). Whatever is missing is **skipped with a precise
reason**, never failed:

```bash
dotnet test HermodSSHTests/HermodSSHTests.csproj
```

## Demo CLI

The `hermod-ssh` tool (project `HermodSSHDemo`) drives the library from a terminal:

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
