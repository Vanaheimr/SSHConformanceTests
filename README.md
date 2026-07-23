# HermodSSH

A modern, fully asynchronous **SSH2 client and server** implementation for **C# / .NET 10**,
including **SFTP**, **post-quantum hybrid key exchange**, **public-key authentication** and
**OpenSSH certificates**. Part of the [Vanaheimr Hermod](https://www.github.com/Vanaheimr/Hermod)
ecosystem.

> **Status:** early implementation. The full design, feature set, milestones (M0–M10) and the
> interoperability test program live in [PLAN.md](PLAN.md); repository conventions are in
> [CLAUDE.md](CLAUDE.md). Progress is tracked with ✅ / 🔶 / ⬜ markers in the plan.

## Highlights (planned)

- SSH2 transport, authentication and connection layers; SFTP v3 with OpenSSH extensions
- Post-quantum hybrid KEX (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`)
- Public-key auth, OpenSSH user **and** host certificates, a built-in mini-CA
- Host-key trust via pinning, known_hosts, certificates and **SSHFP DNS** (Hermod DNS)
- TOTP two-factor auth, session recording (asciicast), keystroke-timing obfuscation
- Least-privilege server access profiles (upload-only / download-only SFTP), quotas & bandwidth limits
- Port forwarding with network ACLs, ProxyJump, a typed audit event stream
- Broad interoperability testing against OpenSSH (Linux/WSL2) and many other implementations

## Projects

| Project           | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| `HermodSSH`       | The library — client, server, transport, crypto, keys, SFTP        |
| `HermodSSHTests`  | NUnit test suite (unit, loopback, interop)                         |
| `HermodSSHDemo`   | The `hermod-ssh` CLI to set up a server and connect clients        |
| `libs/Hermod`     | Vanaheimr Hermod submodule (DNS, TCP, PKI, logging)                |
| `libs/Styx`       | Vanaheimr Styx submodule (base utilities)                          |

## Build & test

```bash
git clone --recurse-submodules <repo-url>
dotnet build SSH.slnx
dotnet test  SSH.slnx
```

The M0 core (binary wire format + tests) has no external dependencies; the `libs/*` submodules
join the solution as features begin to reference them.

## License

Apache License 2.0 — see the header of each source file. © 2010-2026 GraphDefined GmbH.
