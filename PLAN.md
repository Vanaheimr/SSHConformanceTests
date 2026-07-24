# HermodSSH — Implementation Plan

A modern SSH2 **client and server** implementation in C# / .NET 10 including **SFTP**,
fully **async**, with **post-quantum hybrid key exchange**, **public-key authentication**
and **OpenSSH certificates** as first-class features. Unit tests with **NUnit**.
Interoperability with OpenSSH and a broad set of third-party implementations is a
hard acceptance criterion (see §11).

**Status legend:** ✅ done · 🔶 partial · ⬜ open — markers are kept current as implementation proceeds.
**Current state (2026-07-24):** **M0 ✅**, **M1 ✅**, **M2 ✅**, **M3 ✅**, **M4 ✅**, **M5 ✅**, **M6 ✅ (connection + remote exec + streaming `SshCommand` + keepalive/idle liveness + session recording, OpenSSH-validated)**, **M7 ✅ (SFTP v3 client+server, access profiles, local FS + root jail, quotas/bandwidth, extensions, pipelining, `SftpFileStream`, real-`sftp`-validated)**, **M8 🔶 (NetworkAcl + direct-tcpip + **connection multiplexer** + remote `-R` + ProxyJump + ssh-agent + SSHFP; only optional hostkeys-00 left)**, **M9 🔶 (audit catalog + keystroke-timing obfuscation + server limits; fuzz/CI pending)**, **M10 🔶 (demo CLI keygen/scan/ca/exec/serve + README; connect/sftp/forward/play + NuGet/benchmarks pending)**. **High-level `SshClient`/`SshServer` façade ✅** (over the multiplexer: one connection multiplexes exec + direct-tcpip + remote `-R`; `SshClientOptions`/`SshServerOptions`; SFTP-over-mux still pending). Core/Client/Server
split (net10.0, GraphDefined conventions, BouncyCastle via submodules). The **modern transport works
end-to-end and interops with real OpenSSH**: version exchange → KEXINIT negotiation → curve25519-sha256 →
ssh-ed25519 host-key signature → KDF → NEWKEYS → aes256-gcm, both roles, over an in-memory `IDuplexPipe`
**and real TCP (IPv4 + `::1`)**, strict-KEX + ext-info advertised and detected. **77 NUnit tests green**,
including a real-OpenSSH interop test: our server completes the handshake with the actual `ssh` client
(OpenSSH 10.2) and **decrypts its `SERVICE_REQUEST`**, proving KEX + KDF + AES-GCM match OpenSSH byte-for-byte.
Remaining interop breadth (our client ↔ real `sshd`, full WSL harness) grows with the interop program.
**M2 ✅ complete:** added AES-CTR + HMAC-SHA2-256/512 **encrypt-then-MAC**, **chacha20-poly1305@openssh.com**
(now the default cipher), the **NIST ECDH key exchanges** (`ecdh-sha2-nistp256/384/521`, `SshKeyExchange`
abstraction, variable SHA-256/384/512), the **classic finite-field DH key exchanges**
(`diffie-hellman-group14-sha256` / `group16-sha512`, RFC 3526 MODP groups 14/16, mpint `e`/`f` +
modexp, peer-value validation), **ECDSA + RSA host keys** (`ISshHostKey` + `SshSignature.Verify`
signature abstraction — reused later for pubkey auth), **rekeying** (`SshTransport`, a stateful
transport owning the mutable cipher/sequence state; `RekeyAsync` re-runs the KEX over the encrypted
channel, fresh keys but the same session id; strict-KEX resets the sequence numbers after every
NEWKEYS; shared KEX core `SshKexCore`), and **ext-info / server-sig-algs** (RFC 8308: `ExtInfoMessage`,
the server emits `SSH_MSG_EXT_INFO(server-sig-algs)` right after its first NEWKEYS, the client parses it
via `TryHandleExtInfo`). Full cipher, KEX **and** host-key matrices green;
**OpenSSH-validated** across chacha20-poly1305/gcm/ctr-etm × curve25519/nistp256/nistp521/**group14/group16** ×
ed25519/ecdsa-nistp256/rsa-sha2-512, plus real `ssh` receiving our EXT_INFO / server-sig-algs. **125 tests
green.** (Non-ETM E&M HMACs intentionally still omitted — EtM only.)
**M4 ✅ complete (auth + keys):** on top of everything below, **password** (RFC 4252 §8) and
**keyboard-interactive** (RFC 4256) authentication, **method chaining via partial success**, and
**TOTP 2FA** (`publickey,keyboard-interactive`) with a **standard RFC 6238** validator (RFC 6238 test
vectors green; base32 secret, ±1-step skew, single-use replay cache, `otpauth://` enrolment URI) —
composed through `SshAuthenticationPolicy` (`WithPublicKey`/`WithPassword`/`WithSecondFactor`). A **typed
audit stream** (`SshAuditEvent` records + `ISshAuditSink`) emits banner/auth-method/success/failure events.
(Note: Hermod's `TOTPGenerator` is a different e-mobility construction, so TOTP uses the standard RFCs, not
that type.) **179 tests green.**
**M4 (public-key foundation):** **public-key authentication** landed (RFC 4252): the `ssh-userauth`
service request/accept, the `publickey` method with the **query-then-sign** flow, banner and
success/failure handling — driven by `UserAuthentication` over `SshTransport`, with a pluggable
`ISshUserAuthenticator` (server) and `SshSignature.Verify` reused for the client-signature check. The
client picks the signature algorithm from the server's `server-sig-algs` (so RSA keys use rsa-sha2-256/512,
never SHA-1). **OpenSSH-validated:** real `ssh` authenticates to our server with ssh-keygen ed25519/ecdsa/rsa
keys and we verify the signature. **Key material** landed too: `SshFingerprint` (SHA256/MD5), `SshPublicKey`
(authorized_keys line + RFC 4716), `OpenSshPrivateKey` (openssh-key-v1 read incl. bcrypt-encrypted, write),
`BcryptPbkdf` (eksblowfish KDF using BouncyCastle's Blowfish constants), PKCS#8/PEM for RSA/ECDSA, and
`SshKeyGenerator` (+ first-run host key) — validated against `ssh-keygen` (we read its unencrypted &
bcrypt-encrypted keys; it reads ours). **Key trust**: `AuthorizedKeysFile` (options + `notBefore`/`notAfter`
validity windows), `KnownHostsFile` (hashed `|1|`, wildcards, `@cert-authority`/`@revoked`), and the
`HostKeyPolicy` chain (pins → known_hosts → TOFU) wired to the client's host-key verification. Still open
in M4: password/keyboard-interactive + TOTP 2FA, typed audit stream. **172 tests green.**
**M3 ✅ complete (post-quantum hybrid KEX):** `mlkem768x25519-sha256` (ML-KEM-768 via the .NET BCL `MLKem`)
and `sntrup761x25519-sha512` (+ `@openssh.com` alias, sntrup761 via BouncyCastle) — both now the default
top KEX preference, matching OpenSSH 10. `SshKeyExchange` was generalised to an explicit client/server
model (`StartClient` / `ServerRespond` / `ClientFinish`) so the asymmetric KEM flow (server encapsulates
against the client's public key) fits alongside ECDH/DH; a `SshKem` abstraction wraps the two KEMs.
**The PQ interop trap is handled:** the hybrids encode the shared secret K (the KEX hash output) as an
SSH `string`, not an mpint (`EncodeSharedSecret` override) — verified. **OpenSSH-validated**: real
`ssh` (10.2p1) completes both hybrids with our server and decrypts through NEWKEYS (BouncyCastle's
sntrup761 matches OpenSSH byte-for-byte). Interop auto-selects an ssh that supports the method (the
Windows-bundled OpenSSH 9.5 lacks PQ, so those cases skip on it). **134 tests green.** Next: **M4 (auth + keys)**.

---

## 1. Goals & Non-Goals

### Goals (v1)

- Complete SSH2 protocol: transport (RFC 4253), authentication (RFC 4252), connection/channels (RFC 4254)
- Client **and** server from one code base (the transport is symmetric; ~90 % shared code)
- SFTP v3 (client + server subsystem) including the important OpenSSH extensions
- Post-quantum hybrid key exchange: `mlkem768x25519-sha256`, `sntrup761x25519-sha512`
- Public-key authentication (Ed25519, ECDSA, RSA/rsa-sha2) — **essential**
- OpenSSH certificates (`*-cert-v01@openssh.com`) for user **and** host auth, including a built-in mini-CA (issue certificates) — **essential**
- Flexible client-side host key trust: explicit fingerprint pinning via options, known_hosts, host certificates, SSHFP DNS lookups (RFC 4255, DNSSEC-gated, pluggable resolver → Hermod DNS)
- Server-side least-privilege authorization: per-account session permissions with ready-made SFTP profiles — upload-only (device log collection) and download-only (firmware distribution) — **essential**
- Port forwarding as an admin/debugging feature — gated by fine-grained network ACLs (loopback-only, private-networks-only, specific subnets, port sets) on both roles
- **ProxyJump / jump hosts** (client): SSH-over-SSH through one or more bastions, per-hop host-key policy and credentials (`-J` equivalent)
- **SFTP quotas & bandwidth limits** per access profile: max file size, per-session byte/file caps, throughput throttling
- **Typed audit event stream**: structured, strongly-typed events (auth, sessions, transfers, policy/ACL denials, disconnects) for SIEM integration
- **Pre-auth authentication banner** (`SSH_MSG_USERAUTH_BANNER`): server-configurable legal notice; client surfaces peer banners
- **Connection liveness**: keepalive-based dead-peer detection and idle-session timeouts on both roles (`ClientAlive*`/`ServerAlive*` equivalents)
- **Key generation API** (`SshKeyGenerator`): create Ed25519/ECDSA/RSA keys and export all formats; server auto-generates host keys on first run
- **IPv6 as a first-class citizen** throughout: dual-stack listeners, ACLs, known_hosts, address parsing
- **TOTP two-factor authentication** (server side): `publickey` + one-time code over keyboard-interactive, standard authenticator apps **and** a phishing-resistant session-bound variant (reuses Hermod `TOTP`)
- **Session recording** (server side): interactive/exec sessions to replayable asciicast v2, SFTP sessions to structured transcripts — for compliance and demos
- **Keystroke-timing obfuscation** for interactive sessions (chaff packets, OpenSSH `ping@openssh.com`) — defeats keystroke timing analysis
- Interoperability with OpenSSH (≥ 9.x, incl. Windows OpenSSH) and other major implementations as a hard acceptance criterion (full program in §11)
- Hardening: strict KEX (Terrapin mitigation), DoS limits, constant-time comparisons, key zeroization
- Fully `async`/`await`, `CancellationToken`, `IAsyncDisposable`, System.IO.Pipelines, Span/Memory

### Non-Goals (v1, kept open as extension points)

- SCP (OpenSSH itself runs SCP over SFTP these days), X11 forwarding, GSSAPI/Kerberos
- Connection multiplexing à la ControlMaster; compression (`zlib@openssh.com` later, optional)
- SSH1 and any legacy cryptography (CBC, 3DES, hmac-md5/sha1, DH group1, ssh-rsa/SHA-1 — at most as an explicit opt-in)
- Full interactive shell **hosting** in the server (protocol support yes: `pty-req`, `shell`, `exec`; actual PTY hosting via ConPTY only as a demo/extension)

### Parked "fun/optional" features (kept as a backlog, not scheduled in v1)
Reviewed and deliberately deferred: SSH-over-WebSocket transport (Hermod has the WS stack — strong later candidate for firewalled devices), `~/.ssh/config` reader, agent forwarding, FIDO2/`sk-*` security keys, Unix-domain-socket forwarding, admin-console subsystem, honeypot/tarpit listener. **Committed for v1 from this backlog:** TOTP 2FA, session recording, keystroke-timing obfuscation, ProxyJump, SFTP quotas/bandwidth, typed audit stream, pre-auth banner (see Goals).

---

## 2. Standards & References

| Area | Reference |
|---|---|
| Architecture / numbers | RFC 4251, RFC 4250 |
| Transport / KEX | RFC 4253, RFC 9142 (KEX update), RFC 8268 (DH-SHA2), RFC 5656 (ECDH/ECDSA), RFC 8731 (curve25519-sha256), RFC 4344 (CTR) |
| PQ hybrid KEX | draft-ietf-sshm-mlkem-hybrid-kex (`mlkem768x25519-sha256`; may have been published as an RFC by now → verify), OpenSSH `sntrup761x25519-sha512`, FIPS 203 (ML-KEM) |
| Auth | RFC 4252 (incl. §5.4 `SSH_MSG_USERAUTH_BANNER`), RFC 4256 (keyboard-interactive), RFC 8332 (rsa-sha2), RFC 8709 (Ed25519), RFC 8308 (ext-info / server-sig-algs) |
| ProxyJump | OpenSSH `ssh_config` `ProxyJump`/`-J` (SSH-over-SSH layered on `direct-tcpip`, RFC 4254 §7) |
| Connection | RFC 4254 |
| AEAD | RFC 5647 + OpenSSH semantics (`aes*-gcm@openssh.com`), OpenSSH `PROTOCOL.chacha20poly1305` |
| MACs | RFC 6668 (hmac-sha2), OpenSSH `-etm@openssh.com` |
| Certificates | OpenSSH `PROTOCOL.certkeys`, `PROTOCOL.krl` (revocation, stretch goal) |
| SFTP | draft-ietf-secsh-filexfer-02 (v3), OpenSSH `PROTOCOL` (extensions) |
| Key formats | OpenSSH `PROTOCOL.key` (openssh-key-v1 + bcrypt_pbkdf), PKCS#8, RFC 7468 (PEM), RFC 4716 |
| Agent | draft-miller-ssh-agent |
| 2FA / TOTP | RFC 6238 (TOTP), RFC 4226 (HOTP), RFC 4256 (keyboard-interactive), `otpauth://` enrollment URI; Hermod `TOTP` (session-bindable variant) |
| Session recording | asciicast v2 (asciinema recording format) for PTY/exec; structured JSON transcript for SFTP |
| Keystroke timing | OpenSSH `PROTOCOL` (`ping@openssh.com`, `SSH_MSG_PING`/`PONG`, chaff-based timing obfuscation ≥ 9.5); background: Song/Wagner/Tian, "Timing Analysis of Keystrokes and Timing Attacks on SSH" (2001) |
| SSHFP / DNS | RFC 4255 (SSHFP RR, type 44), RFC 6594 (SHA-256, ECDSA), RFC 7479 (Ed25519), IANA SSHFP registry (Ed448 = 6); DNSSEC validation as the trust anchor |
| Security | CVE-2023-48795 "Terrapin" → strict KEX (`kex-strict-c/s-v00@openssh.com`) |

Primary interop reference: **OpenSSH** — the OpenBSD upstream project, consumed as portable releases under Linux/WSL2 and as Windows OpenSSH (`C:\Windows\System32\OpenSSH`). Details and the full peer matrix in §11.

---

## 3. Algorithm Portfolio

Order = default preference. Everything configurable via an options object (enable/disable/reorder).

### Key Exchange
1. ✅ `mlkem768x25519-sha256` — PQ hybrid, OpenSSH default since 10.0
2. ✅ `sntrup761x25519-sha512` (+ alias `@openssh.com`) — PQ hybrid, OpenSSH default 9.0–9.9
3. ✅ `curve25519-sha256` (+ alias `@libssh.org`)
4. ✅ `ecdh-sha2-nistp256` / `-nistp384` / `-nistp521`
5. ✅ `diffie-hellman-group14-sha256` (MUST per RFC 9142), `diffie-hellman-group16-sha512`
6. Later, optional: `mlkem1024nistp384-sha384`
- Pseudo algorithms: `ext-info-c`/`ext-info-s` (RFC 8308), `kex-strict-c-v00@openssh.com`/`kex-strict-s-v00@openssh.com` (Terrapin)

> **Interop trap:** for the PQ hybrid KEX methods the shared secret K is encoded as an SSH `string` (hash output); for all classic KEX methods it is an `mpint`. This is the single most common interop bug — it gets its own test cases.

### Host Keys / Signatures (user and host auth alike)
- `ssh-ed25519` (+ `ssh-ed25519-cert-v01@openssh.com`)
- `ecdsa-sha2-nistp256/384/521` (+ their `-cert-v01@openssh.com` forms)
- `rsa-sha2-256`, `rsa-sha2-512` (key type `ssh-rsa`, min. 2048 bit, signatures always SHA-2; + `ssh-rsa-cert-v01@openssh.com`)
- `ssh-rsa` (SHA-1): **off by default**, explicit opt-in only
- PQ signatures (ML-DSA for SSH): not standardized yet → extension point in the algorithm registry, track the drafts. Context: the PQ urgency is on the **KEX** (harvest-now-decrypt-later); signatures only matter at attack time and can migrate later.

### Ciphers
1. `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com` (hardware AES in the BCL → fastest option on .NET)
2. `chacha20-poly1305@openssh.com` — **OpenSSH's own construction** (two ChaCha20 instances, packet length encrypted separately, Poly1305 over the packet; *not* the IETF AEAD from the BCL)
3. `aes256-ctr`, `aes192-ctr`, `aes128-ctr` (CTR built on top of the BCL AES-ECB transform — the BCL has no CTR mode)
- No CBC/3DES/RC4.

### MACs (only relevant for CTR ciphers; GCM/ChaCha are implicit AEAD)
1. `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com` (encrypt-then-MAC preferred)
2. `hmac-sha2-256`, `hmac-sha2-512`
- No `hmac-sha1`/`-md5` (sha1 at most as opt-in compat).

### Compression
- `none` (default and only option in v1). `zlib@openssh.com` (delayed) as a later feature.

---

## 4. Cryptography Strategy on .NET 10

### What the BCL provides
- AES (ECB transform → CTR by hand), `AesGcm`, SHA-2 family, HMAC-SHA2, RSA (rsa-sha2 = RSASSA-PKCS1-v1_5 with SHA-256/512), ECDSA/ECDH on NIST curves, `RandomNumberGenerator`, `CryptographicOperations.FixedTimeEquals/ZeroMemory`, `PemEncoding`, PKCS#8 import/export
- **New in .NET 10: `System.Security.Cryptography.MLKem`** (FIPS 203), plus `MLDsa`/`SlhDsa`. Caveat: possibly still marked experimental (`SYSLIB5006`) and platform-dependent (Windows CNG with PQC support, or OpenSSL ≥ 3.5). → Spike task in M3: verify availability on the target platforms.

### What is missing → third-party library or self-built
| Gap | Solution |
|---|---|
| X25519, Ed25519 | **BouncyCastle** (`BouncyCastle.Cryptography` 2.x) |
| Raw ChaCha20 + Poly1305 (for the OpenSSH construction) | BouncyCastle primitives, construction built ourselves |
| sntrup761 | BouncyCastle (NTRU Prime) |
| ML-KEM fallback (where BCL/OS cannot) | BouncyCastle |
| `bcrypt_pbkdf` (encrypted openssh-key-v1 files) | small in-house implementation per OpenSSH spec (Blowfish from BC), with test vectors |
| AES-CTR | built on BCL AES-ECB (standard technique, easily testable) |

### Architectural decision
A central **provider abstraction** (`ISshCryptoProvider` + algorithm registry), default provider = "BCL first, BouncyCastle for the gaps". This keeps things swappable: a pure-BC variant (max portability), later a pure-BCL variant (if X25519/Ed25519 ever land in .NET), a FIPS-only profile, hardware-backed keys.

Principle: **no self-implemented crypto primitives** — in-house code only for modes/constructions (CTR, chacha20-poly1305@openssh.com, bcrypt_pbkdf, KDF), each validated against official test vectors.

---

## 5. Architecture & Project Structure

Following the conventions of the sibling projects (own git repo, `.slnx`, `net10.0`, `Nullable`, `ImplicitUsings`, `LangVersion latest`, block-scoped namespaces per the GraphDefined template, logging via `Microsoft.Extensions.Logging` + Serilog):

```
SSH/
├── SSH.slnx
├── libs/                       ← git submodules (same pattern as the sibling projects)
│   ├── Hermod/                 Vanaheimr Hermod — networking stack incl. DNS client (SSHFP!),
│   │                           TCP server infrastructure, PKI, logging
│   └── Styx/                   Vanaheimr Styx — base utilities (Illias)
├── HermodSSH.Core/            ← shared foundation; both client and server depend on it
│   ├── Core/                   wire format (reader/writer), constants, message numbers,
│   │                           name-list negotiation, error/disconnect codes
│   ├── Crypto/                 ISshCryptoProvider, KEX implementations (incl. PQ hybrid),
│   │                           cipher/MAC/AEAD, key derivation (KDF), registry
│   ├── Keys/                   SshPublicKey/SshPrivateKey (Ed25519/ECDSA/RSA), SshKeyGenerator,
│   │                           formats: openssh-key-v1 (+bcrypt_pbkdf), PKCS#8/PEM, RFC 4716,
│   │                           authorized_keys, known_hosts, OpenSshCertificate (+builder = mini-CA),
│   │                           revocation
│   ├── Transport/              version exchange, binary packet protocol (Pipelines), KEX state machine,
│   │                           rekeying, strict KEX, ext-info  (symmetric — shared by both roles)
│   ├── Connection/             channels + window/flow control, channel/global requests, NetworkAcl
│   ├── Sftp/                   SFTP protocol types (packets, attrs, status)  — shared
│   └── Audit/                  SshAuditEvent model + ISshAuditSink
├── HermodSSH.Client/          ← depends on Core
│   ├── SshClient, SshCommand, host key verification/policies, SshAgentClient, ProxyJump,
│   └── client auth methods, SftpClient, client-side forwarding
├── HermodSSH.Server/          ← depends on Core
│   ├── SshServer, auth pipeline (authorized_keys, certs, TOTP), access profiles, banner,
│   └── SftpSubsystem, ISftpFileSystem (local with root jail, in-memory), session recording
├── HermodSSHTests/             ← NUnit (unit, loopback, interop)
│   └── interop/                interop harness assets: scripts, Dockerfiles, peer configs
└── HermodSSHDemo/              ← CLI to set up a server and connect clients (references Client + Server)
```

`SSH.slnx` references the submodule projects in a `/Dependencies/` solution folder
(`libs/Hermod/Hermod/Hermod.csproj`, `libs/Styx/Styx/Styx.csproj`) — exactly like SMTPServer.

**Three packages** (`HermodSSH.Core` / `.Client` / `.Server`): the transport, crypto, keys and SFTP protocol are shared and live in **Core** (root namespace `org.GraphDefined.Vanaheimr.Hermod.SSH`, SFTP under `….SSH.SFTP`); the high-level client and server APIs live in **Client** (`….SSH.Client`) and **Server** (`….SSH.Server`), each depending only on Core. **BouncyCastle** (X25519/Ed25519/sntrup761/ChaCha20/…) plus Hermod's DNS/TCP/PKI/logging arrive **transitively through the `libs/Hermod` + `libs/Styx` submodule references on Core** — no direct package reference.

### Code conventions

Every `.cs` file follows the GraphDefined template (verbatim header in `CLAUDE.md`): Apache-2.0 license header (© 2010-2026 GraphDefined GmbH, "This file is part of Vanaheimr Hermod" — this repo is part of that ecosystem), `#region Usings` block, **block-scoped** namespace. Namespaces: `org.GraphDefined.Vanaheimr.Hermod.SSH` (library), `….SSH.SFTP` (SFTP), `….SSH.Tests` (NUnit), `….SSH.CLI` (demo). Project folders keep their names (`HermodSSH`, `HermodSSHTests`, `HermodSSHDemo`) with `<RootNamespace>` set accordingly. All code, XML docs, comments and commit messages in English.

### Layer model

```
┌────────────────────────────┬───────────────────────────────┐
│  SshClient  /  SftpClient  │   SshServer  /  SftpSubsystem │   high-level API
├────────────────────────────┴───────────────────────────────┤
│  Connection layer: channels, requests, flow control        │   RFC 4254
├────────────────────────────────────────────────────────────┤
│  Auth layer: methods (client) / pipeline (server)          │   RFC 4252
├────────────────────────────────────────────────────────────┤
│  Transport: version exchange, BPP, KEX, rekey, strict KEX  │   RFC 4253
├────────────────────────────────────────────────────────────┤
│  Crypto provider (BCL + BouncyCastle)  │  keys & certs     │
├────────────────────────────────────────────────────────────┤
│  System.IO.Pipelines over Socket / any IDuplexPipe         │
└────────────────────────────────────────────────────────────┘
```

The transport is built against `IDuplexPipe` (not directly against a socket) → loopback tests entirely without networking, easy unit testing, unusual transports possible. The listener/socket layer can optionally be hosted on Hermod's TCP server infrastructure (`libs/Hermod`, `TCP/`) — decide at the start of M0.

### Demo CLI (`HermodSSHDemo`)

A single `hermod-ssh` tool (System.CommandLine) that makes every feature runnable from a terminal — for
setting up a demo server and driving clients against it (or against real OpenSSH). Verbs grow with the
milestones; the intended surface:

- `keygen` — generate host/user keys (Ed25519/ECDSA/RSA), export any format (`SshKeyGenerator`)
- `serve` — run a demo server: choose host keys, auth methods (authorized_keys / password / **TOTP**),
  access **profiles** (`--sftp-upload-only <root>`, `--sftp-download-only <root>`), SFTP root, forwarding
  policy, **banner**, **session recording**, audit-to-console — the "set up a server" workflow
- `connect` / `exec` — log in, run a command, capture stdout/stderr + exit code, log out (with `-J` jump hosts)
- `sftp` — `get`/`put`/`ls` with progress
- `forward` — local/remote/`-J` tunnels driven from the CLI
- `ca` — issue user/host certificates (mini-CA), inspect them (`ssh-keygen -L`-style)
- `scan` — fetch a host's key / emit its SSHFP record (`ssh-keyscan` / `ssh-keygen -r` style)
- `play` — replay a recorded asciicast session

Doubles as living documentation and as a manual interop driver against `ssh`/`sshd`.

### Core abstractions (sketches)

```csharp
// Wire format — ref structs over Span/IBufferWriter, RFC 4251 §5
public ref struct SshPacketReader { /* ReadUInt32, ReadBoolean, ReadString,
                                       ReadMPInt, ReadNameList, … with hard length limits */ }
public ref struct SshPacketWriter { /* symmetric, over IBufferWriter<byte> */ }

// Algorithm registry — everything replaceable and extensible
public interface IKexAlgorithm       { string Name { get; }  Task<KexResult> ExchangeAsync(…, CancellationToken ct); }
public interface ISignatureAlgorithm { string Name { get; }  bool Verify(…);  byte[] Sign(…); }
public interface IPacketCipher       { /* AEAD and EtM/E&M framing, sequence numbers */ }

// Server side: delegates/handlers instead of inheritance
public sealed class SshServerOptions
{
    public required IReadOnlyList<SshPrivateKey>  HostKeys        { get; init; }   // incl. host certificates
    public required ISshUserAuthenticator         Authenticator   { get; init; }
    public Func<SshSession, ExecRequest,  CancellationToken, Task<ISshChannelHandler?>>? ExecHandler  { get; init; }
    public Func<SshSession, ShellRequest, CancellationToken, Task<ISshChannelHandler?>>? ShellHandler { get; init; }
    public ISftpFileSystem?                       SftpFileSystem  { get; init; }   // enables the SFTP subsystem
    public ISessionRecordingSink?                 Recording       { get; init; }   // asciicast/transcript recording (§7)
    public ISshAuditSink?                         AuditSink       { get; init; }   // typed audit event stream (§8)
    public Func<SshPeer, CancellationToken, Task<string?>>? AuthBanner { get; init; } // SSH_MSG_USERAUTH_BANNER (§6)
    public KeystrokeTimingObfuscation             KeystrokeTiming { get; init; } = KeystrokeTimingObfuscation.InteractiveDefault; // chaff (§9)
    public SshAlgorithmOptions                    Algorithms      { get; init; } = SshAlgorithmOptions.Default;
    public SshServerLimits                        Limits          { get; init; } = new();  // MaxAuthTries, LoginGraceTime, MaxSessions, IdleTimeout, ClientAliveInterval/CountMax, …
}
```

### Target API (a feel for usage)

```csharp
// Client
await using var client = await SshClient.ConnectAsync(
    "server.example.org", 22,
    new SshClientOptions {
        Username      = "achim",
        // Host key trust — ordered chain: pins → known_hosts → host-cert CA → SSHFP DNS → TOFU
        HostKeyPolicy = HostKeyPolicy.Pin("SHA256:hQ0tCUOTFRTM7hkfufR8jSyPCvKuz9r7CH1E7Vq0hkE") // ssh-keygen -lf format
                                     .OrKnownHosts(knownHostsPath)                  // understands @cert-authority too
                                     .OrSshfpDns(sshfpResolver, SshfpTrust.RequireDnssec) // e.g. Hermod-DNS adapter
                                     .OrInteractiveTofu(promptCallback),
        Credentials   = [
            SshCredential.Certificate("id_ed25519-cert.pub", "id_ed25519"),  // cert auth first-class
            SshCredential.PrivateKeyFile("id_ed25519", passphrase),
            SshCredential.Agent()                                            // ssh-agent (Windows named pipe / SSH_AUTH_SOCK)
        ],
        // Jump hosts (ssh -J): tunnel through one or more bastions; each hop has its own policy + credentials
        ProxyJump     = [ SshJumpHost.Parse("achim@bastion1:22"), SshJumpHost.Parse("bastion2") ],
        BannerCallback = (banner, lang) => Console.Error.Write(banner),      // surface SSH_MSG_USERAUTH_BANNER
    }, ct);

// Remote command execution (exec channel): log in once, run commands, capture everything, log out
var result = await client.ExecuteAsync("bash -lc 'uname -a && df -h'", ct);
// → result.ExitCode / result.ExitSignal, result.StandardOutput / result.StandardError (text + raw bytes)

await using var cmd = await client.StartCommandAsync(new SshCommand("wc -c") {
    Input                = dataStream,                    // piped to remote stdin
    EnvironmentVariables = { ["LANG"] = "C.UTF-8" },      // env requests (mind sshd's AcceptEnv)
    UsePty               = false                          // no PTY → stdout/stderr stay separate
}, ct);                                                   // streaming variant for long-running commands
await cmd.StandardOutput.CopyToAsync(localSink, ct);
var exitCode = await cmd.WaitForExitAsync(ct);            // exit-status — or exit-signal if killed
// plus SshCommandLine.Quote(…): safe POSIX-shell argument quoting for composed command lines

// Port forwarding (admin/debugging): -L equivalent + in-process tunnel stream
await using var fwd    = await client.StartLocalForwardAsync(
    new IPEndPoint(IPAddress.Loopback, 15432), "db.internal", 5432, ct);      // binds loopback by default
await using var tunnel = await client.OpenTcpStreamAsync("10.20.5.7", 443, ct); // direct-tcpip as a plain
                                                                                // Stream — no local listener

await using var sftp = await client.OpenSftpClientAsync(ct);
await sftp.UploadFileAsync(localPath, "/remote/file", new SftpTransferOptions { Progress = p }, ct);
await foreach (var entry in sftp.EnumerateDirectoryAsync("/remote", ct)) { … }

// Server
await using var server = new SshServer(new SshServerOptions {
    HostKeys      = [hostKey, hostCertKey],
    Authenticator = SshUserAuthenticator.Create(auth => auth
        .TrustUserCA(caPublicKey)                          // OpenSSH certificates
        .WithAuthorizedKeys(user => LoadAuthorizedKeys(user))   // entries carry optional NotBefore/NotAfter
        .WithPassword((user, pw, ct) => CheckPasswordAsync(user, pw, ct))
        .WithAccessProfile(user => user.Name switch {      // authorization: least privilege per account
            "logdrop"  => SshAccessProfile.SftpUploadOnly  ("D:\\logs\\{username}", allowOverwrite: false),
            "firmware" => SshAccessProfile.SftpDownloadOnly("D:\\firmware"),
            "admin"    => SshAccessProfile.Default with {
                              PortForwarding = ForwardingPolicy.LoopbackOnly,  // tunnel only to services on this host
                              RecordSessions = true                            // capture this profile's sessions (§7)
                          },
            _          => SshAccessProfile.Default
        })
        .WithSecondFactor(user =>                            // TOTP 2FA, e.g. only for admins
            user.Name == "admin" ? TotpValidator.Rfc6238(LoadTotpSecret(user)) : null)),
    SftpFileSystem = new LocalSftpFileSystem(root: "C:\\SftpRoot", readOnly: false),
    Recording      = new AsciicastRecordingSink("D:\\ssh-recordings"),  // + JSON sidecar per session
    AuthBanner     = (peer, ct) => Task.FromResult<string?>("Authorized use only. Sessions are recorded."),
    AuditSink      = new SerilogAuditSink(logger),                      // typed SshAuditEvent stream → SIEM
    ExecHandler    = HandleExecAsync
});
await server.StartAsync(new IPEndPoint(IPAddress.Any, 22), ct);
```

---

## 6. Authentication — Public Keys & Certificates (Core Feature)

### Client
- `publickey` with query-then-sign (wait for `SSH_MSG_USERAUTH_PK_OK`, only then sign); pick the signature algorithm from `server-sig-algs` (ext-info) — RSA keys **always** rsa-sha2
- Certificate auth: `*-cert-v01@openssh.com` as the PK algorithm, signing with the corresponding private key
- `ssh-agent` client: Windows named pipe `\\.\pipe\openssh-ssh-agent`, Unix `SSH_AUTH_SOCK`; lists keys **and** certificates, signs remotely (private key never leaves the agent)
- `password`, `keyboard-interactive`, `none` probe; multi-step auth via `SSH_MSG_USERAUTH_FAILURE partial success`
- Host key verification: ordered source chain, see below

### Host key verification: pinning, known_hosts, certificates, SSHFP

`HostKeyPolicy` is an ordered chain of sources; the first source that reaches a verdict wins:

1. **Explicit pins** — manual fingerprints straight in `SshClientOptions`, no files involved (`HostKeyPolicy.Pin(…)`):
   - `"SHA256:<base64>"` exactly as printed by `ssh-keygen -lf` and by OpenSSH on first connect (SHA-256 over the public-key wire blob, unpadded base64) — copy & paste friendly
   - full public keys: an `SshPublicKey` instance, a `known_hosts`/`authorized_keys`-style line, or a raw key blob (pinning the whole key — strongest form)
   - legacy hex MD5 (`aa:bb:…`): parse support behind an explicit opt-in only, discouraged
   - pins are per host pattern (host, `[host]:port`, wildcards); multiple pins per host = any-match (multi-key hosts: ed25519 + ecdsa + rsa)
2. **known_hosts** files (incl. hashed `|1|…`, `@cert-authority`, `@revoked`) + `KnownHosts.Append` helper to persist TOFU decisions
3. **Host certificates**: presented certificate validated against trusted CA keys (`TrustHostCA(…)` / `@cert-authority` entries)
4. **SSHFP via DNS** (below) — plain host keys only; cert-presenting hosts go through source 3
5. **TOFU / custom callback**: `HostKeyPolicy.Custom(async ctx => …)` receiving host key, all fingerprints (SHA-256/MD5), certificate details and remote endpoint — full control incl. "accept once" vs "accept & persist"; strict mode = chain without sources 4/5

Pins and known_hosts entries also steer the **host-key algorithm negotiation order** (as OpenSSH does): if an Ed25519 key is pinned/known for the host, `ssh-ed25519` moves to the front of our KEXINIT proposal so the server presents exactly that key.

### SSHFP DNS lookups (RFC 4255) — Hermod DNS integration

- SSHFP resource record (DNS type 44): `algorithm` (1 = RSA, 3 = ECDSA, 4 = Ed25519, 6 = Ed448; 2 = DSA legacy), `fp type` (2 = SHA-256, 1 = SHA-1 legacy), fingerprint over the host-key blob
- **Dependency seam:** HermodSSH defines a minimal `ISshfpResolver` — `ValueTask<SshfpLookupResult> QueryAsync(string host, CancellationToken ct)` returning the records **plus a `DnssecValidated` flag**. The SSH core takes no DNS dependency; a thin adapter binds it to the **Hermod DNS client from the `libs/Hermod` submodule** (raw type-44 query, or a registered custom SSHFP record type if the DNS client supports that). An in-process fake resolver serves the tests.
- **Trust model** (`SshfpTrust`): `Off` · `Advisory` (unvalidated SSHFP never auto-accepts — it only annotates the TOFU prompt) · `RequireDnssec` (auto-accept only when the resolver reports authenticated data — mirrors OpenSSH `VerifyHostKeyDNS yes` honoring the AD bit). SHA-256 records preferred; SHA-1-only records are at best advisory.
- **Tooling:** `SshfpRecord.FromHostKey(hostKey, hostname)` emits zone-file lines — the `ssh-keygen -r` equivalent — so our own server's records can be published; interop test pins byte-for-byte equality with `ssh-keygen -r`

### Server — auth pipeline
Pluggable backends behind `ISshUserAuthenticator`; policy: allowed methods, method chains (e.g. `publickey,password` as 2FA via partial success), `MaxAuthTries`, `LoginGraceTime`, uniform (timing-neutral) failure responses to prevent user enumeration.

- `authorized_keys` parser incl. options: `from=`, `command=`, `environment=`, `no-*`/`restrict`, **`cert-authority`**, **`principals=`**, plus **validity windows on plain keys**: `not-before="…"` / `not-after="…"` (HermodSSH extension) and `expiry-time="…"` (OpenSSH-compatible alias of not-after)
- **Key validity windows** — certificate-style `notBefore`/`notAfter` on every authorized key, settable programmatically (`new AuthorizedKey(key) { NotBefore = …, NotAfter = … }`, both optional) or in the file (accepted formats: OpenSSH `YYYYMMDD[HHMM[SS]][Z]` and ISO 8601). Semantics exactly as in certificates: `notBefore ≤ now < notAfter`, evaluated via `TimeProvider` **at authentication time only** (established sessions survive expiry, same as with certs). Outside the window ⇒ generic, timing-neutral auth failure on the wire; the server audit log records the real reason (expired / not yet valid). Portability note: stock `sshd` rejects lines with unknown options — `expiry-time=` is the portable subset, `not-before=` is our extension.
- `TrustedUserCAKeys` equivalent + `AuthorizedPrincipals` mechanism
- **Authorization result:** successful authentication yields an `SshAccessProfile` (via `WithAccessProfile`) attached to the session; effective rights = intersection of server profile ∧ `authorized_keys` options ∧ certificate critical options/extensions — the most restrictive source always wins (details in §7)

### Two-factor authentication (TOTP)

Real 2FA for admin accounts, built on the auth pipeline's existing partial-success chaining — the typical
policy is `publickey,keyboard-interactive`: a valid key/cert gets *partial* success, then a TOTP prompt
(RFC 4256 keyboard-interactive) must be answered before the session opens.

- **`WithSecondFactor(user => …)`** attaches an `ISshSecondFactor` requirement per account (or per access
  profile — e.g. only the `admin` profile needs it); accounts without it keep single-factor publickey
- **`ISshKeyboardInteractiveFactor` / `Totp`** — pluggable; the built-in provider is **standard RFC 6238
  TOTP** ✅ — base32 shared secret, 6/8 digits, HMAC-SHA1/256/512, 30 s step, ±1 step skew tolerance;
  compatible with Google Authenticator / Authy / YubiKey OATH / KeePassXC. `Totp.ProvisioningUri(...)` emits
  the `otpauth://totp/HermodSSH:user?secret=…&issuer=…` URI for QR provisioning. `TotpKeyboardInteractive`
  adapts it to the keyboard-interactive factor. (An SSH-session-bound variant could be added later as a
  standard HMAC-over-*H* construction — **not** via Hermod's `TOTPGenerator`, which is a separate e-mobility
  algorithm with a different alphabet.)
- **Hardening:** replay cache (a code is single-use within its window) ✅, attempt rate-limiting shared with
  `MaxAuthTries`, all comparisons `FixedTimeEquals`, clock via `TimeProvider` (skew + tests deterministic),
  secrets zeroized; the prompt/response text is excluded from session recording (§7)
- Interop: real OpenSSH `ssh` renders our keyboard-interactive prompt and submits the code; our client can
  likewise answer a keyboard-interactive challenge from a PAM/OTP-configured `sshd` (§11.3 #6)

### Authentication banner (`SSH_MSG_USERAUTH_BANNER`, RFC 4252 §5.4)

- **Server:** `AuthBanner` — a static string or `Func<SshPeer, CancellationToken, Task<string?>>` (per-peer,
  e.g. include source IP / time); sent during the authentication phase (the portable-sshd equivalent of
  `Banner`). Emits a `BannerSent` audit event. Independent of the SSH **identification-string** comment and of
  any post-auth MOTD (a shell/PTY concern, not this).
- **Client:** `BannerCallback(string text, string languageTag)` surfaces peer banners (legal notices); no
  callback ⇒ banner ignored safely. Banner text is untrusted peer data — length-capped, control characters
  sanitized before it can reach a terminal.

### Certificate validation (server, user cert) — mandatory check order
1. Parse the format (`PROTOCOL.certkeys`: nonce, pubkey, serial, type, key id, principals, validity, critical options, extensions, signature key, signature)
2. `type == user` (or `host` for host certs — mismatch ⇒ reject)
3. CA key is trusted (TrustedUserCAKeys / `cert-authority` entry); the CA key itself must **not** be a certificate
4. CA signature over the TBS data is valid (respect signature algorithm policy, e.g. enforce rsa-sha2)
5. `valid_after ≤ now < valid_before`
6. Login name ∈ `valid principals` (or an explicit principal mapping)
7. Evaluate critical options: `source-address` (CIDR match against peer IP), `force-command` (pass through to the session), **unknown critical option ⇒ reject**; unknown extensions ⇒ ignore; extensions (`permit-pty`, `permit-port-forwarding`, …) passed through as session permissions
8. Key/cert not revoked (v1: list of keys/serials/key IDs; binary KRL format as stretch goal)
9. Only then: verify the client's signature with the public key **embedded in the certificate**

### Key generation
`SshKeyGenerator`: create `ssh-ed25519`, `ecdsa-sha2-nistp256/384/521` and `ssh-rsa` (2048/3072/4096) key pairs (the `ssh-keygen -t` equivalent), export to openssh-key-v1 (optionally passphrase-encrypted via bcrypt_pbkdf), PKCS#8/PEM and RFC 4716, with fingerprints. Feeds the mini-CA and tests; the **server auto-generates missing host keys on first run** into its config directory (matching the sibling SMTPServer's first-run crypto pattern).

### Mini-CA
`OpenSshCertificateBuilder`: issue user/host certificates (equivalent of `ssh-keygen -s`), incl. all fields/options. Required for tests, useful as a product feature (e.g. short-lived certificates from an auth service).

---

## 7. SFTP, Access Control & Session Recording

**Version 3** (the de-facto standard, draft-ietf-secsh-filexfer-02) + OpenSSH extensions:
`posix-rename@openssh.com`, `statvfs@openssh.com`, `fsync@openssh.com`, `hardlink@openssh.com`, `limits@openssh.com`, `expand-path@openssh.com`, `copy-data`.

### Client
- Complete operations: open/read/write/close, stat/lstat/fstat/setstat, mkdir/rmdir/remove/rename, symlink/readlink, realpath
- `SftpFileStream` (a real `Stream` with seek), `UploadFileAsync`/`DownloadFileAsync` with progress
- **Pipelining** as the performance core: N parallel outstanding read/write requests (window e.g. 32–64 requests × 32–256 KiB), adopt limits from `limits@openssh.com`
- `IAsyncEnumerable<SftpEntry>` for directory listings

### Server
- SFTP as a built-in subsystem of `SshServer`
- `ISftpFileSystem` abstraction: `LocalSftpFileSystem` (root jail!) and `InMemorySftpFileSystem` (tests); custom backends (DB, blob storage, virtual) pluggable
- Request dispatcher with parallel processing but correct ordering guarantees per handle
- **Path canonicalization & traversal protection** (`SSH_FXP_REALPATH`, `..`, symlinks, Windows specifics: ADS, reserved names, `\` vs `/`) — dedicated negative test suite
- Version negotiation: we are v3; peers requesting v4–v6 must be answered correctly with v3 (see interop §11.3)

### Access profiles (server-side least privilege)

Authorization is a first-class server concept: authentication yields an `SshAccessProfile` per session
(§6), and everything the session attempts is checked against it — **default-deny**, most restrictive
source wins (server profile ∧ authorized_keys options ∧ certificate constraints).

- **`SshAccessProfile`** — session-level rights: shell / exec / PTY / port & agent forwarding / subsystems,
  optional forced command. The `SftpOnly…` presets deny everything except the SFTP subsystem — the
  machine-account pattern for devices.
- **`SftpPermissions`** — operation-level rights as `[Flags] SftpOperations` (Read, Write, Create, Overwrite,
  Delete, Rename, List, Stat, SetAttrs, Mkdir, Rmdir, Symlink, …) plus a **per-profile root jail** with
  `{username}` templating (e.g. `D:\logs\{username}` → per-device drop directories).
- **`SftpQuota` (quotas & bandwidth per profile)** — resource caps so a single account can't exhaust the host:
  - **Size caps:** `MaxFileSize`, `MaxBytesPerSession`, `MaxFileCount`, `MaxOpenHandles`; optional
    **directory-tree quota** (total bytes under the root jail, checked on write) for the log-drop case
  - **Bandwidth throttling:** per-session (and optional per-account, shared across sessions) upload/download
    byte-rate limits via a token-bucket `RateLimitedStream` — smooths device fleets hammering the firmware
    server; the presets take an optional `bandwidth:` argument
  - **Enforcement at the same central gate:** exceeding a size cap answers `SSH_FX_FAILURE` /
    `SSH_FX_QUOTA_EXCEEDED`-style status (v3 has no quota code → documented status + message), mid-write
    overruns stop cleanly and remove the partial file (upload) rather than leaving a truncated artifact;
    `limits@openssh.com` advertises our per-operation ceilings so well-behaved clients pre-chunk correctly
- **Ready-made profiles** (the two driving use cases):
  - `SshAccessProfile.SftpUploadOnly(root, allowOverwrite: false)` — **log upload**: allows `REALPATH`,
    `OPEN(CREATE|WRITE)`, `WRITE`, `CLOSE` (+ optional `MKDIR`, `STAT`, tolerated `SETSTAT` on the session's
    own handles); no reads, no directory listings (uploaders cannot see each other's files), no
    delete/rename; overwriting existing files is optional (default off → `SSH_FX_FAILURE` on collision)
  - `SshAccessProfile.SftpDownloadOnly(root)` — **firmware distribution**: allows `OPEN(READ)`, `READ`,
    `CLOSE`, `OPENDIR`/`READDIR`, `STAT`, `REALPATH`; every mutating operation denied
  - `SshAccessProfile.SftpReadWrite(root)` and `.Default` (full session per server options)
- **Enforcement point:** one central gate in the SFTP request dispatcher — every packet type (incl.
  extensions: `copy-data` = Read+Write, `fsync` = Write, `posix-rename` = Rename, `statvfs` = Stat,
  `limits` = always allowed) maps to required `SftpOperations`; denied requests answer
  `SSH_FX_PERMISSION_DENIED` and leave the session and all other handles fully intact.
- **Client-reality check** (pinned by interop tests): the standard `sftp put` sequence
  (`REALPATH → OPEN → WRITE → CLOSE [→ SETSTAT]`) must succeed under upload-only; common clients must see a
  clean "Permission denied" on forbidden operations — never hangs or dropped connections.

### Port forwarding & network ACLs (client + server)

Port forwarding is an essential admin/debugging feature — and the most dangerous one to leave wide open.
Both roles share one reusable rule engine:

**`NetworkAcl` rule engine**
- Ordered allow/deny rules, first match wins, configurable default — profiles default to **deny**
- Matchers: exact IP, CIDR (IPv4 + IPv6), hostname wildcard patterns, ports (single / ranges / sets)
- Presets: `NetworkAcl.LoopbackOnly` (127.0.0.0/8 + ::1), `NetworkAcl.PrivateNetworksOnly` (RFC 1918 +
  ULA fc00::/7 + link-local), `NetworkAcl.Subnet("10.20.0.0/16")`, `.To("db.internal", 5432)`,
  `.Ports(80, 443, 8000..8999)`
- **DNS-rebinding safe:** for `direct-tcpip` requests carrying hostnames, the ACL is evaluated against
  **all resolved addresses**, and exactly that resolution result is dialed (no re-resolve between check
  and connect); hostname-pattern rules are an opt-in addition, never the sole gate

**Server side** (`SshAccessProfile.PortForwarding`, a `ForwardingPolicy`)
- `direct-tcpip` (`ssh -L`, client tunnels *through* the server): destination ACL — e.g. loopback-only
  (only services on the SSH host itself), this-subnet-only, explicit host:port allowlist; the
  OpenSSH-equivalent of `PermitOpen` + `AllowTcpForwarding local`
- `tcpip-forward` (`ssh -R`, remote listen): listen ACL — permitted bind addresses (loopback vs any,
  `GatewayPorts` semantics) and port ranges (e.g. ≥ 1024 only, or an explicit set); equivalent of `PermitListen`
- Presets: `ForwardingPolicy.None` (default — and hard-off in the SFTP-only profiles), `.LoopbackOnly`,
  `.PrivateNetworks`, `.Subnet(…)`, `.Custom(acl)`
- Intersection as everywhere: profile ∧ `authorized_keys` (`permitopen=`/`permitlisten=`/`no-port-forwarding`)
  ∧ certificate (`permit-port-forwarding`) — most restrictive wins
- Every allow **and deny** decision is logged and metered — admins want to see refused attempts
- Denials answer `SSH_MSG_CHANNEL_OPEN_FAILURE` (`ADMINISTRATIVELY_PROHIBITED`) / request failure — the
  session stays healthy

**Client side**
- `StartLocalForwardAsync(localEndPoint, host, port)` / `StartRemoteForwardAsync(…)` → `IAsyncDisposable`
  handles with live stats; local listeners bind **loopback by default**, non-loopback binds are explicit opt-in
- `OpenTcpStreamAsync(host, port)` — a `direct-tcpip` channel as a plain `Stream` without any local listener
  (in-process tunneling for admin tooling: DB clients, HTTP calls through the jump host)
- The same `NetworkAcl` engine is available client-side to cap what local applications may request through
  a tunnel (relevant for the dynamic/SOCKS forward, which stays a stretch goal)

### Jump hosts / ProxyJump (client)

The everyday `ssh -J bastion target` admin pattern — reach a target that's only routable from a bastion.
Almost free here: the transport already runs on `IDuplexPipe`, so a hop is just **SSH-over-SSH**.

- `SshClientOptions.ProxyJump` = an ordered list of `SshJumpHost` (each `user@host:port` with its **own**
  `HostKeyPolicy` + `Credentials` — jump hosts are not more trusted than the target)
- Mechanism: connect + authenticate to hop 1, open a `direct-tcpip` channel to hop 2, wrap **that channel's
  `Stream` as the `IDuplexPipe`** for the next `SshClient`, repeat — the final client speaks end-to-end with
  the target, so **host-key verification and auth for the target happen through the tunnel** (the bastion
  never sees the target session's plaintext or credentials)
- Arbitrary chain depth; each hop is torn down in reverse on dispose; a failure at any hop reports which one
- `SshJumpHost.Parse("achim@bastion:22")` and a parser for the `-J host1,host2` comma syntax; reading it from
  `~/.ssh/config` (`ProxyJump`/`ProxyCommand`) stays parked with the config-reader
- Composes with everything downstream: exec, SFTP and even further local/remote forwards run over the
  tunneled connection unchanged

### Session recording (server-side, compliance & demos)

Opt-in per server (`Recording` sink) and gated per access profile (`RecordSessions`) — capture what happened
in a session in a replayable, tamper-evident-ish form.

- **`ISessionRecordingSink`** — pluggable target: `AsciicastRecordingSink` (files in a rotating directory),
  or custom (stream to blob storage / a SIEM / Hermod logging). One recording per channel, plus a per-session
  JSON **sidecar** (who: user + key fingerprint / cert key-id / principal; from where: peer endpoint; when:
  `DateTimeOffset` start/end; which access profile; session id; disconnect reason)
- **Formats:**
  - **PTY / shell** → **asciicast v2** (asciinema JSON-lines: header + `[elapsed, "o", data]` output events) —
    replayable with `asciinema play` or the web player; window size + resizes captured (`[t,"r","CxR"]`)
  - **exec** → asciicast (output) plus a header line with the exact command, argv and exit status/signal
  - **SFTP** → structured operation transcript (op, path, offset, length, result, `DateTimeOffset`) — not
    asciicast; enough to reconstruct exactly which bytes/paths a device touched (pairs with the upload/download
    profiles: a full audit trail of every firmware fetch and log drop)
- **Redaction is mandatory, not optional:** password and keyboard-interactive **inputs** (incl. TOTP codes)
  are never written; by default recording captures channel **output** (what a reviewer sees on replay), with
  input/keystroke capture as an explicit opt-in that still masks credential prompts
- **Streaming & bounded:** events flow to the sink incrementally via `PipeWriter`-style backpressure (never
  buffer a whole session in memory); size/time caps with rotation; a crash leaves a valid partial asciicast
- **Ties into the audit story:** the same events feed `System.Diagnostics.Metrics`/`ILogger`, so recording and
  live monitoring share one pipeline

---

## 8. Async, Performance & Observability

- Public API fully `Task`/`ValueTask` + `CancellationToken`; `IAsyncDisposable`; no sync-over-async; internal loops over `PipeReader`/`PipeWriter`
- Channel flow control = real backpressure (window ↔ `PipeWriter` flush), no unbounded buffering
- `Span<byte>`/`Memory<byte>` parsers, `ArrayPool`/`MemoryPool`, zero-copy where possible; wipe key material via `CryptographicOperations.ZeroMemory`, never pool buffers holding secrets
- `TimeProvider` instead of `DateTime.UtcNow`/`Task.Delay` → timeouts/rekey testable with `FakeTimeProvider`; **`DateTimeOffset` everywhere** (`DateTime` never appears in public API or models — certificate validity, key windows, timestamps; third-party `DateTime` values are converted at the boundary)
- **IPv6 is first-class, not an afterthought:** dual-stack listeners (`IPAddress.IPv6Any` with `DualMode`, or explicit v4+v6 binds), `IPAddress`/`IPEndPoint` (never string hosts) internally, IPv6 literals in known_hosts/`[host]:port` and forwarding targets, the `NetworkAcl` engine matches v4 **and** v6 CIDRs; loopback tests exercise `::1`
- Rekeying: after 1 GiB or 1 h (configurable), initiable from both sides, without blocking active channels
- Observability: `ILogger` (Serilog-compatible like the sibling projects), `System.Diagnostics.Metrics` (handshakes, active sessions, bytes, auth failures), optional `ActivitySource`
- Benchmarks (BenchmarkDotNet, separate project, not NUnit): handshake latency, throughput per cipher, SFTP throughput. Target: SFTP ≥ 100 MB/s loopback with AES-GCM

### Typed audit event stream

Free-text logs are for humans; **auditing is for machines**. Every security-relevant thing that happens emits
a strongly-typed event, so fleet operators can feed a SIEM without regex-parsing log lines.

- **`SshAuditEvent`** — an immutable record hierarchy, every event carrying a common envelope: monotonic
  sequence no., `DateTimeOffset`, connection id (correlates all events of one connection), peer endpoint, and
  the server/client role. Emitted by **both** roles.
- **Event catalog** (grows with the milestones): `ConnectionOpened`/`Closed`, `VersionExchanged`,
  `KexCompleted` (negotiated KEX/cipher/MAC/host-key alg + whether PQ/strict-KEX were used),
  `HostKeyAccepted`/`Rejected` (how it was trusted: pin/known_hosts/cert/SSHFP), `BannerSent`,
  `AuthAttempt` (method, key fingerprint / cert key-id / principal) → `AuthSucceeded` (with the assigned
  `SshAccessProfile`) / `AuthFailed` (**with the real, un-sanitized reason** — the wire stays timing-neutral,
  the audit log tells the truth: unknown user / bad key / expired key window / expired cert / wrong TOTP / …),
  `SessionOpened`/`Closed`, `ChannelOpened` (session/`direct-tcpip`/`tcpip-forward`), `ExecRequested`
  (command), `SubsystemRequested`, `SftpOperation` (op/path/bytes/result), `PolicyDenied`
  (ACL/profile/quota — what and why), `Rekeyed`, `LimitExceeded`, `Disconnected` (code + description).
- **`ISshAuditSink`** — pluggable: `SerilogAuditSink`/`ILoggerAuditSink` (structured properties, not string
  interpolation), an `IAsyncEnumerable<SshAuditEvent>` observer for in-process consumers, or a custom SIEM
  forwarder. **Never blocks the connection**: bounded queue with an explicit overflow policy (drop-oldest +
  a counter, or apply backpressure) — configurable, because dropping audit events is itself a security event.
- **One source of truth:** metrics counters, `ILogger` entries and session-recording sidecars are all derived
  from this event stream, so they can never disagree about what happened.

---

## 9. Security Hardening

- **Strict KEX** (Terrapin, CVE-2023-48795): send/detect the markers, sequence number reset at `SSH_MSG_NEWKEYS`, tolerate no foreign messages during KEX ⇒ immediate disconnect
- Hard limits: max packet size (payload ≤ 256 KiB, minimum support 35 000 bytes), name-list/mpint/string length caps, max channels/session, window clamps
- DoS: `LoginGraceTime`, `MaxAuthTries`, connection limits (MaxStartups semantics), optional per-source penalties
- **Connection liveness & timeouts** (both roles, `TimeProvider`-driven): keepalive probes via `keepalive@openssh.com` global requests that expect a reply; N consecutive unanswered probes ⇒ dead-peer disconnect (`ClientAliveInterval`/`ClientAliveCountMax` on the server, `ServerAliveInterval`/`ServerAliveCountMax` on the client). Separate **idle timeout** (no channel data for a configured span ⇒ disconnect). Both emit audit events (§8) and never fire while legitimate traffic flows — important for flaky device links
- Constant time: `FixedTimeEquals` for MAC/signature/password comparisons; identical response timing for "unknown user" vs "wrong key"
- Defensive parsers: validate all lengths before allocation, no unbounded growth, fuzzing-friendly (SharpFuzz as a stretch goal)
- Clear trust boundaries: everything from the peer is untrusted until MAC/AEAD-verified; auth decisions only from verified data
- Security review checklist as a gate before v1 (incl. running `/security-review` over the code base)

### Keystroke-timing obfuscation

In an interactive PTY session each keystroke is its own packet, so the encrypted inter-packet timing leaks
typing rhythm — enough to narrow down passwords (Song/Wagner/Tian 2001). Mitigation, matching OpenSSH ≥ 9.5:

- **`SSH_MSG_PING`/`SSH_MSG_PONG` (`ping@openssh.com`) — correctness first:** understand, answer and (when
  obfuscating) send these chaff packets. We must tolerate a peer's chaff from the moment interactive channels
  exist — so PING/PONG handling ships with the connection layer (M6), independent of our own obfuscation.
- **`KeystrokeTimingObfuscation` option** (both roles, default on for interactive PTY sessions like OpenSSH):
  while a PTY channel is active, real keystroke packets are sent on a **fixed cadence** (≈ 20 ms grid) and the
  gaps filled with chaff PINGs, so an observer sees a constant-rate stream instead of keystroke timing;
  the chaff stream stops shortly (~1 s) after typing pauses to bound overhead. Interval + enable configurable.
- **Scope & honesty:** protects interactive typing only (not bulk transfer, which isn't timing-sensitive that
  way); it is traffic-analysis mitigation, not perfect — documented as such.
- Uses `TimeProvider` for the cadence so tests are deterministic (`FakeTimeProvider`).

---

## 10. Testing Strategy (NUnit)

**Stack:** NUnit 4.x + `NUnit3TestAdapter` + `Microsoft.NET.Test.Sdk` + `NUnit.Analyzers` + `coverlet.collector`.
Async tests with `[CancelAfter(…)]` + `CancellationToken` parameter, `Assert.ThatAsync`, `TestCaseSource` for matrices. Categories: `Unit` (fast, deterministic, default), `Loopback`, `Interop` (see §11), `Slow`.

### 10.1 Unit tests (per layer, with test vectors)
- Wire format: mpint round-trips (leading zeros, sign handling, 0, maximum sizes), string/name-list/bool/uint64, error cases (truncated, oversized)
- KDF: key derivation A–F incl. the extension iteration, session ID constancy across rekeys — vectors cross-checked against OpenSSH
- Crypto: RFC 7748 vectors (X25519), RFC 8032 (Ed25519), NIST KATs (ML-KEM), OpenSSH regress vectors (chacha20-poly1305@openssh.com, bcrypt_pbkdf), Wycheproof (X25519, AES-GCM), our CTR against NIST SP 800-38A
- Negotiation: algorithm selection logic (RFC 4253 §7.1) incl. corner cases (no common algorithm, ext-info, strict-KEX markers, guessed KEX packets)
- Keys/formats: openssh-key-v1 (plain + bcrypt_pbkdf-encrypted), PKCS#8/PEM, RFC 4716, authorized_keys (all options), known_hosts (hashed, cert-authority, revoked, wildcards, ports)
- Key generation: `SshKeyGenerator` produces valid Ed25519/ECDSA/RSA keys, round-trips through every export format (openssh-key-v1 plain + bcrypt_pbkdf, PKCS#8/PEM, RFC 4716), fingerprints match; server first-run generates host keys once and reuses them
- Connection liveness: with FakeTimeProvider, N unanswered keepalive probes ⇒ dead-peer disconnect (and *not* one probe short); idle timeout fires only after true inactivity; legitimate traffic resets both timers
- IPv6: `NetworkAcl` v6 CIDRs, known_hosts/`[host]:port` with v6 literals, `IPEndPoint` parsing/formatting, loopback handshake over `::1`
- Authorized-key validity windows: parser round-trips (`not-before`/`not-after`/`expiry-time`, OpenSSH date formats incl. `Z` suffix + ISO 8601), decision matrix (no window / only notBefore / only notAfter / inside / before / after / exact boundary values — `notBefore ≤ now < notAfter`), FakeTimeProvider crossing the boundary (auth-time check only, established sessions unaffected)
- **Certificate suite** (focus area): valid / expired / not-yet-valid / wrong principal / foreign CA / tampered signature / unknown critical option ⇒ reject / unknown extension ⇒ accept / `source-address` violation / user cert used as host cert (and vice versa) / CA key is itself a cert / revoked — each from both client and server perspective
- SFTP: packet round-trips, attrs encoding, path canonicalization incl. traversal attacks
- SFTP access profiles: table-driven permission matrix — every SFTP packet type (incl. extensions) × profile (upload-only, download-only, read-write, custom) → expected allow/deny; per-profile root jails against traversal; intersection logic (profile ∧ authorized_keys options ∧ cert constraints)
- `NetworkAcl` engine: CIDR matching (IPv4/IPv6, edge prefixes /0 /32 /128), port ranges/sets, rule ordering & first-match, presets (loopback, private networks, subnet), hostname rules with a mock resolver, DNS-rebinding case (name resolves to allowed **and** disallowed addresses → deny)
- TOTP: **RFC 6238 official test vectors** (SHA-1/256/512), base32 secret round-trips, `otpauth://` URI generation, ±1 step skew window, replay rejection (same code twice → deny), FakeTimeProvider stepping across slots; Hermod session-bound variant: a code bound to session A is rejected under session B
- Session recording: asciicast v2 output parses back / plays (round-trip through a minimal asciicast reader), exec header carries command + exit status, SFTP transcript reconstructs the op sequence, **redaction**: password/keyboard-interactive/TOTP inputs never appear in the recording, partial (crash-truncated) recording is still valid
- Keystroke-timing obfuscation: with FakeTimeProvider, injected keystrokes at irregular intervals produce an output packet cadence that is ~constant (timing decorrelated from input); chaff present while "typing", stops after the idle timeout; `SSH_MSG_PING` → correct `SSH_MSG_PONG`
- SFTP quotas/bandwidth: size-cap decisions (`MaxFileSize`/`MaxBytesPerSession`/`MaxFileCount`/tree quota) at boundaries; token-bucket rate limiter throughput under FakeTimeProvider (asserted bytes-per-interval); mid-write overrun → clean stop + partial upload removed
- Audit events: envelope correctness (sequence, connection id correlation, `DateTimeOffset`), `AuthFailed` carries the real reason while the paired wire response is generic, sink overflow policy (drop-oldest increments the counter vs backpressure), structured-property serialization round-trip
- ProxyJump: `-J host1,host2` parsing + `SshJumpHost.Parse`, chain assembly order, per-hop policy isolation (a hop's `HostKeyPolicy` applies to that hop only)
- Auth banner: control-character/length sanitization of untrusted banner text before it can reach a terminal

### 10.2 Loopback integration tests (no networking)
Our client ↔ our server over an in-memory `IDuplexPipe`:
- **Full handshake matrix**: every KEX × cipher × MAC × host key format (TestCaseSource, cartesian) — every combination must establish a session + echo channel
- Auth flows positive/negative (key not authorized, key outside its validity window — not yet valid / expired, cert expired, wrong password, MaxAuthTries, partial-success chain)
- Exec semantics against an in-process command handler: exit-status vs exit-signal, stderr separation, stdin piping, binary-safe round-trips, output larger than the channel window, cancellation tears down the handler, parallel exec channels on one session
- Rekey mid-transfer (initiated from both sides), large transfers (> 1 GiB trigger via FakeTimeProvider/byte counters), cancellation at every point, abrupt disconnects, parallel channels
- SFTP round-trips on temp directories + in-memory FS, aborts mid-transfer, resume
- Access profiles end-to-end: an upload-only session can create + write, but READ/READDIR/REMOVE/RENAME return `SSH_FX_PERMISSION_DENIED`; download-only as the mirror image; denied operations leave the session and open handles healthy
- Port forwarding end-to-end against `ForwardingPolicy` profiles: allowed `direct-tcpip` targets reach an in-process echo server, denied targets get `CHANNEL_OPEN_FAILURE (ADMINISTRATIVELY_PROHIBITED)` with the session intact; `tcpip-forward` bind/port ACLs (denied binds → request failure); remote-forward round-trips; `OpenTcpStreamAsync` data integrity through the tunnel
- 2FA end-to-end: `publickey,keyboard-interactive` chain — key alone yields partial success, correct TOTP completes auth, wrong/expired/replayed code fails with attempts counted against `MaxAuthTries`; session-bound variant rejects a code minted for another session
- Recording end-to-end: an exec + a scripted PTY session produce valid asciicast files matching the actual I/O; an upload-only SFTP session yields a transcript listing exactly the writes; recording a 2FA login never captures the code
- ProxyJump end-to-end: our client reaches a target **through one and two in-process bastions**; the target's host key is verified end-to-end and a wrong-key bastion vs wrong-key target are distinguished; exec + SFTP work unchanged over the tunneled hop; disposing tears hops down in reverse
- Quotas/bandwidth end-to-end: an upload exceeding `MaxFileSize` fails cleanly with no partial file left; a throttled download's duration matches the configured rate (FakeTimeProvider); a full session's audit stream contains exactly the expected typed events in order
- Robustness: corrupted/truncated/oversized packets, wrong MAC, messages in the wrong state, Terrapin scenario (injected messages before NEWKEYS ⇒ abort)

### 10.3 Definition of Done per feature
A feature is done when: unit + loopback tests green, interop demonstrated against OpenSSH (and the peers listed for that milestone in §12), negative tests present, XML docs on the public API.

---

## 11. Interoperability Test Program

Interop is not an afterthought here — it is the primary acceptance mechanism. Principles:

- **OpenSSH is the reference.** The OpenBSD upstream project, consumed as portable OpenSSH under Linux (WSL2 + containers) and as Windows OpenSSH. Every feature must interop with it in **both roles** (our client ↔ their server, their client ↔ our server) before it counts as done.
- **Breadth catches what the reference forgives.** Independent implementations (PuTTY, Dropbear, TinySSH, Go, Python, Java, …) exercise different corners: minimal algorithm sets, different message ordering, vendor quirks.
- **Every quirk becomes a pinned test.** Any peer-specific behavior discovered (e.g. PuTTY's `winadj@putty.projects.tartarus.org` channel request) is recorded in a quirk registry document and covered by a regression test that simulates the quirk in-process — so the lesson survives even when the peer isn't installed.

### 11.1 Peer implementations & tiers

Feature columns reflect status at planning time (July 2026) — **re-verify when wiring each peer in.**

**Tier 1 — gating (run in CI on every merge; feature-complete matrix):**

| Peer | Roles vs us | Certs | PQ KEX | Notes |
|---|---|---|---|---|
| OpenSSH portable, current (≥ 10.x) | both | yes | mlkem768 + sntrup761 | primary reference; WSL2 + Docker |
| OpenSSH 9.9 / 9.6 / 8.9 (containers) | both | yes | varies | version spread: first-mlkem, first-strict-kex, pre-PQ negotiation fallback |
| Windows OpenSSH (`System32\OpenSSH`) | both | yes | per shipped version | native Windows path, agent named pipe |

**Tier 2 — automated matrix (nightly / on demand):**

| Peer | Roles vs us | Certs | PQ KEX | Why it matters |
|---|---|---|---|---|
| Dropbear (`dropbear`/`dbclient`) | both | no | sntrup761 (recent) | embedded-world defaults, small algo set, no ext-info corner cases |
| TinySSH (`tinysshd`) | server only | no | sntrup761 | radically minimal: ed25519 + chacha20 + sntrup761 only — forces our minimal-path negotiation |
| PuTTY `plink`/`psftp` (Windows + `putty-tools` on Linux) | client only | user certs (≥ 0.78) | sntrup761 (≥ 0.78), ML-KEM (≥ 0.83, verify) | independent lineage; famous quirks (`winadj@…`); exercises our **server** |
| AsyncSSH (Python) | both | yes (user+host, can also issue) | sntrup761, mlkem (recent, verify build) | most scriptable feature-rich peer; great for cert edge cases + SFTP v4–v6 negotiation |
| Paramiko (Python) | both | client-side certs (partial) | no (verify) | very widely deployed; conservative algorithm set |
| Go `x/crypto/ssh` (small test harness binaries) | both | yes (first-class) | mlkem768 (recent, verify) | strict, spec-literal implementation — catches sloppiness; harness sources live in `HermodSSHTests/interop/go/` |
| SSH.NET (NuGet) | client only, **in-process** | no | recent releases (verify) | runs directly inside NUnit — zero orchestration cost, fast server-role smoke tests |
| curl with libssh/libssh2 (SFTP) | client only | n/a | n/a | exercises our SFTP server through a completely different stack |

**Tier 3 — extended / periodic (weekly or manual, best effort):**

| Peer | Roles vs us | Notes |
|---|---|---|
| Apache MINA SSHD (Java) | both | enterprise Java ecosystems; cert support in recent versions; PQ via BC (verify) |
| libssh (0.11+) CLI examples | both | third C lineage besides OpenSSH/Dropbear |
| WinSCP (scripted via `winscp.com /script`) | client only | most popular Windows SFTP client (PuTTY-derived core) |
| FileZilla | client only | manual smoke test per release |
| wolfSSH, Russh (Rust), JSch (mwiede fork, Java) | varies | additional lineages, capabilities to verify; nice-to-have |
| **OpenBSD (native)** in a VM (Hyper-V/QEMU) | both | the literal upstream on its home OS — manual smoke per release, closes the "official OpenBSD SSH" loop :-) |
| Legacy OpenSSH (7.x/8.x containers) | both | validates our legacy opt-in policy + clean "no common algorithm" failures |

### 11.2 Environments

**WSL2 (primary local environment, explicitly in scope):**
- Ubuntu LTS distro with an idempotent setup script `HermodSSHTests/interop/setup-wsl.sh`: `openssh-server openssh-client dropbear-bin tinysshd putty-tools curl socat` + a Python venv with `asyncssh`/`paramiko` (+ optional Go toolchain for the x/crypto harness)
- Orchestration from NUnit via `wsl.exe -e …`; test instances only (no system sshd): `sshd -D -e -f <tempconfig>` as a non-root user on high ports, per-test host keys/`TrustedUserCAKeys`/`RevokedKeys`
- **Networking:** Windows → WSL works via `localhost` (localhostForwarding). WSL → Windows host needs the host IP (default route) in NAT mode — or enable `networkingMode=mirrored` in `.wslconfig` (Windows 11) so `localhost` works in both directions. The harness auto-detects both setups.
- **Key permission gotcha:** private keys on `/mnt/c` appear world-readable → OpenSSH refuses them. The harness always copies key material into the WSL home directory and `chmod 600`s it.
- `tinysshd` is inetd-style → run it under `socat`/systemd socket activation.

**Docker / Testcontainers (version matrix + CI):**
- Dockerfiles per peer+version under `HermodSSHTests/interop/docker/`; orchestrated from NUnit via the `Testcontainers` NuGet package
- Covers the OpenSSH version spread (8.9/9.6/9.9/10.x), Dropbear, TinySSH, MINA, AsyncSSH, libssh — reproducible locally and in CI (hosted CI runners have no WSL; containers provide the same peers there)

**Windows native:** Win32-OpenSSH (`ssh`, `sshd`, `sftp`, `ssh-keygen`, `ssh-agent` incl. the named-pipe agent), PuTTY `plink`/`psftp`, WinSCP CLI.

**In-process:** SSH.NET as a client against our in-process server — the cheapest cross-implementation signal, suitable even for the per-commit run.

### 11.3 Test dimensions (checklist per peer, where supported)

1. **Version exchange:** identification strings with comments, pre-banner lines, CRLF handling
2. **KEX:** every mutually supported method (incl. PQ hybrids); preference-order fallbacks; strict-KEX on/off peers; guessed-KEX packets; clean failure when no common algorithm
3. **Host keys:** every mutual algorithm; `server-sig-algs` honored (RSA keys must end up rsa-sha2); host certificates where supported
4. **Ciphers/MACs:** full sub-matrix vs OpenSSH; per-peer supported subset elsewhere; ETM vs E&M
5. **ext-info:** peers that send it, peers that don't
6. **Auth:** publickey per key type; certificates (issue with `ssh-keygen`, verify with peer — and vice versa); password; keyboard-interactive; partial-success chains; `MaxAuthTries` behavior; **TOTP 2FA**: real `ssh` renders our keyboard-interactive prompt and a code from a standard authenticator app (RFC 6238) completes `publickey,keyboard-interactive`; our client answers a keyboard-interactive challenge from an OTP-configured `sshd`; **auth banner**: our server's `SSH_MSG_USERAUTH_BANNER` shows up in the real `ssh` client, and our client surfaces a banner from an `sshd` configured with `Banner`
7. **Channels (plumbing):** shell with PTY (`pty-req`, `window-change`; scripted expect-style checks); window stress (tiny windows, huge bursts); parallel channels
8. **Remote command execution end-to-end** — the everyday "log in to a Linux box, run a bash command, capture the output, log out" workflow (the friendly kind of remote code execution, not the CVE kind). Runs with our client against real Linux sshds (WSL2 + containers), and mirrored against our server using `ssh`/`plink` as clients:
   - stdout capture (`uname -a`, `lsb_release -a`), stderr kept separate (`ls /nonexistent`), exit codes (`exit 42`, `false` → 1, command not found → 127)
   - exit-signal instead of exit-status (remote process killed → e.g. `KILL`, incl. core-dumped/error-message fields)
   - stdin piping (`wc -c` over 10 MiB), binary-safe `cat` round-trip — byte-identical output doubles as a whole-transport integrity check
   - large output with backpressure (≥ 256 MiB via `seq`/`dd`, bounded client memory), long-running command + cancellation (`sleep 300` → channel torn down, session stays usable, remote process verified gone)
   - parallel exec channels on one connection (vs sshd `MaxSessions`), env requests (`AcceptEnv` interplay), UTF-8 and deliberately invalid output bytes
   - PTY vs no-PTY exec semantics (merged output + CRLF translation vs separate streams — documented and asserted)
   - `SshCommandLine.Quote` round-trips: arguments with spaces, quotes, `$`, backticks, newlines survive the remote shell
   - Windows sshd as exec target (cmd.exe/PowerShell semantics, different quoting) — smoke level
9. **Port forwarding & ACLs:** real `ssh -L`/`-R` (and `plink`) against our server under different `ForwardingPolicy` profiles — allowed targets connect end-to-end, denied targets yield failures that real clients surface cleanly (no hangs, no drops); our client's forwards against `sshd` restricted via `PermitOpen`/`PermitListen`/`AllowTcpForwarding` (denials surfaced as clear errors); remote-forward round-trips in both directions
10. **Known global/channel-request quirks:** `winadj@putty.projects.tartarus.org` (must answer CHANNEL_FAILURE, not die), `no-more-sessions@openssh.com`, `hostkeys-00@openssh.com` after auth, `keepalive@openssh.com`, **`ping@openssh.com` (`SSH_MSG_PING`→`PONG`)** — respond correctly to unknown requests with/without `want_reply`; OpenSSH ≥ 9.5 sends keystroke-timing chaff by default → our client/server must accept it and interoperate with our own obfuscation on/off
11. **Rekey:** forced rekeys (`RekeyLimit 512K` on the peer / byte trigger on ours) mid-transfer, both directions
12. **SFTP:** against OpenSSH `sftp`/`sftp-server`, `psftp`, WinSCP, curl, AsyncSSH (which will ask for v4–v6 → must settle on v3 correctly); extensions (`limits@`, `posix-rename@`, `statvfs@`, `fsync@`, `copy-data`); large files, thousands of small files, weird filenames (UTF-8, spaces, quotes, newlines), resume, abort mid-transfer; **access profiles against real clients**: upload-only accepts `put` from the `sftp` CLI while `get`/`ls`/`rm` are cleanly denied, download-only serves `get`/curl while uploads are denied, WinSCP/`psftp` handle denials gracefully
13. **Disconnect semantics:** clean disconnect codes both ways; behavior on abrupt TCP resets
14. **Keepalives/timeouts:** `ServerAliveInterval`-style traffic must not confuse us
15. **Jump hosts / ProxyJump:** our client reaches a target `sshd` **through a real OpenSSH bastion** (`-J`), and a real `ssh -J our-server target` uses **our server as the bastion** (our `direct-tcpip` carries their inner session); two-hop chains; mixed vendors on the path (OpenSSH bastion → Dropbear target)

### 11.4 Certificate & key tooling interop (core-feature deep dive)

- **Key format round-trips with `ssh-keygen`:** every key type, openssh-key-v1 plain + passphrase-encrypted (bcrypt_pbkdf), PKCS#8, RFC 4716 — import theirs, export ours, `ssh-keygen -l`/`-y` agree on fingerprints; keys minted by our `SshKeyGenerator` authenticate against real `sshd`
- **IPv6 transport:** our client ↔ `sshd` and real `ssh` ↔ our server over IPv6 (`::1` and a v6 test address), known_hosts with v6 literals
- **Certificates, both directions:** (a) `ssh-keygen -s` issues → we authenticate with it and our server validates it; (b) our `OpenSshCertificateBuilder` issues → `sshd` accepts it and `ssh-keygen -L -f` pretty-prints it (external structural validator); AsyncSSH as a second independent cert validator/issuer
- **Server-side cert configs vs real `sshd`:** `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `RevokedKeys`, `cert-authority`/`principals=` in authorized_keys — same scenarios mirrored onto our server with the `ssh` CLI as client
- **`expiry-time` parity:** the same authorized_keys file with `expiry-time=` entries behaves identically under our server and `sshd` (accepted before the deadline, rejected after)
- **Host certificates:** `sshd` with `HostCertificate` → our client validates via `@cert-authority` known_hosts; our server presents a host cert → `ssh` with `@cert-authority` accepts it
- **SSHFP:** our zone-record generator vs `ssh-keygen -r` (identical output for every key type); client-side SSHFP verification E2E against the in-process fake resolver (DNSSEC flag on/off → auto-accept vs advisory-only)
- **Critical options end-to-end:** `force-command`, `source-address` (positive + violation), certs with unknown critical options must be rejected by both sides
- **KRL (stretch):** `ssh-keygen -k` generates KRLs → we honor them; `ssh-keygen -Q` cross-checks our revocation decisions
- **Agent:** OpenSSH agent on Windows (named pipe) and in WSL (`SSH_AUTH_SOCK`), keys + certs from the agent; Pageant optional
- **PPK (optional):** import PuTTY key files via `puttygen` round-trips

### 11.5 Harness architecture

- `InteropTestBase` with **environment discovery**: probes for `wsl.exe` + distro, Docker, native binaries (`ssh -V` parsing for version-dependent expectations); missing prerequisites ⇒ `Assert.Ignore` with a precise message — never red because a tool is absent, never silently green without running
- **Process orchestration:** temp `sshd_config`/`dropbear` args, dynamic high ports, startup readiness probes, hard timeouts, full peer logs (`sshd -ddd`, `plink -v`) captured and attached to failing tests via `TestContext.AddTestAttachment`, alongside our own packet trace
- **Category taxonomy:** `[Category("Interop")]` plus per-peer/per-environment (`Interop.OpenSSH`, `Interop.WSL`, `Interop.Docker`, `Interop.PuTTY`, …) and per-role (`ClientRole`/`ServerRole`) — arbitrary slicing via `dotnet test --filter`
- **Peer capability model:** a small declarative table per peer (supported KEX/ciphers/auth/SFTP versions per version) drives test generation — the matrix stays honest as peers evolve
- **Quirk registry:** `docs/INTEROP-QUIRKS.md`, one entry per discovered quirk (peer, version, behavior, our handling, link to the pinned in-process regression test)
- **Interop matrix report:** a small tool renders NUnit results into `docs/INTEROP-MATRIX.md` (peer × feature: pass/fail/n-a) — the living conformance statement of the project

### 11.6 CI strategy

- **Per commit:** unit + loopback + in-process SSH.NET smoke + one OpenSSH-current container round-trip (client and server role) — minutes, not hours
- **Nightly:** full Tier 1 + Tier 2 matrix on a Linux runner (containers + apt peers); Windows runner covers Win32-OpenSSH + plink
- **Weekly/manual:** Tier 3, incl. the native OpenBSD VM smoke test
- **Local dev box:** the full WSL2 suite (closest match to the "OpenSSH under Linux/WSL" requirement); `dotnet test --filter Category=Interop.WSL`

---

## 12. Milestones

| # | Status | Content | Acceptance (DoD) | Effort* |
|---|---|---|---|---|
| **M0** | ✅ | Repo/solution skeleton (`SSH.slnx`, **Core/Client/Server split** + Tests + Demo, Hermod/Styx referenced → BouncyCastle available), wire format (`SshPacketReader`/`Writer`, mpint & co.), message/disconnect constants, NUnit setup, demo-CLI scaffold, interop harness prereqs (`setup-wsl.sh`) | round-trip and error-case tests green (38 tests, incl. RFC 4251 §5 mpint vectors) ✅ | S |
| **M1** | ✅ | Minimal modern transport: version exchange, KEXINIT negotiation, `curve25519-sha256` + `ssh-ed25519` + `aes256-gcm@openssh.com`, NEWKEYS, KDF, **strict KEX from day one**, **dual-stack IPv6 listener** (`SshTcp`/`SshTcpListener`), OpenSSH interop test — loopback both roles ✅, TCP IPv4 + `::1` ✅, real OpenSSH client ↔ our server decrypts `SERVICE_REQUEST` ✅ (KEX+KDF+GCM match byte-for-byte). Residual interop breadth (our client ↔ real `sshd`; full WSL harness) tracked in the interop program | loopback handshake green (IPv4 + `::1`); handshake vs OpenSSH ✅ (server role) | L |
| **M2** | ✅ | Transport complete: rekeying, `chacha20-poly1305@openssh.com`, AES-CTR + EtM HMACs, `ecdh-nistp*`, `group14/16`, `rsa-sha2`, `ecdsa`, ext-info/`server-sig-algs` — **all done ✅**: chacha20-poly1305 (default), AES-CTR + HMAC-SHA2-ETM, ecdh-sha2-nistp256/384/521, diffie-hellman-group14-sha256/group16-sha512, ecdsa/rsa-sha2 host keys, rekeying (`SshTransport` + `RekeyAsync`, strict-KEX seq reset, stable session id), ext-info/server-sig-algs (`ExtInfoMessage`, server emits EXT_INFO after NEWKEYS). Cipher + KEX + host-key matrices green; OpenSSH interop across chacha20/gcm/ctr-etm × curve25519/nistp256/nistp521/group14/group16 × ed25519/ecdsa-nistp256/rsa-sha2-512, rekey loopback (both roles × 3 cipher families + peer-initiated), real `ssh` receives our EXT_INFO/server-sig-algs. (Non-ETM E&M HMACs intentionally omitted.) | full loopback matrix green; cipher/MAC sub-matrix vs OpenSSH ✅ | M–L |
| **M3** | ✅ | **PQ hybrid**: `mlkem768x25519-sha256` (BCL `MLKem`) + `sntrup761x25519-sha512` (+`@openssh.com`, BC sntrup761); `SshKeyExchange` generalised to client/server model for the asymmetric KEM flow, `SshKem` abstraction, **K-as-string encoding** (the interop trap). OpenSSH-validated: real `ssh` 10.2p1 completes both hybrids with our server through NEWKEYS (BC sntrup761 matches byte-for-byte); interop auto-picks a PQ-capable ssh (skips on Win-bundled 9.5). Loopback + unit + interop green | automated interop vs OpenSSH ≥ 9.9 (server role ✅; client role + TinySSH sntrup761 grow with the interop program) | M |
| **M4** | ✅ | **Auth + keys**: publickey (query-then-sign, server-sig-algs), **password**, **keyboard-interactive**, **TOTP 2FA** (`publickey,keyboard-interactive`, standard **RFC 6238**, replay cache, `otpauth://`), method chaining via partial success, **auth banner**, **typed audit stream** (`SshAuditEvent` + `ISshAuditSink`); key formats (openssh-key-v1 incl. bcrypt_pbkdf, PKCS#8/PEM RSA/ECDSA, RFC 4716) + **`SshKeyGenerator`** (+ first-run host key), authorized_keys/known_hosts (incl. **notBefore/notAfter validity windows**), host-key policy chain (fingerprint pinning, known_hosts, TOFU). OpenSSH-validated: real `ssh` auths with ssh-keygen ed25519/ecdsa/rsa keys; ssh-keygen reads our keys & we read its bcrypt-encrypted keys. **179 tests green.** (Remaining for later: our client ↔ real `sshd`, ssh-agent, Ed25519-PKCS#8, cert auth → M5.) | done ✅ (loopback + ssh-keygen/ssh interop) | L |
| **M5** | ✅ | **Certificates**: `SshCertificate` parser + `SshCertificateValidator` (full §6 check order: type, CA trust, CA signature, validity, principals, unknown-critical-option reject, revocation), `OpenSshCertificateBuilder` mini-CA (`ssh-keygen -s` equiv), **user cert auth** (`CertifiedKey` + `SshAuthenticationPolicy.WithCertificateAuthority`, cert-aware `SshSignature.Verify`), **host certificates** (`HostKeyPolicy.HostCertificate` / `@cert-authority`, cert host-key negotiation), revocation by serial/key-id/key. OpenSSH-validated: we verify+validate ssh-keygen's CA-signed certs; `ssh-keygen -L` reads our issued certs | done ✅ (loopback user+host cert auth, validator negative suite, ssh-keygen interop both directions). Later: binary KRL, source-address CIDR enforcement, AsyncSSH cross-check | L |
| **M6** | ✅ | Connection layer: **channels + window-based flow control, `exec`/`shell` + `pty-req`/`env` accept, `exit-status`, capture stdout/stderr ✅** (`SshConnection.ExecuteAsync` client + `ServeExecAsync` server + `SshExecContext`/`SshCommandResult`/`SshExecHandler`) — **the "log in, run a command, capture output, log out" core, OpenSSH-validated** (real `ssh user@host cmd` runs on our server, gets our output + exit code; loopback incl. 200 KiB multi-packet). **Streaming `SshCommand` ✅** (`SshConnection.StartCommandAsync` → `SshCommandProcess`: incremental stdout/stderr `Stream`s, piped stdin with channel flow control, `env`/`pty-req`, `WaitForExitAsync`; concurrent `ServeCommandAsync` server that consumes stdin as it streams). **Keepalive/idle timeouts ✅** (`SshLivenessMonitor` state machine — `ClientAlive*`/`ServerAlive*` equiv — driven by `TimeProvider`; `SshConnectionOptions` wires `keepalive@openssh.com` probing + dead-peer + idle-timeout into `SshCommandProcess`; `SSH_MSG_PING`/`PONG` handled). **Session recording ✅** (asciicast v2 `AsciicastWriter`/`AsciicastReader` — streaming, crash-truncation-tolerant; `SessionRecorder` output-only-by-default with input redaction, byte cap, `TimeProvider` timing; SFTP `SftpTranscriptRecorder`; `ISessionRecordingSink` → `InMemoryRecordingSink`/`DirectoryRecordingSink` + JSON metadata sidecar; teed into `ServeCommandAsync`). **`SshCommandLine.Quote` ✅** (POSIX-shell arg quoting). Deterministic liveness units (N probes, *not one short*; idle only on true inactivity; responsive-but-silent peer still times out); loopback streaming/keepalive + recording integration (asciicast matches actual I/O, exec header carries command+exit, SFTP transcript reconstructs ops, credentials/input never captured, partial recording still valid). ⬜ later: subsystem dispatch beyond SFTP, size/time rotation policies | remote-exec E2E ✅; streaming stdout/stdin + large-output loopback ✅; liveness deterministic + idle/keepalive integration ✅; recording round-trip + redaction + e2e ✅ | L |
| **M7** | ✅ | **SFTP v3 client + server done ✅** (`SftpClient` upload/download/list/stat/mkdir/remove/rename over a channel duplex; `SftpServer` dispatch to `ISftpFileSystem`; `InMemorySftpFileSystem`; `SftpProtocol`/`SftpFileAttributes`/`SftpStatusCode`; subsystem channels `SshConnection.Open/AcceptSubsystemAsync` + `SshChannelDuplex` flow control) — loopback upload/download (100 KiB multi-chunk) + list/rename/remove + error status green; **access profiles ✅** (`SshAccessProfile.SftpUploadOnly`/`SftpDownloadOnly` + `SftpPermissions` gate the server — log-upload / firmware-download presets); **`LocalSftpFileSystem` ✅** (real-disk backing with a **root jail**: `Path.GetFullPath` containment rejects `..`/absolute/drive escapes with `PermissionDenied`, `RandomAccess` offset I/O, optional read-only mode; unit traversal-containment + real-disk round-trip + wire loopback that lands bytes on disk). **Quotas & bandwidth ✅** (`SftpLimits`: `MaxFileSize`/`MaxBytesPerSession`/`MaxFileCount` + upload/download `TokenBucketRateLimiter` throttle, all `TimeProvider`-driven; `SftpQuotaTracker` rejects at the boundary and a mid-write overrun discards the partial upload + keeps the session healthy; wired into `SftpServer.ServeAsync(Limits:)`). **Extensions ✅** (`posix-rename@openssh.com` atomic replace, `fsync@openssh.com`, `statvfs@openssh.com` — surfaces the session quota as free space, `limits@openssh.com` — reports max packet/read/write + file-count as open-handle limit; advertised in VERSION, `SftpClient.ServerExtensions`/`Supports`/`PosixRenameAsync`/`StatVfsAsync`/`LimitsAsync`). **Pipelining ✅** (`SftpClient` refactored to a background reader + request-id correlation → many requests in flight; upload/download pipeline WRITE/READ over a 16-request window with short-read reassembly). **`SftpFileStream` ✅** (seekable client `Stream` over a remote file, offset-based READ/WRITE, `CopyToAsync`-friendly; `OpenFileStreamAsync`). **Server robustness ✅** (FSTAT via handle→path registry, SETSTAT/FSETSTAT accepted-and-ignored, channel EOF terminates the read + close handshake). **Real `sftp` interop ✅** (`OpenSshSftpInteropTests`: the OpenSSH `sftp` CLI puts + gets 40 KB against our `LocalSftpFileSystem` byte-for-byte, exercising INIT/VERSION/limits@/realpath/open/write/read/close/fstat/fsetstat). | loopback client↔server ✅ (in-memory + local FS); traversal jail ✅; quotas boundary + partial-discard ✅; token-bucket rate math deterministic ✅; extensions + pipelined 1 MiB + file-stream loopback ✅; **real `sftp` CLI put/get ✅** | L |
| **M8** | 🔶 | **`NetworkAcl` engine + `ForwardingPolicy` presets ✅** (first-match, default-deny; IPv4/IPv6 CIDR incl. /0../32/128, port ranges/sets, host wildcards; presets LoopbackOnly/PrivateNetworksOnly/Subnet; **DNS-rebinding safe** `AllowsAll`). **`direct-tcpip` + `OpenTcpStreamAsync` ✅** (`SshForwarding`: client tunnel as a plain `Stream` via `SshChannelStream`; ACL-gated server relay, denials → `CHANNEL_OPEN_FAILURE (ADMINISTRATIVELY_PROHIBITED)`, session stays healthy). **ProxyJump / jump-host chaining ✅** (`SshProxyJump.ConnectThroughAsync` = SSH-over-SSH via `DuplexPipe.FromStream` over a direct-tcpip tunnel; target host-key verify + auth end-to-end, bastion sees nothing; `SshJumpHost.Parse`/`ParseChain`; `SshTunneledConnection` reverse teardown). **ssh-agent client ✅** (`SshAgentClient` over Windows named pipe / `SSH_AUTH_SOCK`; `ListIdentities`/`Sign`; `SshAgentKey : ISshHostKey` → agent-backed publickey auth). **SSHFP DNS ✅** (`SshfpRecord.FromHostKey` = `ssh-keygen -r` equivalent, `ISshfpResolver`+`SshfpLookupResult` DNSSEC flag, `SshfpTrust` Off/Advisory/RequireDnssec, `SshfpVerifier` verdicts). **Connection multiplexer ✅** (`SshChannelMultiplexer` + `SshMuxChannel`: one receive loop demuxes to concurrent channels, window-credit-on-read decouples channels; open/accept, global requests, PING/rekey/DISCONNECT central) → **`tcpip-forward` (remote `-R`) ✅** (`SshRemoteForwarding`: server binds gated by `ForwardingPolicy.TcpIpForward`, opens `forwarded-tcpip` per inbound connection; client relays to a local target). ⬜ still: `hostkeys-00@openssh.com` (optional), Hermod-DNS `ISshfpResolver` adapter | ACL matrix ✅; direct-tcpip loopback (echo through tunnel + ACL denial) ✅; ProxyJump 1-hop exec-on-target + wrong-key-reject ✅; ssh-agent fake-loopback list/sign + agent-backed auth ✅ + real-agent interop; **SSHFP records match `ssh-keygen -r` byte-for-byte** (ed25519/ecdsa/rsa) ✅; **two concurrent exec channels on one connection** ✅; **remote `-R` echo through the server listener** ✅ | L |
| **M9** | 🔶 | **Audit catalog complete ✅** (full `SshAuditEvent` hierarchy + common envelope [seq/connId/peer/role], `SshAuditContext` stamping, non-blocking `BoundedAuditSink` with `AuditOverflowPolicy` drop-oldest/newest/block + drop counter). **Keystroke-timing obfuscation ✅** (`KeystrokeTimingObfuscator` — fixed-cadence real+chaff-PING, stops after idle window, `TimeProvider`-deterministic; `KeystrokeTimingObfuscation` options). **DoS/liveness config ✅** (`SshServerLimits` MaxAuthTries/LoginGraceTime/MaxSessions/MaxPacketSize/ClientAlive*/IdleTimeout → `CreateLivenessMonitor`). Strict-KEX / constant-time / length caps already land in M1–M6. ⬜ still: fuzz-light suite, security-review gate, nightly Tier-2 matrix + interop report generator (CI/process) | audit catalog tests (envelope/sequence/overflow) ✅; keystroke-timing decorrelation deterministic ✅; nightly matrix job = CI todo | M–L |
| **M10** | 🔶 | **Demo CLI ✅** (`hermod-ssh`: `keygen`/`scan`/`ca`/`exec`/`serve` working end-to-end — serve+exec verified across two processes; `connect`/`sftp`/`forward`/`play` planned). **README updated ✅** (feature status + CLI examples). XML docs land per file as written. ⬜ still: `connect`/`sftp`/`forward`/`play` verbs, NuGet packaging, BenchmarkDotNet baseline | demo keygen→scan→ca pipeline test ✅; serve+exec manual E2E ✅ | S–M |

\* Rough relations: S ≈ a few days, M ≈ 1–2 weeks, L ≈ 2–4 weeks (single person, focused). Realistic overall frame **5–7 months** including the extended interop program (the matrix infrastructure adds ~2–4 weeks spread across milestones); a working modern core (M0–M5: transport + PQ + keys + certs) is reachable around the halfway mark.

Ordering logic: first the **narrow modern path** (Ed25519 + Curve25519 + AES-GCM) to a working handshake, then broaden. Auth/certs (M4/M5) before the connection layer because they are the declared core feature and only require the transport. Interop harness grows with the features from M1 on — never as a big bang at the end.

---

## 13. Risks & Open Decisions

### Risks
| Risk | Mitigation |
|---|---|
| `System.Security.Cryptography.MLKem` platform-dependent / possibly experimental (SYSLIB5006) | spike in M3; BouncyCastle fallback designed in from the start |
| No X25519/Ed25519 in the BCL | BouncyCastle (established in this ecosystem); provider abstraction keeps a BCL migration path open |
| PQ hybrid interop traps (K encoded as string, hash choice) | dedicated test vectors + early OpenSSH ≥ 9.9 interop test |
| Managed chacha20-poly1305 is slow | AES-GCM as default; ChaCha as compatibility cipher |
| PTY/shell hosting in the server (ConPTY, Unix openpty) | protocol complete; hosting delegated to demo/extension |
| Self-built constructions (CTR, bcrypt_pbkdf, OpenSSH ChaCha construction) | only with official test vectors + interop proof |
| Interop matrix maintenance cost (peers evolve, CI time) | tiering (§11.1), per-commit smoke vs nightly matrix, capability tables per peer version |
| WSL not available on hosted CI runners | harness abstracts "how to reach a Linux shell": WSL locally, containers in CI — same peers either way |
| Scope creep (SSH is huge) | non-goals list, milestone gates, legacy only as opt-in |

### Open decisions (please confirm/decide)
1. ✅ **Naming — resolved (2026-07-23):** namespace `org.GraphDefined.Vanaheimr.Hermod.SSH` (+ `.SFTP`/`.Tests`/`.CLI`) with the GraphDefined Apache-2.0 file header on every `.cs` file (template in `CLAUDE.md`). Project folders stay `HermodSSH`/`HermodSSHTests`/`HermodSSHDemo` with `<RootNamespace>` set.
2. ✅ **Package split — resolved (2026-07-23):** three packages `HermodSSH.Core` / `.Client` / `.Server` (shared foundation in Core, high-level APIs in Client/Server), not one assembly.
3. ✅ **BouncyCastle — resolved (2026-07-23):** yes, used, and it arrives **transitively via the `libs/Hermod` + `libs/Styx` submodules** (both reference `BouncyCastle.Cryptography` 2.6.2) — Core references the submodules, no direct package needed.
4. ✅ **Demo CLI — resolved (2026-07-23):** yes, `HermodSSHDemo` is a wanted first-class deliverable for standing up a server and connecting clients (command design in §5). Scaffolded in M0, grows with the features, polished in M10.
5. ⬜ **CI provider** for the nightly interop matrix (GitHub Actions with Linux + Windows runners?) — repo is currently local-only
6. ⬜ Tier 3 peers: any that matter specifically to you (e.g. WinSCP because your users use it)? Commercial peers (Rebex) only if a license exists
7. ✅ **Hermod DNS integration — resolved (2026-07-23):** Vanaheimr Hermod + Styx are vendored as git submodules under `libs/` (internal `git.graphdefined.com` URLs, same as SMTPServer). The SSHFP adapter binds to the Hermod DNS client and lives in this repo; HermodSSH core still only depends on `ISshfpResolver`.

---

## 14. First Concrete Steps (M0)

0. ✅ Git repo on `master` + `.gitignore`, `libs/Hermod` & `libs/Styx` submodules, conventions (`CLAUDE.md`: file template, namespace)
1. ✅ Create `SSH.slnx` + `HermodSSH.Core`/`.Client`/`.Server` (net10.0) + `HermodSSHTests` (NUnit) + `HermodSSHDemo`, Hermod/Styx submodules referenced on Core, adopting the sibling-project conventions
2. ✅ Implement `Core/SshPacketReader|Writer` + constants (`SshMessageNumber`, `DisconnectReason`)
3. ✅ NUnit suite for the wire format incl. error cases (38 tests green)
4. ✅ Set up WSL prerequisites (`HermodSSHTests/interop/setup-wsl.sh`, idempotent, syntax-checked under WSL) so the M1 interop harness has a target from day one; `.gitattributes` keeps `*.sh` LF
5. ⬜ Then straight into M1: version exchange + KEXINIT, compared against a local OpenSSH server
