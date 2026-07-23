# HermodSSH — Implementation Plan

A modern SSH2 **client and server** implementation in C# / .NET 10 including **SFTP**,
fully **async**, with **post-quantum hybrid key exchange**, **public-key authentication**
and **OpenSSH certificates** as first-class features. Unit tests with **NUnit**.
Interoperability with OpenSSH and a broad set of third-party implementations is a
hard acceptance criterion (see §11).

**Status legend:** ✅ done · 🔶 partial · ⬜ open — markers are kept current as implementation proceeds.
**Current state (2026-07-23):** planning & repo scaffolding ✅ (git repo on `master`, `libs/Hermod` + `libs/Styx`
submodules, conventions in `CLAUDE.md`) — implementation ⬜, next up: M0 (solution, wire format, NUnit).

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
- Interoperability with OpenSSH (≥ 9.x, incl. Windows OpenSSH) and other major implementations as a hard acceptance criterion (full program in §11)
- Hardening: strict KEX (Terrapin mitigation), DoS limits, constant-time comparisons, key zeroization
- Fully `async`/`await`, `CancellationToken`, `IAsyncDisposable`, System.IO.Pipelines, Span/Memory

### Non-Goals (v1, kept open as extension points)

- SCP (OpenSSH itself runs SCP over SFTP these days), X11 forwarding, GSSAPI/Kerberos
- Connection multiplexing à la ControlMaster; compression (`zlib@openssh.com` later, optional)
- SSH1 and any legacy cryptography (CBC, 3DES, hmac-md5/sha1, DH group1, ssh-rsa/SHA-1 — at most as an explicit opt-in)
- Full interactive shell **hosting** in the server (protocol support yes: `pty-req`, `shell`, `exec`; actual PTY hosting via ConPTY only as a demo/extension)

---

## 2. Standards & References

| Area | Reference |
|---|---|
| Architecture / numbers | RFC 4251, RFC 4250 |
| Transport / KEX | RFC 4253, RFC 9142 (KEX update), RFC 8268 (DH-SHA2), RFC 5656 (ECDH/ECDSA), RFC 8731 (curve25519-sha256), RFC 4344 (CTR) |
| PQ hybrid KEX | draft-ietf-sshm-mlkem-hybrid-kex (`mlkem768x25519-sha256`; may have been published as an RFC by now → verify), OpenSSH `sntrup761x25519-sha512`, FIPS 203 (ML-KEM) |
| Auth | RFC 4252, RFC 4256 (keyboard-interactive), RFC 8332 (rsa-sha2), RFC 8709 (Ed25519), RFC 8308 (ext-info / server-sig-algs) |
| Connection | RFC 4254 |
| AEAD | RFC 5647 + OpenSSH semantics (`aes*-gcm@openssh.com`), OpenSSH `PROTOCOL.chacha20poly1305` |
| MACs | RFC 6668 (hmac-sha2), OpenSSH `-etm@openssh.com` |
| Certificates | OpenSSH `PROTOCOL.certkeys`, `PROTOCOL.krl` (revocation, stretch goal) |
| SFTP | draft-ietf-secsh-filexfer-02 (v3), OpenSSH `PROTOCOL` (extensions) |
| Key formats | OpenSSH `PROTOCOL.key` (openssh-key-v1 + bcrypt_pbkdf), PKCS#8, RFC 7468 (PEM), RFC 4716 |
| Agent | draft-miller-ssh-agent |
| SSHFP / DNS | RFC 4255 (SSHFP RR, type 44), RFC 6594 (SHA-256, ECDSA), RFC 7479 (Ed25519), IANA SSHFP registry (Ed448 = 6); DNSSEC validation as the trust anchor |
| Security | CVE-2023-48795 "Terrapin" → strict KEX (`kex-strict-c/s-v00@openssh.com`) |

Primary interop reference: **OpenSSH** — the OpenBSD upstream project, consumed as portable releases under Linux/WSL2 and as Windows OpenSSH (`C:\Windows\System32\OpenSSH`). Details and the full peer matrix in §11.

---

## 3. Algorithm Portfolio

Order = default preference. Everything configurable via an options object (enable/disable/reorder).

### Key Exchange
1. `mlkem768x25519-sha256` — PQ hybrid, OpenSSH default since 10.0
2. `sntrup761x25519-sha512` (+ alias `@openssh.com`) — PQ hybrid, OpenSSH default 9.0–9.9
3. `curve25519-sha256` (+ alias `@libssh.org`)
4. `ecdh-sha2-nistp256` / `-nistp384` / `-nistp521`
5. `diffie-hellman-group14-sha256` (MUST per RFC 9142), `diffie-hellman-group16-sha512`
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

Following the conventions of the sibling projects (own git repo, `.slnx`, `net10.0`, `Nullable`, `ImplicitUsings`, `LangVersion latest`, file-scoped namespaces, logging via `Microsoft.Extensions.Logging` + Serilog):

```
SSH/
├── SSH.slnx
├── libs/                       ← git submodules (same pattern as the sibling projects)
│   ├── Hermod/                 Vanaheimr Hermod — networking stack incl. DNS client (SSHFP!),
│   │                           TCP server infrastructure, PKI, logging
│   └── Styx/                   Vanaheimr Styx — base utilities (Illias)
├── HermodSSH/                  ← one library for client + server + SFTP
│   ├── Core/                   wire format (reader/writer), constants, message numbers,
│   │                           name-list negotiation, error/disconnect codes
│   ├── Crypto/                 ISshCryptoProvider, KEX implementations (incl. PQ hybrid),
│   │                           cipher/MAC/AEAD, key derivation (KDF), registry
│   ├── Keys/                   SshPublicKey/SshPrivateKey (Ed25519/ECDSA/RSA),
│   │                           formats: openssh-key-v1 (+bcrypt_pbkdf), PKCS#8/PEM, RFC 4716,
│   │                           authorized_keys, known_hosts, OpenSshCertificate (+builder = mini-CA),
│   │                           revocation
│   ├── Transport/              version exchange, binary packet protocol (Pipelines),
│   │                           KEX state machine, rekeying, strict KEX, ext-info
│   ├── Auth/                   client auth methods, server auth pipeline (policies, backends)
│   ├── Connection/             channels + window/flow control, channel/global requests,
│   │                           port forwarding, NetworkAcl rule engine
│   ├── Client/                 SshClient, SshCommand, host key verification, SshAgentClient
│   ├── Server/                 SshServer, session/handler model, limits
│   └── Sftp/                   protocol (packets, attrs, status), SftpClient, SftpSubsystem,
│                               ISftpFileSystem (+ local with root jail, + in-memory for tests)
├── HermodSSHTests/             ← NUnit (unit, loopback, interop)
│   └── interop/                interop harness assets: scripts, Dockerfiles, peer configs
└── HermodSSHDemo/              ← from M6: mini CLI — `exec` (remote command + output capture),
                                   `sftp` up-/download, `serve` (demo server)   [optional]
```

`SSH.slnx` references the submodule projects in a `/Dependencies/` solution folder
(`libs/Hermod/Hermod/Hermod.csproj`, `libs/Styx/Styx/Styx.csproj` + their test projects) — exactly like SMTPServer.

**One** assembly instead of a client/server split — transport, crypto, keys and the SFTP protocol are almost entirely shared. Root namespace `org.GraphDefined.Vanaheimr.Hermod.SSH` (client and server side by side, like other Hermod modules), SFTP under `….SSH.SFTP`. Can be split later if needed.

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
    public SshAlgorithmOptions                    Algorithms      { get; init; } = SshAlgorithmOptions.Default;
    public SshServerLimits                        Limits          { get; init; } = new();  // MaxAuthTries, LoginGraceTime, MaxSessions, …
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
        ]
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
                              PortForwarding = ForwardingPolicy.LoopbackOnly   // tunnel only to services on this host
                          },
            _          => SshAccessProfile.Default
        })),
    SftpFileSystem = new LocalSftpFileSystem(root: "C:\\SftpRoot", readOnly: false),
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

### Mini-CA
`OpenSshCertificateBuilder`: issue user/host certificates (equivalent of `ssh-keygen -s`), incl. all fields/options. Required for tests, useful as a product feature (e.g. short-lived certificates from an auth service).

---

## 7. SFTP & Server-Side Access Control

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

---

## 8. Async & Performance Guidelines

- Public API fully `Task`/`ValueTask` + `CancellationToken`; `IAsyncDisposable`; no sync-over-async; internal loops over `PipeReader`/`PipeWriter`
- Channel flow control = real backpressure (window ↔ `PipeWriter` flush), no unbounded buffering
- `Span<byte>`/`Memory<byte>` parsers, `ArrayPool`/`MemoryPool`, zero-copy where possible; wipe key material via `CryptographicOperations.ZeroMemory`, never pool buffers holding secrets
- `TimeProvider` instead of `DateTime.UtcNow`/`Task.Delay` → timeouts/rekey testable with `FakeTimeProvider`; **`DateTimeOffset` everywhere** (`DateTime` never appears in public API or models — certificate validity, key windows, timestamps; third-party `DateTime` values are converted at the boundary)
- Rekeying: after 1 GiB or 1 h (configurable), initiable from both sides, without blocking active channels
- Observability: `ILogger` (Serilog-compatible like the sibling projects), `System.Diagnostics.Metrics` (handshakes, active sessions, bytes, auth failures), optional `ActivitySource`
- Benchmarks (BenchmarkDotNet, separate project, not NUnit): handshake latency, throughput per cipher, SFTP throughput. Target: SFTP ≥ 100 MB/s loopback with AES-GCM

---

## 9. Security Hardening

- **Strict KEX** (Terrapin, CVE-2023-48795): send/detect the markers, sequence number reset at `SSH_MSG_NEWKEYS`, tolerate no foreign messages during KEX ⇒ immediate disconnect
- Hard limits: max packet size (payload ≤ 256 KiB, minimum support 35 000 bytes), name-list/mpint/string length caps, max channels/session, window clamps
- DoS: `LoginGraceTime`, `MaxAuthTries`, connection limits (MaxStartups semantics), optional per-source penalties
- Constant time: `FixedTimeEquals` for MAC/signature/password comparisons; identical response timing for "unknown user" vs "wrong key"
- Defensive parsers: validate all lengths before allocation, no unbounded growth, fuzzing-friendly (SharpFuzz as a stretch goal)
- Clear trust boundaries: everything from the peer is untrusted until MAC/AEAD-verified; auth decisions only from verified data
- Security review checklist as a gate before v1 (incl. running `/security-review` over the code base)

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
- Authorized-key validity windows: parser round-trips (`not-before`/`not-after`/`expiry-time`, OpenSSH date formats incl. `Z` suffix + ISO 8601), decision matrix (no window / only notBefore / only notAfter / inside / before / after / exact boundary values — `notBefore ≤ now < notAfter`), FakeTimeProvider crossing the boundary (auth-time check only, established sessions unaffected)
- **Certificate suite** (focus area): valid / expired / not-yet-valid / wrong principal / foreign CA / tampered signature / unknown critical option ⇒ reject / unknown extension ⇒ accept / `source-address` violation / user cert used as host cert (and vice versa) / CA key is itself a cert / revoked — each from both client and server perspective
- SFTP: packet round-trips, attrs encoding, path canonicalization incl. traversal attacks
- SFTP access profiles: table-driven permission matrix — every SFTP packet type (incl. extensions) × profile (upload-only, download-only, read-write, custom) → expected allow/deny; per-profile root jails against traversal; intersection logic (profile ∧ authorized_keys options ∧ cert constraints)
- `NetworkAcl` engine: CIDR matching (IPv4/IPv6, edge prefixes /0 /32 /128), port ranges/sets, rule ordering & first-match, presets (loopback, private networks, subnet), hostname rules with a mock resolver, DNS-rebinding case (name resolves to allowed **and** disallowed addresses → deny)

### 10.2 Loopback integration tests (no networking)
Our client ↔ our server over an in-memory `IDuplexPipe`:
- **Full handshake matrix**: every KEX × cipher × MAC × host key format (TestCaseSource, cartesian) — every combination must establish a session + echo channel
- Auth flows positive/negative (key not authorized, key outside its validity window — not yet valid / expired, cert expired, wrong password, MaxAuthTries, partial-success chain)
- Exec semantics against an in-process command handler: exit-status vs exit-signal, stderr separation, stdin piping, binary-safe round-trips, output larger than the channel window, cancellation tears down the handler, parallel exec channels on one session
- Rekey mid-transfer (initiated from both sides), large transfers (> 1 GiB trigger via FakeTimeProvider/byte counters), cancellation at every point, abrupt disconnects, parallel channels
- SFTP round-trips on temp directories + in-memory FS, aborts mid-transfer, resume
- Access profiles end-to-end: an upload-only session can create + write, but READ/READDIR/REMOVE/RENAME return `SSH_FX_PERMISSION_DENIED`; download-only as the mirror image; denied operations leave the session and open handles healthy
- Port forwarding end-to-end against `ForwardingPolicy` profiles: allowed `direct-tcpip` targets reach an in-process echo server, denied targets get `CHANNEL_OPEN_FAILURE (ADMINISTRATIVELY_PROHIBITED)` with the session intact; `tcpip-forward` bind/port ACLs (denied binds → request failure); remote-forward round-trips; `OpenTcpStreamAsync` data integrity through the tunnel
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

1. **Version exchange:** banners with comments, pre-banner lines, CRLF handling
2. **KEX:** every mutually supported method (incl. PQ hybrids); preference-order fallbacks; strict-KEX on/off peers; guessed-KEX packets; clean failure when no common algorithm
3. **Host keys:** every mutual algorithm; `server-sig-algs` honored (RSA keys must end up rsa-sha2); host certificates where supported
4. **Ciphers/MACs:** full sub-matrix vs OpenSSH; per-peer supported subset elsewhere; ETM vs E&M
5. **ext-info:** peers that send it, peers that don't
6. **Auth:** publickey per key type; certificates (issue with `ssh-keygen`, verify with peer — and vice versa); password; keyboard-interactive; partial-success chains; `MaxAuthTries` behavior
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
10. **Known global/channel-request quirks:** `winadj@putty.projects.tartarus.org` (must answer CHANNEL_FAILURE, not die), `no-more-sessions@openssh.com`, `hostkeys-00@openssh.com` after auth, `keepalive@openssh.com` — respond correctly to unknown requests with/without `want_reply`
11. **Rekey:** forced rekeys (`RekeyLimit 512K` on the peer / byte trigger on ours) mid-transfer, both directions
12. **SFTP:** against OpenSSH `sftp`/`sftp-server`, `psftp`, WinSCP, curl, AsyncSSH (which will ask for v4–v6 → must settle on v3 correctly); extensions (`limits@`, `posix-rename@`, `statvfs@`, `fsync@`, `copy-data`); large files, thousands of small files, weird filenames (UTF-8, spaces, quotes, newlines), resume, abort mid-transfer; **access profiles against real clients**: upload-only accepts `put` from the `sftp` CLI while `get`/`ls`/`rm` are cleanly denied, download-only serves `get`/curl while uploads are denied, WinSCP/`psftp` handle denials gracefully
13. **Disconnect semantics:** clean disconnect codes both ways; behavior on abrupt TCP resets
14. **Keepalives/timeouts:** `ServerAliveInterval`-style traffic must not confuse us

### 11.4 Certificate & key tooling interop (core-feature deep dive)

- **Key format round-trips with `ssh-keygen`:** every key type, openssh-key-v1 plain + passphrase-encrypted (bcrypt_pbkdf), PKCS#8, RFC 4716 — import theirs, export ours, `ssh-keygen -l`/`-y` agree on fingerprints
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
| **M0** | 🔶 | Repo/solution skeleton (`SSH.slnx`, 2–3 projects, sibling-project conventions), wire format (reader/writer, mpint & co.), NUnit setup — git repo, submodules & conventions ✅; solution, wire format, NUnit ⬜ | round-trip and error-case tests green | S |
| **M1** | ⬜ | Minimal modern transport: version exchange, KEXINIT negotiation, `curve25519-sha256` + `ssh-ed25519` + `aes256-gcm@openssh.com`, NEWKEYS, KDF, disconnect, **strict KEX from day one**; interop harness skeleton (env discovery, process orchestration, WSL bridge) | loopback handshake green; scripted handshake vs OpenSSH under WSL, both roles | L |
| **M2** | ⬜ | Transport complete: rekeying, `chacha20-poly1305@openssh.com`, AES-CTR + EtM HMACs, `ecdh-nistp*`, `group14/16`, `rsa-sha2`, `ecdsa`, ext-info/`server-sig-algs` | full loopback matrix green; cipher/MAC sub-matrix vs OpenSSH | M–L |
| **M3** | ⬜ | **PQ hybrid**: spike "MLKem availability .NET 10 on Win/Linux", then `mlkem768x25519-sha256` (BCL, BC fallback) + `sntrup761x25519-sha512` (BC); K-as-string encoding | automated interop vs OpenSSH ≥ 9.9 (both roles) + TinySSH (sntrup761) + plink ML-KEM against our server | M |
| **M4** | ⬜ | **Auth + keys**: publickey flow both sides (all key types), key formats (openssh-key-v1 incl. bcrypt_pbkdf, PKCS#8/PEM, RFC 4716), authorized_keys/known_hosts (incl. **notBefore/notAfter validity windows** on authorized keys), server auth pipeline, password/keyboard-interactive, host key policies (explicit fingerprint pinning via `SshClientOptions`, known_hosts, TOFU chain) | interop auth both roles with ssh-keygen material; Dropbear + Paramiko/AsyncSSH auth round-trips | L |
| **M5** | ⬜ | **Certificates**: parser/validator (check chain from §6), `CertificateBuilder` (mini-CA), client cert auth, server CA trust + principals + critical options, host certificates, revocation list | full §11.4 cert program vs OpenSSH (`ssh-keygen -L` validates our certs) + AsyncSSH as second validator; full negative suite | L |
| **M6** | ⬜ | Connection layer: channels + flow control, `exec`/`shell`/`pty-req`/`env`/`exit-status`/`window-change`, subsystem dispatch, keepalives; **`SshCommand` API** (capture + streaming, stdin, env, PTY toggle, exit-status/exit-signal, `SshCommandLine.Quote`) | remote-exec E2E suite (§11.3 #8) green vs WSL/container sshds; `ssh` CLI and `plink` execute against our server (incl. winadj quirk pinned) | L |
| **M7** | ⬜ | **SFTP** v3 client + server + extensions, pipelining, `ISftpFileSystem` (local with root jail, in-memory); **access profiles** (`SshAccessProfile`/`SftpPermissions`, upload-only & download-only presets, central default-deny gate) | `sftp` CLI + `psftp` + curl against our server; our client vs `sftp-server` across the OpenSSH version spread; v4–v6 downgrade vs AsyncSSH; profile permission matrix green incl. real-client denial behavior; throughput benchmark; traversal suite green | L |
| **M8** | ⬜ | Forwarding (`direct-tcpip`, `tcpip-forward`, `OpenTcpStreamAsync`) with **`NetworkAcl` engine + `ForwardingPolicy` presets** (loopback-only, private-networks, subnet), ssh-agent client, **SSHFP DNS** (`ISshfpResolver` + Hermod-DNS adapter, `SshfpTrust` modes, zone-record generator), `hostkeys-00@openssh.com` (optional) | ACL permission matrix green; real `ssh -L/-R` vs our ACL'd server (clean denials) and our forwards vs `PermitOpen`-restricted sshd; loopback + interop proof (OpenSSH agent on Windows pipe and WSL socket); SSHFP generator matches `ssh-keygen -r`; resolver E2E with DNSSEC on/off | M–L |
| **M9** | ⬜ | Hardening + full interop program: DoS limits, robustness/fuzz-light suite, timing review, security review checklist; Tier 2 matrix automated nightly, quirk registry + interop matrix report generator | all gates green; nightly matrix job runs; `docs/INTEROP-MATRIX.md` generated | M–L |
| **M10** | ⬜ | Polish: complete XML docs, README + samples, demo CLI (`exec` = log in / run command / capture output / log out, `sftp` transfers, `serve` = demo server mapping exec to local processes), optional NuGet packaging, BenchmarkDotNet baseline | release v1 | S–M |

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
2. ⬜ **One assembly** (client+server+SFTP, proposal) vs. split into Core/Client/Server packages?
3. ⬜ **BouncyCastle as a dependency** — ok? (Alternative: implement everything in-house = far more effort + crypto risk — not recommended.) Note: `libs/Hermod` already references `BouncyCastle.Cryptography`, so BC is in the dependency tree anyway — this is only about direct use.
4. ⬜ Demo CLI (`HermodSSHDemo`) wanted, or library only?
5. ⬜ **CI provider** for the nightly interop matrix (GitHub Actions with Linux + Windows runners?) — repo is currently local-only
6. ⬜ Tier 3 peers: any that matter specifically to you (e.g. WinSCP because your users use it)? Commercial peers (Rebex) only if a license exists
7. ✅ **Hermod DNS integration — resolved (2026-07-23):** Vanaheimr Hermod + Styx are vendored as git submodules under `libs/` (internal `git.graphdefined.com` URLs, same as SMTPServer). The SSHFP adapter binds to the Hermod DNS client and lives in this repo; HermodSSH core still only depends on `ISshfpResolver`.

---

## 14. First Concrete Steps (M0)

0. ✅ Git repo on `master` + `.gitignore`, `libs/Hermod` & `libs/Styx` submodules, conventions (`CLAUDE.md`: file template, namespace)
1. ⬜ Create `SSH.slnx` + `HermodSSH` (classlib, net10.0) + `HermodSSHTests` (NUnit), adopting the sibling-project conventions
2. ⬜ Implement `Core/SshPacketReader|Writer` + constants (`SshMessageNumber`, disconnect codes)
3. ⬜ NUnit suite for the wire format incl. error cases
4. ⬜ Set up WSL prerequisites (`setup-wsl.sh`) so the M1 interop harness has a target from day one
5. ⬜ Then straight into M1: version exchange + KEXINIT, compared against a local OpenSSH server
