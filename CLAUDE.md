# HermodSSH — Repository Conventions

Modern SSH2 client + server + SFTP implementation for .NET 10. The full implementation plan
(architecture, algorithms, milestones, interop program) lives in [PLAN.md](PLAN.md).

## C# file template (mandatory for every `.cs` file)

Every source file starts with this header **verbatim** (the "part of Vanaheimr Hermod" line is
intentional — this repository is part of the Vanaheimr Hermod ecosystem), followed by a
`#region Usings` block and a **block-scoped** namespace:

```csharp
/*
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    // ...

}
```

## Namespaces

**The SSH implementation lives in the `libs/Hermod` submodule** (moved there 2026-08-11): it is a folder
of the `Hermod` project, exactly like `DNS/`, `HTTP/`, `SMTP/` and `TCP/`, and ships in the
`org.GraphDefined.Vanaheimr.Hermod` assembly. This repository is the conformance harness around it.

| Location | Area | Namespace |
|---|---|---|
| `libs/Hermod/Hermod/SSH/`         | Foundation (wire format, crypto, keys, transport, connection) | `org.GraphDefined.Vanaheimr.Hermod.SSH` |
| `libs/Hermod/Hermod/SSH/SFTP/`    | SFTP protocol types | `org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP` |
| `libs/Hermod/Hermod/SSH/Client/`  | High-level client API | `org.GraphDefined.Vanaheimr.Hermod.SSH.Client` |
| `libs/Hermod/Hermod/SSH/Server/`  | High-level server API | `org.GraphDefined.Vanaheimr.Hermod.SSH.Server` |
| `libs/Hermod/HermodTests/SSH/`    | **Hermetic** tests: unit + loopback, no external software | `org.GraphDefined.Vanaheimr.Hermod.SSH.Tests` |
| `HermodSSHDemo/`                  | Demo CLI | `org.GraphDefined.Vanaheimr.Hermod.SSH.CLI` |
| `HermodSSHTests/interop/`         | **Conformance** tests: real peers (OpenSSH, Dropbear, TinySSH, AsyncSSH, Paramiko, SSH.NET) | `org.GraphDefined.Vanaheimr.Hermod.SSH.Tests` |
| `HermodSSHTests/CLI/`             | Demo-CLI tests | `org.GraphDefined.Vanaheimr.Hermod.SSH.Tests` |
| `HermodSSHBenchmarks/`            | BenchmarkDotNet suite | `org.GraphDefined.Vanaheimr.Hermod.SSH.Benchmarks` |
| `HermodSSHInteropReport/`         | TRX → interop-matrix generator | `org.GraphDefined.Vanaheimr.Hermod.SSH.InteropReport` |

Layering inside `SSH/`: `Client/` → foundation ← `Server/` (Client and Server never reference each other) —
now a source convention rather than an assembly boundary. **BouncyCastle** (2.7.0) and Hermod's
DNS/TCP/PKI/logging are available directly — do **not** add a direct `BouncyCastle.Cryptography` package.

**Which suite does a test belong to?** If it needs nothing but the code — a unit test, a loopback
round-trip between our own client and server — it belongs in the submodule, where Hermod's suite must
stay runnable anywhere. If it needs software the machine has to provide — WSL, an `ssh` binary, a Python
environment, a NuGet peer — it belongs in `HermodSSHTests/interop/`. That is the whole point of this
repository, and it keeps Hermod's own suite hermetic.

Because the library and its hermetic tests live in the submodule, a change to either usually means **two
commits** (submodule first, then the pointer bump here) — see the push order in [PLAN.md](PLAN.md) §13.5.

## Other conventions

- `net10.0`, `Nullable` + `ImplicitUsings` enabled, `LangVersion latest`
- Everything async: `Task`/`ValueTask` + `CancellationToken` throughout, `IAsyncDisposable`, no sync-over-async
- **`DateTimeOffset` instead of `DateTime` wherever possible** (public API, models, file parsers); current
  time only via `TimeProvider.GetUtcNow()` (returns `DateTimeOffset`); where a third-party API forces
  `DateTime` (e.g. BouncyCastle), convert at that boundary and keep it out of our types
- Tests with NUnit 4.x (`[CancelAfter]` on async tests); categories `Unit` / `Loopback` / `Interop` / `Slow`
- English for all code, XML docs, comments and commit messages
- Dependencies: `libs/Hermod` + `libs/Styx` git submodules, referenced via the `/Dependencies/`
  solution folder in `SSH.slnx`; BouncyCastle comes in through Hermod
- No self-implemented crypto primitives — BCL first, BouncyCastle for gaps; in-house code only for
  modes/constructions (CTR, chacha20-poly1305@openssh.com, bcrypt_pbkdf, KDF) with official test vectors
- [PLAN.md](PLAN.md) carries status markers (✅ done · 🔶 partial · ⬜ open) — keep them current
  whenever a feature lands, a milestone completes or a decision is made
- **Use Hermod's networking types, not `System.Net`.** Public APIs and models use `IIPAddress`,
  `IPv4Address`/`IPv6Address` (`.Localhost`/`.Any`), `IPPort`, `IPSocket` from
  `org.GraphDefined.Vanaheimr.Hermod`. Convert to `System.Net` only at the lowest layer (actual socket
  calls) via `IIPAddress.ToDotNet()`, `IPPort.ToInt32()/ToUInt16()`, `IPSocket.ToIPEndPoint()` /
  `IPSocket.FromIPEndPoint(...)`, and `IPAddress.Build(...)`/`FromDotNet(...)`. Example: `SshTcp`/`SshTcpListener`.
- **Related namespace gotcha:** our namespace is nested under `org.GraphDefined.Vanaheimr.Hermod`, whose
  `IPAddress` is a *static factory class* (not `System.Net.IPAddress`). If you ever genuinely need the
  `System.Net` type, fully-qualify it or alias it **inside the namespace block** (a file-scoped alias sits
  at the global level and loses to the enclosing Hermod type) — but prefer the Hermod types above.
