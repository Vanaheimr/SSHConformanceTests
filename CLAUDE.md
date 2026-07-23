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

| Area | Namespace |
|---|---|
| Library (client + server + transport + keys) | `org.GraphDefined.Vanaheimr.Hermod.SSH` |
| SFTP | `org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP` |
| Tests (NUnit) | `org.GraphDefined.Vanaheimr.Hermod.SSH.Tests` |
| Demo CLI | `org.GraphDefined.Vanaheimr.Hermod.SSH.CLI` |

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
