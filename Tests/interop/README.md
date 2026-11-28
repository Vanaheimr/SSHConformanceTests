# Interop harness assets

Supporting files for the interoperability test program ([PLAN.md](../../PLAN.md), section 11).

This suite lives here rather than with the library because every test in it needs something the machine
has to provide — WSL, an `ssh` binary, a Python environment, a peer package. Hermod's own test suite stays
hermetic; this is where the world gets involved.

The NUnit interop tests (`[Category("Interop")]`) drive our client and server against real
third-party SSH/SFTP implementations and probe the environment first — missing prerequisites make a
test `Assert.Ignore(...)` with a precise message, never a red failure.

## Layout

| Path             | Purpose                                                                      |
|------------------|------------------------------------------------------------------------------|
| `setup-wsl.sh`   | Provision the peers on any Debian-family Linux (idempotent; root/sudo for apt). |
| `setup-windows.ps1` | Provision the peers that need no Linux natively on Windows: the Python ones into `.venv-interop-win/`, the jars of MINA SSHD and JSch into `.java-interop-win/`, and the Rust toolchain Russh pins (idempotent; Windows PowerShell 5.1 or PowerShell 7, no administrator rights). |
| `build-openssh.sh` | Build one OpenSSH portable release into a private prefix, for the nightly's version spread; put `<prefix>/bin` and `<prefix>/sbin` in front of `PATH` and every OpenSSH fixture uses it. |
| `forward-proxy.sh` | Start one real forward proxy in the foreground - Squid or tinyproxy - on a port of the test's choosing, opening `CONNECT` tunnels to one port alone, optionally asking for HTTP Basic and (Squid) speaking TLS to its clients; it logs every request to stdout. |
| `.venv-interop/` | The Python peers (AsyncSSH, Paramiko, ncclient, websockets), created by `setup-wsl.sh`. Git-ignored. |
| `.venv-interop-win/` | The same peers for Windows, created by `setup-windows.ps1`. Git-ignored. |
| `.java-interop-win/` | The jars of MINA SSHD 2.13.2 and JSch 0.2.19 with their dependencies, fetched from Maven Central by `setup-windows.ps1`, checked against pinned SHA-256s and stored under Debian's names. Git-ignored. |
| `python/`        | Peer drivers speaking a JSON contract with `PythonPeers.RunDriverAsync`, and `asyncssh_server.py`, a server for our client (`PythonPeers.StartServerAsync`). `asyncssh_messaging.py` is both: a driver, and with `server` first a server. `websocket_bridge.py` carries a byte stream through a WebSocket of Python's `websockets`: `client` as OpenSSH's `ProxyCommand`, `server` as an endpoint in front of TCP (with `tls <certificate> <key>` as `wss`, with `basic <user> <password>` behind HTTP Basic), and as a driver one handshake or rule break. |
| `WslInterop.cs`  | Runs the peers — through WSL on Windows, directly on Linux: process plumbing, addressing, peer logs, skip reasons. |
| `PeerPlatform.cs` | Runs the peers that need no Linux — the Python, Java, Rust and Go ones — natively on Windows where they are provisioned, and through `WslInterop.cs` otherwise. |
| `JavaPeers.cs`   | The Java toolchain and jars a Java peer is built against: the distribution's in Linux, `.java-interop-win` on Windows. |
| `go/`            | `main.go`, a client for `golang.org/x/crypto/ssh` and `github.com/pkg/sftp` speaking the JSON contract, built on demand from the module proxy as `go.mod` and `go.sum` pin them — with `go.exe` from the PATH on Windows, otherwise inside WSL. |
| `libssh/`        | `libssh_peer.c`, one C program that is a libssh client speaking the JSON contract and a libssh server for our client, compiled on demand against the distribution's libssh. |
| `mina/`          | `MinaPeer.java`, the same for Apache MINA SSHD: a client speaking the JSON contract and a server for our client, compiled on demand against the distribution's jars. |
| `wolfssh/`       | `wolfssh_peer.c`, the same for wolfSSH: a client speaking the JSON contract and a server for our client, compiled on demand against the wolfSSH release `build-wolfssh.sh` pins and builds once into `~/.cache/hermod-interop/wolfssh`, on the distribution's wolfSSL. |
| `jsch/`          | `JschPeer.java`, a JSch client speaking the JSON contract, compiled on demand against the distribution's jars. JSch has no server, so this peer has no server role. |
| `russh/`         | `russh-peer`, the same for Russh in Rust: a client speaking the JSON contract and a server for our client, built on demand from crates.io as `Cargo.lock` pins them, by the compiler `rust-toolchain.toml` pins. |

## Which peers are exercised, and how

| Peer | Role | Driven via |
|---|---|---|
| OpenSSH (`ssh`, `sftp`, `ssh-keygen`) | client | Windows process |
| SSH.NET | client | in-process (NuGet) |
| AsyncSSH | **both** | Windows process or WSL + `python/asyncssh_driver.py`, `python/asyncssh_server.py` as a server for our client (password, keyboard-interactive), and `python/asyncssh_messaging.py`, Hermod's message protocol written from its README alone, as a client against our `SshMessageServer` and a server for our `SshMessageClient` |
| Paramiko | client | Windows process or WSL + `python/paramiko_driver.py` |
| Python `websockets` (RFC 6455), with OpenSSH | **both** | Windows process or WSL + `python/websocket_bridge.py`: SSH over WebSocket written from Hermod's README alone. Their endpoint takes our `SshServer.ConnectOut` (OpenSSH's client behind it) and our `SshWebSocketClient` (an `sshd` behind it); their client is OpenSSH's `ProxyCommand` to our `SshWebSocketEndpoint`, and breaks its rules. The cases with OpenSSH need WSL or Linux |
| Squid, tinyproxy (forward proxies, `CONNECT`) | proxy | WSL + `forward-proxy.sh`, between our `SshWebSocketClient` - as a client, and as the station's `SshServer.ConnectOut` - and their `websockets` endpoint: HTTP Basic, 407 and its challenge, a port the proxy does not open - each refusal `FromProxy` -, the endpoint's own 401 through the tunnel, which is not, `wss` inside the tunnel, and with Squid an `https` proxy with a pinned key, TLS in TLS. Each check reads the proxy's own log for the one tunnel it opened |
| ncclient | client (NETCONF, RFC 6242) | Windows process or WSL + `python/ncclient_driver.py`, against a `netconf` subsystem the test serves |
| Go `x/crypto/ssh`, `pkg/sftp` | client | Windows process or WSL + `go/main.go` |
| Dropbear | **both** | WSL (`dbclient`, and `dropbear` as a server for our client) |
| TinySSH | server | WSL (`socat` + `tinysshd`), exercising our client |
| libssh | **both** | WSL + `libssh/libssh_peer.c`: `client` speaks the JSON contract against our server, `server` answers `exec` and serves libssh's own SFTP server for our client |
| Apache MINA SSHD | **both** | Windows process or WSL + `mina/MinaPeer.java`: `client` speaks the JSON contract against our server, `server` answers `exec` and serves MINA's own SFTP server for our client |
| wolfSSH | **both** | WSL + `wolfssh/wolfssh_peer.c`: `client` speaks the JSON contract against our server, `server` answers `exec` and serves wolfSSH's own SFTP server for our client |
| JSch | client | Windows process or WSL + `jsch/JschPeer.java`: speaks the JSON contract against our server, SFTP through JSch's `ChannelSftp` |
| Russh | **both** | Windows process or WSL + `russh/src/main.rs`: `client` speaks the JSON contract against our server, `server` answers `exec` and serves SFTP through russh-sftp for our client |
| OpenSSH + [SSHTOTPTool](../../libs/SSHTOTPTool/README.md) | **both** | `OpenSshTotpInteropTests`: Hermod's one-time password, with `hermod-ssh-totp` as `ssh`'s `SSH_ASKPASS` (Windows or Linux process, against our server) and in `sshd`'s PAM stack through `pam_exec` (our client, and `ssh` with the tool, against it). The `sshd` cases rewrite `/etc/pam.d/sshd` while they run, so they run as root in a container only - the Debian CI leg, or locally `debian:13` - and skip everywhere else |

## Local setup (Windows, native)

```powershell
# From this directory, in Windows PowerShell 5.1 or PowerShell 7:
.\setup-windows.ps1                                  # the newest Python the py launcher knows
.\setup-windows.ps1 -Python C:\Python312\python.exe  # or a particular one
```

This provisions the peers that need no Linux: AsyncSSH, Paramiko and ncclient into their virtual
environment, the jars MINA SSHD and JSch are built against, and - through any `rustup` on the PATH -
the Rust toolchain Russh pins. The fixtures then build the Java peers with any `javac.exe` on the PATH
(Java 11 or later), Russh with `cargo`, and the Go harness with `go.exe`. Russh's crypto, aws-lc-sys,
would assemble parts of itself with NASM; the fixture has it use the prebuilt objects the crate ships
for Windows instead, so NASM need not be installed.

Where both a native and a WSL environment exist, the native one is used: the peer then
shares the test's loopback, so no address has to be probed and no firewall rule stands between them,
and the Linux build of the same peers is what the Debian CI leg runs anyway. Every other peer still
needs WSL.

## Local setup (WSL2)

```bash
# From a WSL2 Debian/Ubuntu shell, in this directory:
./setup-wsl.sh            # install OpenSSH, Dropbear, TinySSH, PuTTY tools, curl, libssh, wolfSSL for wolfSSH, MINA SSHD, JSch, Rust for Russh + Python peers
./setup-wsl.sh --check    # report what is present, install nothing
```

On Windows the tests reach this shell via `wsl.exe -e`. On Linux the same script provisions the same
peers and the harness runs them directly — no bridge, no path translation, no gateway to find. Note
the two WSL gotchas the harness handles automatically on the Windows path (the plan's §11.2): private
keys are copied off `/mnt/c` into the WSL home and `chmod 600`-ed (OpenSSH refuses world-readable
keys), and `localhost` reachability differs between NAT and mirrored networking modes.

One asymmetry is worth knowing when reading `WslInterop.cs`: `wsl.exe` hands a peer WSL's own default
`PATH`, which includes `/usr/sbin`, while a natively started child inherits the test process's `PATH`,
which for a non-root user on Debian does not. Since the fixtures start `dropbear`, `tinysshd` and
`sshd` by bare name — and Debian puts all three in `/usr/sbin` — the native path adds those
directories explicitly. Without that the two paths would disagree about which peers exist at all.

### Which address a WSL peer must dial (measured 2026-08-11, NAT mode)

Peers that run inside WSL — Dropbear, TinySSH, and AsyncSSH, Paramiko, ncclient and the Go harness when
they are not provisioned natively — connect *back* to a server hosted on Windows. Under WSL's default **NAT** networking that
server is **not reachable at `127.0.0.1`**: from inside WSL, the Windows host answers on the
**default gateway** address (`ip route show default | awk '{print $3}'`, e.g. `172.23.32.1`).

So a test driving a WSL peer must bind our listener to **`IPv4Address.Any`**, not `Localhost`, and
hand the peer the gateway address. The existing interop tests bind to `Localhost` and are unaffected
only because their peer (`ssh.exe`, `ssh-keygen`, SSH.NET) runs on Windows alongside the server.
Under **mirrored** networking (`networkingMode=mirrored` in `.wslconfig`) `localhost` does work — so
detect rather than assume: try `127.0.0.1` first, fall back to the gateway.

## CI

Hosted CI runners have no WSL, which is exactly why the harness gained its native Linux path: on the
`debian:13` container leg of [ci.yml](../../.github/workflows/ci.yml) the peers are ordinary local
processes, so `setup-wsl.sh` is the provisioning script there too. On the `windows-latest` leg the
peers that need no Linux run natively: `setup-windows.ps1` provisions the Python ones under Windows
PowerShell 5.1 along with the jars and the Rust toolchain, `setup-go` and `setup-java` put `go.exe`
and Java 21 on the PATH, and a step after the tests fails the leg if any of those eight fixtures
skipped. No per-peer container images are
involved — an earlier plan for a `docker/` directory was never built and the container leg made it
unnecessary.

Since 2026-08-13 the Debian leg runs `setup-wsl.sh` itself — as root, where the script skips the
sudo it would use on a developer box — so every fixture in this repository runs on every commit:
**95 of 95 checks**, in about 16 s of test time. The Python peers deliberately keep coming from PyPI
rather than apt: trixie's `python3-asyncssh` 2.20 predates AsyncSSH's PyCA-cryptography ML-KEM path
(2.24), and with the apt package the post-quantum interop check could not pass. What remains for a
nightly job (the plan's §11.6) is the *version spread* — older and newer OpenSSH releases, the Tier 3
peers — not this suite at the distro's own peer versions.

The [nightly](../../.github/workflows/nightly.yml) covers OpenSSH from both ends: the newest upstream
release, built from source, and three older ones (8.9 in `ubuntu:22.04`, 9.6 in `ubuntu:24.04`, both
as the distribution ships them, and 9.9 built from source in `debian:13`). To run one of the source
builds locally:

```bash
sudo ./build-openssh.sh openssh-9.9p1 /opt/openssh-9.9p1
PATH=/opt/openssh-9.9p1/bin:/opt/openssh-9.9p1/sbin:$PATH dotnet test ../Tests.csproj --filter "FullyQualifiedName~OpenSsh"
```
