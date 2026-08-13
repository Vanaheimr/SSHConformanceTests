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

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using NUnit.Framework;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// What a peer inside WSL reported back after driving our server.
    /// </summary>
    /// <param name="Ok">Whether the peer completed the requested operation.</param>
    /// <param name="Error">The peer's error message when it did not.</param>
    /// <param name="ErrorType">The peer's exception type name — lets a test assert *how* it failed.</param>
    /// <param name="Stage">How far the session got — the first thing to look at when a peer stalls.</param>
    /// <param name="StdOut">Command output the peer received from us.</param>
    /// <param name="ExitStatus">The exit status the peer saw.</param>
    /// <param name="Listing">Directory entries the peer read over SFTP.</param>
    /// <param name="Algorithms">Best-effort view of what the peer thinks it negotiated (diagnostic only).</param>
    /// <param name="PeerVersion">The peer library's own version, recorded in the interop evidence.</param>
    /// <param name="ServerVersion">Our identification string as the peer saw it.</param>
    public sealed record PeerRunResult(

        [property: JsonPropertyName("ok")]             Boolean                             Ok,
        [property: JsonPropertyName("error")]          String?                             Error,
        [property: JsonPropertyName("error_type")]     String?                             ErrorType,
        [property: JsonPropertyName("stage")]          String?                             Stage,
        [property: JsonPropertyName("stdout")]         String?                             StdOut,
        [property: JsonPropertyName("stderr")]         String?                             StdErr,
        [property: JsonPropertyName("exit_status")]    Int32?                              ExitStatus,
        [property: JsonPropertyName("listing")]        String[]?                           Listing,
        [property: JsonPropertyName("algorithms")]     Dictionary<String, String?>?        Algorithms,
        [property: JsonPropertyName("peer_version")]   String?                             PeerVersion,
        [property: JsonPropertyName("server_version")] String?                             ServerVersion,
        [property: JsonPropertyName("debug_log")]      String[]?                           DebugLog

    )
    {

        /// <summary>
        /// A failure report carrying the peer's own protocol trace — an interop failure is a disagreement
        /// about the wire, and the peer's view shows who stopped talking first.
        /// </summary>
        public String FailureReport
            => $"{ErrorType}: {Error} (stage '{Stage}')" +
               (DebugLog is { Length: > 0 }
                    ? $"\n--- peer trace ---\n{String.Join("\n", DebugLog.TakeLast(60))}"
                    : "");

        /// <summary>A one-line rendering of the negotiated algorithms for the test log.</summary>
        public String AlgorithmSummary
            => Algorithms is null or { Count: 0 }
                   ? "(peer exposes no negotiated-algorithm information)"
                   : String.Join(", ", Algorithms.Where(kv => kv.Value is not null).Select(kv => $"{kv.Key}={kv.Value}"));

    }


    /// <summary>
    /// A peer server running for the lifetime of one test.
    ///
    /// <para>
    /// Disposal reaps the daemon on the Linux side, which is the entire reason this type exists. Killing
    /// <c>wsl.exe</c> ends the Windows half of the bridge and nothing else: the daemon is reparented to
    /// init and keeps listening. So the peer records who it is before it starts, and disposal kills
    /// exactly that — see <see cref="WslInterop.StartServerAsync"/> for what "who it is" has to mean to
    /// survive a daemon that renames itself.
    /// </para>
    /// </summary>
    public sealed class WslServer : IAsyncDisposable
    {

        private readonly Process        process;
        private readonly String         runIdentifier;
        private readonly StringBuilder  log = new ();

        internal WslServer(Process Process, String RunIdentifier)
        {

            this.process       = Process;
            this.runIdentifier = RunIdentifier;

            // Accumulated line by line rather than with ReadToEndAsync: the peer is still running when a
            // test needs to know why it refused something, and a task that only completes at exit would
            // have nothing to say at exactly that moment.
            Process.OutputDataReceived += (_, e) => Append(e.Data);
            Process.ErrorDataReceived  += (_, e) => Append(e.Data);
            Process.BeginOutputReadLine();
            Process.BeginErrorReadLine();

        }

        private void Append(String? Line)
        {
            if (Line is null)
                return;
            lock (log)
                log.AppendLine(Line);
        }

        /// <summary>Whatever the peer has logged so far — the first place to look when it refuses us.</summary>
        public String Output
        {
            get
            {
                lock (log)
                    return log.Length == 0
                               ? "(the peer logged nothing)"
                               : "--- peer log ---\n" + log.ToString();
            }
        }

        public async ValueTask DisposeAsync()
        {

            try { process.Kill(entireProcessTree: true); } catch { }

            try
            {
                // Not belt and braces: on Windows this is the only thing that reaches the daemon at all,
                // and a forgotten SSH daemon keeps listening on the developer's machine.
                await WslInterop.ReapAsync(runIdentifier, CancellationToken.None).ConfigureAwait(false);
            }
            catch { }

            process.Dispose();

        }

    }


    /// <summary>
    /// Collects our own server's audit events during an interop test.
    ///
    /// <para>
    /// A peer can only ever report that the conversation stopped, never why — when the reason is on our
    /// side, this is where it shows up. It earned its place finding exactly that: an AsyncSSH login died
    /// with a bare timeout, and our own audit trail named the cause.
    /// </para>
    /// </summary>
    public sealed class RecordingAuditSink : ISshAuditSink
    {

        private readonly List<SshAuditEvent> events = [];

        public ValueTask WriteAsync(SshAuditEvent Event, CancellationToken CancellationToken = default)
        {
            lock (events)
                events.Add(Event);
            return ValueTask.CompletedTask;
        }

        /// <summary>Everything our server logged, for a failure message.</summary>
        public String Report
        {
            get
            {
                lock (events)
                    return events.Count == 0
                               ? "(our server logged no audit events)"
                               : String.Join("\n", events.Select(e => "   " + e));
            }
        }

    }


    /// <summary>
    /// Drives the interop peers that live in Linux — AsyncSSH, Paramiko, Dropbear, TinySSH, plink,
    /// curl and the Go harness — from wherever NUnit happens to be running.
    ///
    /// <para>
    /// There are two ways to reach them, and the difference is confined to three places. On Windows the
    /// peers live inside WSL2: every command travels through <c>wsl.exe</c>, paths must be translated
    /// into <c>/mnt/…</c> form, and a server bound on the Windows side is reached across a network
    /// boundary. On Linux the peers are ordinary local processes: the command runs directly, a path is
    /// already the path, and everything shares one loopback. How a peer is started, waited for, killed,
    /// and how a driver reports back is identical — which is why the platform split lives in
    /// <see cref="CreateStartInfo"/>, <see cref="ToWslPath"/> and <see cref="ResolveWindowsHostAsync"/>
    /// and nowhere else.
    /// </para>
    ///
    /// <para>
    /// The command convention stays <c>wsl.exe</c>'s on both paths — an argument list starts with
    /// <c>-e</c>, then the program, then its arguments — rather than being invented anew for Linux. That
    /// is what makes the native translation <i>total</i>: drop the <c>-e</c> and execute the rest. A
    /// per-call-site translation could silently mistranslate one of the twenty-odd call sites and run
    /// the wrong thing; this one either works everywhere or throws immediately.
    /// </para>
    ///
    /// <para>
    /// Peers are provisioned by <c>interop/setup-wsl.sh</c>, so anything missing is a *setup* problem and
    /// must <see cref="Assert.Ignore(String)"/> with a precise message rather than fail — an
    /// unprovisioned machine has produced no evidence either way. One asymmetry is genuine and not an
    /// implementation detail: under WSL's default NAT networking a server hosted on Windows is
    /// <b>not</b> reachable at <c>127.0.0.1</c> from inside WSL, the host answers on the default gateway
    /// address instead. Tests therefore bind to <c>IPv4Address.Any</c> and ask
    /// <see cref="ResolveWindowsHostAsync"/> which address the peer must dial — it probes rather than
    /// assumes, so mirrored networking (where <c>localhost</c> does work) is handled too.
    /// </para>
    /// </summary>
    public static class WslInterop
    {

        #region Data

        private static readonly JsonSerializerOptions jsonOptions = new () { PropertyNameCaseInsensitive = true };

        private static readonly Lazy<(String? InteropDir, String? VenvPython, String? Reason)> harness = new (Locate);

        // The reachable address does not change during a run, so probe once.
        private static String? resolvedHost;
        private static readonly SemaphoreSlim resolveLock = new (1, 1);

        // One identifier per test-host process, and a directory of its own for the peers it starts. A
        // second test run on this machine gets a different one, which is what lets InteropPeerCleanup
        // sweep our leftovers without touching peers that another run is still using.
        private static readonly String sessionIdentifier = Guid.NewGuid().ToString("N");

        // Set once a peer server has actually been started, so a run that never used WSL — the common
        // case on a machine without it — does not shell out just to sweep nothing.
        private static Int32 startedServers;

        #endregion

        #region Properties

        /// <summary>The source-tree <c>SSH/interop</c> directory holding the venv and the peer drivers.</summary>
        public static String? InteropDirectory
            => harness.Value.InteropDir;

        /// <summary>Why the WSL harness cannot be used on this machine, or <c>null</c> when it can.</summary>
        public static String? UnavailableReason
            => harness.Value.Reason;

        #endregion


        #region (private, static) Locate()

        /// <summary>
        /// Find the interop directory and the Python virtual environment, reporting precisely what is
        /// missing so a skipped test says something actionable.
        /// </summary>
        private static (String?, String?, String?) Locate()
        {

            // Walk up from the test binaries to the project directory that owns interop/, recognised by the
            // provisioning script rather than the folder name alone.
            var directory = new DirectoryInfo(TestContext.CurrentContext.TestDirectory);
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "interop", "setup-wsl.sh")))
                directory = directory.Parent;

            if (directory is null)
                return (null, null, "Could not locate the 'interop' source directory (no interop/setup-wsl.sh above the test output directory).");

            var interopDirectory = Path.Combine(directory.FullName, "interop");
            var venvPython       = Path.Combine(interopDirectory, ".venv-interop", "bin", "python3");

            // Only Windows needs a bridge to Linux, and only there can it be missing. On Linux the peers
            // are local processes, so there is nothing to check before running one.
            if (OperatingSystem.IsWindows() &&
                !File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wsl.exe")))
                return (interopDirectory, null, "wsl.exe not found — the Linux-only interop peers need WSL2.");

            if (!File.Exists(venvPython))
                return (interopDirectory, null,
                        $"The Python interop peers are not provisioned: '{venvPython}' is missing. " +
                        $"Run interop/setup-wsl.sh{(OperatingSystem.IsWindows() ? " from a WSL2 shell" : "")}.");

            return (interopDirectory, venvPython, null);

        }

        #endregion

        #region SkipIfUnavailable()

        /// <summary>Ignore the calling test when the WSL harness is not provisioned on this machine.</summary>
        public static void SkipIfUnavailable()
        {
            if (UnavailableReason is not null)
                Assert.Ignore(UnavailableReason);
        }

        #endregion


        #region ToWslPath(WindowsPath)

        /// <summary>
        /// The path as the peer sees it: <c>C:\dir\file</c> becomes the <c>/mnt/c/dir/file</c> WSL sees,
        /// while on Linux the test and the peer already share one filesystem and the path is its own
        /// translation.
        /// </summary>
        public static String ToWslPath(String WindowsPath)
        {

            var full = Path.GetFullPath(WindowsPath);

            if (!OperatingSystem.IsWindows())
                return full;

            if (full.Length < 2 || full[1] != ':')
                throw new ArgumentException($"'{WindowsPath}' is not an absolute Windows path.", nameof(WindowsPath));

            return $"/mnt/{Char.ToLowerInvariant(full[0])}{full[2..].Replace('\\', '/')}";

        }

        #endregion

        #region (private, static) CreateStartInfo(Arguments)

        /// <summary>
        /// Build the process start information for one peer command — the single place that knows how
        /// this platform reaches Linux.
        ///
        /// <para>
        /// Callers speak <c>wsl.exe</c>'s convention: <c>-e</c>, then the program, then its arguments.
        /// On Windows that is passed through verbatim. On Linux the whole bridge collapses to dropping
        /// the <c>-e</c> and executing the rest, because <c>wsl.exe -e prog args…</c> and
        /// <c>prog args…</c> are the same command once there is no boundary to cross.
        /// </para>
        ///
        /// <para>
        /// A list that does not follow the convention throws instead of guessing. Guessing here would be
        /// expensive: the plausible wrong reading is to treat <c>-e</c> as an argument of the program,
        /// which on Linux would run a real program with an unexpected flag and report whatever it did as
        /// an interop result.
        /// </para>
        ///
        /// <para>
        /// Every argument has its line endings normalised on the way through, which matters for exactly
        /// one kind of argument and matters a lot: the shell scripts this file passes to <c>bash -c</c>.
        /// They are written as C# raw string literals, and a raw string literal keeps the line endings of
        /// the <i>source file</i> — CRLF in a Windows checkout, because <c>.gitattributes</c> only pins
        /// <c>*.sh</c> to LF and cannot see a script embedded in a <c>.cs</c> file. bash then reads the
        /// carriage return as part of the last word on each line, which does not fail loudly: it silently
        /// makes <c>mkdir "$d"</c> and <c>echo &gt; "$d/f"</c> disagree about what <c>$d</c> is, and turns
        /// a <c>for … ; do</c> header into an outright syntax error. That cost this harness a fleet of SSH
        /// daemons that nothing could ever kill. Line endings are a property of the boundary being
        /// crossed, so they are converted at the boundary, once.
        /// </para>
        /// </summary>
        private static ProcessStartInfo CreateStartInfo(IEnumerable<String> Arguments)
        {

            Arguments = Arguments.Select(argument => argument.Replace("\r\n", "\n"));

            var startInfo = new ProcessStartInfo {
                                RedirectStandardOutput  = true,
                                RedirectStandardError   = true,
                                UseShellExecute         = false,
                                CreateNoWindow          = true,
                                StandardOutputEncoding  = Encoding.UTF8,
                                StandardErrorEncoding   = Encoding.UTF8
                            };

            if (OperatingSystem.IsWindows())
            {

                startInfo.FileName = "wsl.exe";

                foreach (var argument in Arguments)
                    startInfo.ArgumentList.Add(argument);

                return startInfo;

            }

            var arguments = Arguments.ToList();

            if (arguments.Count < 2 || arguments[0] != "-e")
                throw new ArgumentException(
                          "A peer command must be '-e' followed by the program and its arguments — that is the " +
                          "convention the native Linux path translates. Got: " +
                         $"[{String.Join(", ", arguments)}]",
                          nameof(Arguments));

            // wsl.exe hands the peer WSL's own default PATH, which on Debian carries /usr/sbin and /sbin.
            // The fixtures were written against that: they start daemons — dropbear, tinysshd, sshd — by
            // bare name, and on Debian those live in /usr/sbin. A natively started child instead inherits
            // the *test process's* PATH, which for a non-root user has neither directory, so the same
            // fixture would find a peer on one path and not on the other. That asymmetry is worse than an
            // outright failure: it does not break anything, it just quietly tests less.
            var searchPath = Environment.GetEnvironmentVariable("PATH") ?? "";
            var entries    = searchPath.Split(':', StringSplitOptions.RemoveEmptyEntries).ToList();

            foreach (var systemBin in new[] { "/usr/local/sbin", "/usr/sbin", "/sbin" })
                if (!entries.Contains(systemBin))
                    entries.Add(systemBin);

            startInfo.Environment["PATH"] = String.Join(':', entries);

            startInfo.FileName = arguments[1];

            foreach (var argument in arguments.Skip(2))
                startInfo.ArgumentList.Add(argument);

            return startInfo;

        }

        #endregion

        #region RunAsync(Arguments, CancellationToken)

        /// <summary>
        /// Run one peer command — through WSL on Windows, directly on Linux. Arguments are passed through
        /// <see cref="ProcessStartInfo.ArgumentList"/>, so nothing has to be shell-escaped by the caller.
        /// </summary>
        public static async Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(IEnumerable<String>  Arguments,
                                                                                          CancellationToken    CancellationToken)
        {

            var startInfo = CreateStartInfo(Arguments);

            using var process = Process.Start(startInfo)
                                    ?? throw new InvalidOperationException($"Could not start '{startInfo.FileName}'.");

            var stdoutTask = process.StandardOutput.ReadToEndAsync(CancellationToken);
            var stderrTask = process.StandardError. ReadToEndAsync(CancellationToken);

            try
            {
                await process.WaitForExitAsync(CancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                throw;
            }

            return (process.ExitCode, await stdoutTask, await stderrTask);

        }

        #endregion

        #region ResolveWindowsHostAsync(ProbePort, CancellationToken)

        /// <summary>
        /// The address a peer must dial to reach a listener bound by the test process.
        ///
        /// <para>
        /// On Linux there is no boundary to cross — the peer is a sibling process on the same loopback —
        /// so the answer is <c>127.0.0.1</c> without asking anyone. On Windows it is a real question:
        /// this probes <c>127.0.0.1</c> first (correct under mirrored networking) and falls back to the
        /// default gateway (correct under the default NAT networking). Returns <c>null</c> when neither
        /// answers — which on an otherwise healthy machine means the Windows firewall is blocking the
        /// test listener, an environment problem that must not be reported as an interop failure.
        /// </para>
        /// </summary>
        public static async Task<String?> ResolveWindowsHostAsync(CancellationToken CancellationToken)
        {

            if (!OperatingSystem.IsWindows())
                return "127.0.0.1";

            if (resolvedHost is not null)
                return resolvedHost;

            await resolveLock.WaitAsync(CancellationToken).ConfigureAwait(false);

            try
            {

                if (resolvedHost is not null)
                    return resolvedHost;

                // A listener of its own, deliberately: probing a *test's* listener would leave the probe
                // connection sitting in its accept backlog, and the test would then hand its handshake to
                // a dead socket instead of the peer. That cost an afternoon once.
                using var probeListener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Any, 0);
                probeListener.Start();
                var probePort = ((System.Net.IPEndPoint) probeListener.LocalEndpoint).Port;

                var accepting = Task.Run(async () => {
                                    try
                                    {
                                        while (true)
                                            (await probeListener.AcceptTcpClientAsync(CancellationToken)).Dispose();
                                    }
                                    catch { /* the listener was stopped */ }
                                }, CancellationToken);

                var probe = $$"""
                              for host in 127.0.0.1 $(ip route show default 2>/dev/null | awk '{print $3; exit}'); do
                                  if timeout 2 bash -c "exec 3<>/dev/tcp/${host}/{{probePort}}" 2>/dev/null; then
                                      echo "${host}"
                                      exit 0
                                  fi
                              done
                              exit 1
                              """;

                var (exitCode, stdout, _) = await RunAsync(["-e", "bash", "-c", probe], CancellationToken).ConfigureAwait(false);

                probeListener.Stop();
                await accepting.ConfigureAwait(false);

                if (exitCode == 0)
                    resolvedHost = stdout.Trim();

                return resolvedHost;

            }
            finally
            {
                resolveLock.Release();
            }

        }

        #endregion

        #region WhoAmIAsync(CancellationToken)

        /// <summary>
        /// The Linux user name inside WSL. Peers that run unprivileged can only ever authenticate the
        /// account they were started under, so a test connecting to one must use exactly this name.
        /// </summary>
        public static async Task<String> WhoAmIAsync(CancellationToken CancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunAsync(["-e", "whoami"], CancellationToken).ConfigureAwait(false);
            return exitCode == 0
                       ? stdout.Trim()
                       : throw new InvalidOperationException($"Could not determine the WSL user name: {stderr}");
        }

        #endregion

        #region HomeAsync(CancellationToken)

        /// <summary>
        /// The Linux home directory inside WSL.
        ///
        /// <para>
        /// Scratch space for peers that inspect permissions belongs here rather than in <c>/tmp</c>:
        /// Dropbear walks the whole path up to the root and refuses an authorized-keys directory that sits
        /// under a world-writable one, which <c>/tmp</c> (mode 1777) always is.
        /// </para>
        /// </summary>
        public static async Task<String> HomeAsync(CancellationToken CancellationToken)
        {
            var (exitCode, stdout, stderr) = await RunAsync(["-e", "bash", "-c", "echo $HOME"], CancellationToken).ConfigureAwait(false);
            return exitCode == 0
                       ? stdout.Trim()
                       : throw new InvalidOperationException($"Could not determine the WSL home directory: {stderr}");
        }

        #endregion

        #region StartServerAsync(Command, ReadyMarker, CancellationToken)

        /// <summary>
        /// Start a long-running peer <b>server</b> inside WSL — Dropbear or socat-hosted TinySSH — and wait
        /// until it is actually accepting connections.
        ///
        /// <para>
        /// Killing <c>wsl.exe</c> does not reap what it started on the Linux side, so the peer has to be
        /// identified from within Linux. It writes down <b>its own PID and start time</b> just before it
        /// <c>exec</c>s, and <see cref="WslServer.DisposeAsync"/> kills that. Both halves are load-bearing:
        /// the PID says what to kill, and the start time — fixed at fork, unchanged by <c>exec</c> — says
        /// it is still the same process, so a recycled PID from a run that crashed days ago can never be
        /// mistaken for a peer and signalled.
        /// </para>
        ///
        /// <para>
        /// Identifying a daemon by pattern-matching its command line does not work, which is worth
        /// recording because both obvious spellings look like they should. A marker appended as a shell
        /// comment never reaches the peer at all — bash strips it before <c>exec</c>. And a marker passed
        /// in the environment is destroyed in the case that matters most: OpenSSH's <c>setproctitle</c>
        /// reuses the argv <i>and environment</i> memory to write "sshd: … [listener]", so a tagged sshd
        /// has no tag left by the time anyone looks for it.
        /// </para>
        ///
        /// <para>
        /// <c>setsid</c> puts the peer in a session and process group of its own, so one signal to the
        /// negated PID takes its forked children with it — socat's <c>tinysshd</c> instances, sshd's
        /// per-connection children. <c>--wait</c> keeps the bridge process alive exactly as long as the
        /// peer, which the readiness loop below and <see cref="WslServer.Output"/> both depend on.
        /// </para>
        /// </summary>
        /// <param name="Command">The shell command to run inside WSL.</param>
        /// <param name="Port">The TCP port it will listen on, used to wait for readiness.</param>
        public static async Task<WslServer> StartServerAsync(String             Command,
                                                             Int32              Port,
                                                             CancellationToken  CancellationToken)
        {

            var runIdentifier = Guid.NewGuid().ToString("N");

            // $$ is the PID this shell will still have after exec, and field 22 of /proc/self/stat is the
            // start time it was forked with. Everything after the last ')' is parsed positionally because
            // the process name in between sits in parentheses and may contain spaces.
            var script = $$"""
                          mkdir -p "$HOME/.hermod-interop/run/{{sessionIdentifier}}"
                          stat=$(cat /proc/$$/stat)
                          echo "$$ $(echo "${stat#*) }" | cut -d' ' -f20)" > "$HOME/.hermod-interop/run/{{sessionIdentifier}}/{{runIdentifier}}.pid"
                          exec {{Command}}
                          """;

            var startInfo = CreateStartInfo(["-e", "setsid", "--wait", "bash", "-c", script]);

            var process = Process.Start(startInfo)
                              ?? throw new InvalidOperationException($"Could not start '{startInfo.FileName}'.");

            Interlocked.Increment(ref startedServers);

            var server = new WslServer(process, runIdentifier);

            // Wait for the listener rather than sleeping a fixed amount: peers start at very different
            // speeds and a fixed delay is either slow or flaky.
            for (var attempt = 0; attempt < 100; attempt++)
            {

                if (process.HasExited)
                    break;

                try
                {
                    using var probe = new System.Net.Sockets.TcpClient();
                    await probe.ConnectAsync("127.0.0.1", Port, CancellationToken).ConfigureAwait(false);
                    return server;
                }
                catch (System.Net.Sockets.SocketException)
                {
                    await Task.Delay(100, CancellationToken).ConfigureAwait(false);
                }

            }

            var diagnostics = server.Output;
            await server.DisposeAsync().ConfigureAwait(false);

            throw new InvalidOperationException(
                      $"The WSL peer server never accepted a connection on port {Port}.\n{Command}\n{diagnostics}");

        }

        #endregion

        #region (private, static) ReapFunctions

        /// <summary>
        /// The two shell functions the reaping scripts are built from.
        ///
        /// <para>
        /// <c>alive</c> answers "is this still the very process we started?" by comparing the recorded
        /// start time, so it doubles as the liveness check and as the guard against acting on a PID the
        /// kernel has since handed to somebody else. It also refuses anything non-numeric and PID 1,
        /// because the negated-PID form used below turns a stray <c>-1</c> into a signal to every process
        /// on the machine.
        /// </para>
        ///
        /// <para>
        /// <c>reap</c> takes a PID file and ends what it names: the process group first, falling back to
        /// the bare PID when the peer is not a group leader, TERM before KILL so a daemon still gets to
        /// close its sockets, and the PID file removed either way — a peer that is already gone leaves
        /// nothing behind but the file.
        /// </para>
        /// </summary>
        private const String ReapFunctions = """
                                             alive() {
                                                 case "$1" in ''|*[!0-9]*) return 1;; esac
                                                 [ "$1" -gt 1 ] || return 1
                                                 s=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
                                                 [ "$(echo "${s#*) }" | cut -d' ' -f20)" = "$2" ]
                                             }

                                             reap() {
                                                 [ -r "$1" ] || return 0
                                                 read -r pid start rest < "$1" || true
                                                 if alive "$pid" "$start"; then
                                                     kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
                                                     for _ in 1 2 3 4 5 6 7 8 9 10; do
                                                         alive "$pid" "$start" || break
                                                         sleep 0.2
                                                     done
                                                     if alive "$pid" "$start"; then
                                                         kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
                                                     fi
                                                 fi
                                                 rm -f "$1"
                                             }
                                             """;

        #endregion

        #region (internal, static) ReapAsync(RunIdentifier, CancellationToken)

        /// <summary>
        /// End the peer started under <paramref name="RunIdentifier"/>, and everything it forked.
        /// </summary>
        internal static Task ReapAsync(String             RunIdentifier,
                                       CancellationToken  CancellationToken)

            => RunAsync(["-e", "bash", "-c",
                         $$"""
                           {{ReapFunctions}}

                           reap "$HOME/.hermod-interop/run/{{sessionIdentifier}}/{{RunIdentifier}}.pid"
                           exit 0
                           """],
                        CancellationToken);

        #endregion

        #region (internal, static) SweepAsync(CancellationToken)

        /// <summary>
        /// End whatever this test run still has listening inside Linux, and report peers that an earlier
        /// run left behind.
        ///
        /// <para>
        /// Only <i>this</i> session's peers are signalled. Another session's PID files are collected when
        /// the process behind them is gone, but a live one is only counted and reported: a second test host
        /// running right now owns those, and killing its daemons would break a run that is doing nothing
        /// wrong. The count is what a developer needs to see — orphans can only come from a run that died
        /// before it could clean up, and nothing else will ever collect them.
        /// </para>
        /// </summary>
        /// <returns>How many peers from other sessions are still running, or <c>null</c> when the sweep could not run.</returns>
        internal static async Task<Int32?> SweepAsync(CancellationToken CancellationToken)
        {

            if (Volatile.Read(ref startedServers) == 0)
                return 0;

            try
            {

                var (exitCode, stdout, _) = await RunAsync(["-e", "bash", "-c",
                                                            $$"""
                                                              {{ReapFunctions}}

                                                              root="$HOME/.hermod-interop/run"

                                                              for f in "$root/{{sessionIdentifier}}"/*.pid; do
                                                                  reap "$f"
                                                              done

                                                              left=0
                                                              for f in "$root"/*/*.pid; do
                                                                  [ -e "$f" ] || continue
                                                                  read -r pid start rest < "$f" || true
                                                                  if alive "$pid" "$start"; then
                                                                      left=$((left + 1))
                                                                  else
                                                                      rm -f "$f"
                                                                  fi
                                                              done

                                                              for d in "$root"/*/; do rmdir "$d" 2>/dev/null || true; done
                                                              rmdir "$root" 2>/dev/null || true

                                                              echo "$left"
                                                              exit 0
                                                              """],
                                                           CancellationToken).ConfigureAwait(false);

                return exitCode == 0 && Int32.TryParse(stdout.Trim(), out var left)
                           ? left
                           : null;

            }
            catch
            {
                return null;
            }

        }

        #endregion

        #region RunPeerDriverAsync(Driver, Configuration, CancellationToken)

        /// <summary>
        /// Run one of the Python peer drivers and parse its JSON verdict.
        ///
        /// <para>
        /// The configuration travels as a JSON file rather than command-line arguments: it carries paths,
        /// algorithm lists and commands, and a file sidesteps every layer of quoting between .NET,
        /// <c>wsl.exe</c> and the shell.
        /// </para>
        /// </summary>
        /// <param name="Driver">Driver file name inside <c>interop/python/</c>, e.g. <c>asyncssh_driver.py</c>.</param>
        /// <param name="Configuration">The driver configuration, serialised to JSON.</param>
        public static async Task<PeerRunResult> RunPeerDriverAsync(String                       Driver,
                                                                   IReadOnlyDictionary<String, Object?>  Configuration,
                                                                   CancellationToken            CancellationToken)
        {

            var (interopDirectory, venvPython, reason) = harness.Value;

            if (reason is not null || interopDirectory is null || venvPython is null)
                throw new InvalidOperationException(reason ?? "The WSL interop harness is unavailable.");

            var driverPath     = Path.Combine(interopDirectory, "python", Driver);
            if (!File.Exists(driverPath))
                throw new FileNotFoundException($"Peer driver '{Driver}' not found.", driverPath);

            return await RunPeerAsync(Driver,
                                      [ "-e", ToWslPath(venvPython), ToWslPath(driverPath) ],
                                      Configuration,
                                      CancellationToken).ConfigureAwait(false);

        }

        #endregion

        #region RunPeerAsync(Name, Command, Configuration, CancellationToken)

        /// <summary>
        /// Run any peer driver that speaks the JSON contract — the Python ones, the compiled Go harness,
        /// whatever comes next — and parse its verdict.
        /// </summary>
        /// <param name="Name">The driver's name, for error messages.</param>
        /// <param name="Command">The <c>wsl.exe</c> arguments that launch it; the config path is appended.</param>
        /// <param name="Configuration">The driver configuration, serialised to JSON.</param>
        public static async Task<PeerRunResult> RunPeerAsync(String                                Name,
                                                             IReadOnlyList<String>                 Command,
                                                             IReadOnlyDictionary<String, Object?>  Configuration,
                                                             CancellationToken                     CancellationToken)
        {

            var configurationPath = Path.Combine(Path.GetTempPath(), "hermod_peer_" + Guid.NewGuid().ToString("N") + ".json");

            try
            {

                await File.WriteAllTextAsync(configurationPath,
                                             JsonSerializer.Serialize(Configuration),
                                             CancellationToken).ConfigureAwait(false);

                var (exitCode, stdout, stderr) = await RunAsync([ .. Command, ToWslPath(configurationPath) ],
                                                               CancellationToken).ConfigureAwait(false);

                // A driver reports a failed *SSH operation* as ok=false with exit code 0; a non-zero exit
                // means the driver itself broke, which is a harness bug and must be loud.
                if (exitCode != 0)
                    throw new InvalidOperationException(
                              $"The '{Name}' peer driver failed (exit {exitCode}).\nstdout:\n{stdout}\nstderr:\n{stderr}");

                return JsonSerializer.Deserialize<PeerRunResult>(stdout, jsonOptions)
                           ?? throw new InvalidOperationException($"The '{Name}' peer driver produced no JSON.\nstdout:\n{stdout}");

            }
            finally
            {
                try { File.Delete(configurationPath); } catch { }
            }

        }

        #endregion

    }

}
