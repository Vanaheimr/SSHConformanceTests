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

using NUnit.Framework;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Where a peer runs that exists for Windows as well as for Linux: AsyncSSH, Paramiko and ncclient
    /// are Python, MINA SSHD and JSch Java, Russh Rust, the x/crypto/ssh harness Go, and none of them
    /// needs Linux to run.
    ///
    /// <para>
    /// <see cref="Linux"/> is what every peer had until now: <see cref="WslInterop"/>, which crosses
    /// into WSL on Windows and runs the peer directly on Linux. <see cref="Windows"/> runs the peer as
    /// an ordinary Windows process, which puts it on the same loopback as our server: no path
    /// translation, no address to probe, no firewall between them. That is what lets these peers run on
    /// the <c>windows-latest</c> CI leg, which has no WSL, and on a developer machine whose firewall
    /// keeps WSL from reaching the test listener.
    /// </para>
    ///
    /// <para>
    /// The two differ in exactly the places <see cref="WslInterop"/> already isolates: how a command is
    /// started, how a path is spelled for the peer, and which address it dials. Everything else - the
    /// JSON contract of a driver, the readiness wait of a server, the log a test reads - is shared.
    /// </para>
    /// </summary>
    public abstract class PeerPlatform
    {

        #region Instances

        /// <summary>
        /// The peer runs in Linux: inside WSL when this process runs on Windows, as a sibling process
        /// when it runs on Linux.
        /// </summary>
        public static PeerPlatform Linux   { get; } = new LinuxPlatform();

        /// <summary>
        /// The peer runs as a native Windows process next to this one.
        /// </summary>
        public static PeerPlatform Windows { get; } = new WindowsPlatform();

        #endregion

        #region Properties

        /// <summary>
        /// The platform's name, for test logs and skip messages.
        /// </summary>
        public abstract String Name { get; }

        #endregion


        #region ToPeerPath(LocalPath)

        /// <summary>
        /// The path as the peer sees it.
        /// </summary>
        /// <param name="LocalPath">A path on this machine.</param>
        public abstract String ToPeerPath(String LocalPath);

        #endregion

        #region ResolveHostAsync(CancellationToken)

        /// <summary>
        /// The address a peer must dial to reach a listener this process bound on every interface, or
        /// <c>null</c> when it cannot reach one at all.
        /// </summary>
        public abstract Task<String?> ResolveHostAsync(CancellationToken CancellationToken);

        #endregion

        #region RunAsync(Program, Arguments, CancellationToken)

        /// <summary>
        /// Run one program on this platform and collect what it wrote.
        /// </summary>
        /// <param name="Program">The program, as a path the platform understands, or a name on its PATH.</param>
        /// <param name="Arguments">Its arguments, each passed as one word.</param>
        public abstract Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(String               Program,
                                                                                      IEnumerable<String>  Arguments,
                                                                                      CancellationToken    CancellationToken);

        #endregion

        #region RunPeerAsync(Name, Program, Arguments, Configuration, CancellationToken)

        /// <summary>
        /// Run a peer driver that speaks the JSON contract of <see cref="PeerRunResult"/>, with its
        /// configuration in a file whose path is appended to the arguments.
        /// </summary>
        /// <param name="Name">The driver's name, for error messages.</param>
        /// <param name="Program">The program that runs the driver.</param>
        /// <param name="Arguments">Its arguments before the configuration path.</param>
        /// <param name="Configuration">The driver configuration, serialised to JSON.</param>
        public async Task<PeerRunResult> RunPeerAsync(String                                Name,
                                                      String                                Program,
                                                      IReadOnlyList<String>                 Arguments,
                                                      IReadOnlyDictionary<String, Object?>  Configuration,
                                                      CancellationToken                     CancellationToken)
        {

            var configurationPath = Path.Combine(Path.GetTempPath(), "hermod_peer_" + Guid.NewGuid().ToString("N") + ".json");

            try
            {

                await File.WriteAllTextAsync(configurationPath,
                                             JsonSerializer.Serialize(Configuration),
                                             CancellationToken).ConfigureAwait(false);

                var (exitCode, stdout, stderr) = await RunAsync(Program,
                                                                [ .. Arguments, ToPeerPath(configurationPath) ],
                                                                CancellationToken).ConfigureAwait(false);

                return WslInterop.ParsePeerResult(Name, exitCode, stdout, stderr);

            }
            finally
            {
                try { File.Delete(configurationPath); } catch { }
            }

        }

        #endregion

        #region StartServerAsync(Program, ArgumentsForPort, CancellationToken)

        /// <summary>
        /// Start a long-running peer server on a port of this method's choosing, and wait until this
        /// process can reach it.
        /// </summary>
        /// <param name="Program">The program that runs the server.</param>
        /// <param name="ArgumentsForPort">Its arguments for a given port.</param>
        public abstract Task<WslServer> StartServerAsync(String                                Program,
                                                         Func<Int32, IReadOnlyList<String>>    ArgumentsForPort,
                                                         CancellationToken                     CancellationToken);

        #endregion


        #region (internal, static) RunOnWindowsAsync(Program, Arguments, WorkingDirectory, Environment, CancellationToken)

        /// <summary>
        /// Run a native Windows program in a directory and with environment variables of its own - for a
        /// build such as <c>cargo</c>, whose toolchain file is found from the working directory.
        /// </summary>
        internal static Task<(Int32 ExitCode, String StdOut, String StdErr)> RunOnWindowsAsync(String                                Program,
                                                                                               IEnumerable<String>                   Arguments,
                                                                                               String?                               WorkingDirectory,
                                                                                               IReadOnlyDictionary<String, String>?  Environment,
                                                                                               CancellationToken                     CancellationToken)

            => WindowsPlatform.RunAsync(Program, Arguments, WorkingDirectory, Environment, CancellationToken);

        #endregion

        #region (internal, static) FindOnPath(FileName)

        /// <summary>
        /// The full path of a program on this process's PATH, or <c>null</c>.
        /// </summary>
        /// <param name="FileName">The program's file name, e.g. <c>go.exe</c>.</param>
        internal static String? FindOnPath(String FileName)
        {

            foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    var candidate = Path.Combine(directory.Trim('"'), FileName);
                    if (File.Exists(candidate))
                        return candidate;
                }
                catch (ArgumentException)
                { }
            }

            return null;

        }

        #endregion


        #region (private) LinuxPlatform

        private sealed class LinuxPlatform : PeerPlatform
        {

            public override String Name
                => OperatingSystem.IsWindows() ? "WSL" : "Linux";

            public override String ToPeerPath(String LocalPath)
                => WslInterop.ToWslPath(LocalPath);

            public override Task<String?> ResolveHostAsync(CancellationToken CancellationToken)
                => WslInterop.ResolveWindowsHostAsync(CancellationToken);

            public override Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(String               Program,
                                                                                          IEnumerable<String>  Arguments,
                                                                                          CancellationToken    CancellationToken)

                => WslInterop.RunAsync([ "-e", Program, .. Arguments ], CancellationToken);

            public override Task<WslServer> StartServerAsync(String                              Program,
                                                             Func<Int32, IReadOnlyList<String>>  ArgumentsForPort,
                                                             CancellationToken                   CancellationToken)

                => WslInterop.StartServerAsync(port => String.Join(" ", new[] { Program }.Concat(ArgumentsForPort(port))
                                                                                          .Select(word => "'" + word.Replace("'", "'\\''") + "'")),
                                               CancellationToken);

        }

        #endregion

        #region (private) WindowsPlatform

        private sealed class WindowsPlatform : PeerPlatform
        {

            public override String Name
                => "Windows";

            public override String ToPeerPath(String LocalPath)
                => Path.GetFullPath(LocalPath);

            // Peer and listener share this machine's loopback, so there is nothing to probe.
            public override Task<String?> ResolveHostAsync(CancellationToken CancellationToken)
                => Task.FromResult<String?>("127.0.0.1");

            internal static ProcessStartInfo CreateStartInfo(String                                    Program,
                                                             IEnumerable<String>                       Arguments,
                                                             String?                                   WorkingDirectory  = null,
                                                             IReadOnlyDictionary<String, String>?      Environment       = null)
            {

                var startInfo = new ProcessStartInfo {
                                    FileName                = Program,
                                    RedirectStandardOutput  = true,
                                    RedirectStandardError   = true,
                                    UseShellExecute         = false,
                                    CreateNoWindow          = true,
                                    StandardOutputEncoding  = Encoding.UTF8,
                                    StandardErrorEncoding   = Encoding.UTF8
                                };

                foreach (var argument in Arguments)
                    startInfo.ArgumentList.Add(argument);

                // Python on Windows writes to a pipe in the ANSI code page, not UTF-8, so a driver's JSON
                // verdict would arrive mangled the first time it quoted anything outside ASCII - an error
                // message, a banner. UTF-8 mode makes it write what the reader above expects.
                startInfo.Environment["PYTHONUTF8"]       = "1";
                startInfo.Environment["PYTHONIOENCODING"] = "utf-8";

                if (WorkingDirectory is not null)
                    startInfo.WorkingDirectory = WorkingDirectory;

                foreach (var (name, value) in Environment ?? new Dictionary<String, String>())
                    startInfo.Environment[name] = value;

                return startInfo;

            }

            public override Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(String               Program,
                                                                                          IEnumerable<String>  Arguments,
                                                                                          CancellationToken    CancellationToken)

                => RunAsync(Program, Arguments, null, null, CancellationToken);

            internal static async Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(String                                Program,
                                                                                                IEnumerable<String>                   Arguments,
                                                                                                String?                               WorkingDirectory,
                                                                                                IReadOnlyDictionary<String, String>?  Environment,
                                                                                                CancellationToken                     CancellationToken)
            {

                var startInfo = CreateStartInfo(Program, Arguments, WorkingDirectory, Environment);

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

            public override async Task<WslServer> StartServerAsync(String                              Program,
                                                                   Func<Int32, IReadOnlyList<String>>  ArgumentsForPort,
                                                                   CancellationToken                   CancellationToken)
            {

                var attempts = new List<String>();

                for (var attempt = 1; attempt <= WslInterop.StartAttempts; attempt++)
                {

                    var port      = WslInterop.AllocatePort();
                    var startInfo = CreateStartInfo(Program, ArgumentsForPort(port));

                    var process   = Process.Start(startInfo)
                                        ?? throw new InvalidOperationException($"Could not start '{startInfo.FileName}'.");

                    var server    = new WslServer(process, port);

                    if (await WslInterop.WaitUntilReachableAsync(process, port, CancellationToken).ConfigureAwait(false))
                        return server;

                    // A native peer shares this machine's ports, so there is no relay to lose a race to: a
                    // peer that cannot be reached either never bound or has died, and its log says which.
                    if (process.HasExited)
                        try { await process.WaitForExitAsync(CancellationToken).ConfigureAwait(false); } catch { }

                    attempts.Add($"   attempt {attempt} on port {port}: the peer " +
                                 (process.HasExited ? $"exited with {process.ExitCode}." : "never listened.") +
                                 $"\n{server.Output}");

                    await server.DisposeAsync().ConfigureAwait(false);

                }

                throw new InvalidOperationException(
                          $"The peer server never became reachable, on {WslInterop.StartAttempts} different ports.\n" +
                          $"{Program} {String.Join(" ", ArgumentsForPort(0))}\n" +
                          String.Join("\n", attempts));

            }

        }

        #endregion

    }


    /// <summary>
    /// The Python peers - AsyncSSH, Paramiko, ncclient - and where they run on this machine.
    ///
    /// <para>
    /// On Windows a virtual environment of their own at <c>interop/.venv-interop-win</c>, made by
    /// <c>interop/setup-windows.ps1</c>, runs them natively (<see cref="PeerPlatform.Windows"/>), and is
    /// preferred over WSL where both exist: a native peer reaches our server whatever the firewall says
    /// about WSL, and the Linux build of the same peers is what the Debian CI leg runs on every commit.
    /// Without it they run in WSL as before, and on Linux they always run natively from
    /// <c>interop/.venv-interop</c>.
    /// </para>
    /// </summary>
    public static class PythonPeers
    {

        #region Data

        private static readonly Lazy<(PeerPlatform? Platform, String? Python, String? Reason)> located = new (Locate);

        #endregion

        #region Properties

        /// <summary>
        /// Where the Python peers run on this machine.
        /// </summary>
        public static PeerPlatform Platform
            => located.Value.Platform ?? PeerPlatform.Linux;

        /// <summary>
        /// Why the Python peers cannot run on this machine, or <c>null</c> when they can.
        /// </summary>
        public static String? UnavailableReason
            => located.Value.Reason;

        #endregion


        #region (private, static) Locate()

        private static (PeerPlatform?, String?, String?) Locate()
        {

            var interopDirectory = WslInterop.InteropDirectory;

            if (OperatingSystem.IsWindows() && interopDirectory is not null)
            {

                var native = Path.Combine(interopDirectory, ".venv-interop-win", "Scripts", "python.exe");

                if (File.Exists(native))
                    return (PeerPlatform.Windows, native, null);

                if (WslInterop.UnavailableReason is not null)
                    return (null, null,
                            $"The Python interop peers are not provisioned: '{native}' is missing - run interop\\setup-windows.ps1 " +
                            $"to run them natively. ({WslInterop.UnavailableReason})");

            }

            return WslInterop.UnavailableReason is null
                       ? (PeerPlatform.Linux, WslInterop.VenvPython, null)
                       : (null, null, WslInterop.UnavailableReason);

        }

        #endregion

        #region SkipIfUnavailable()

        /// <summary>
        /// Ignore the calling test when the Python peers are not provisioned on this machine.
        /// </summary>
        public static void SkipIfUnavailable()
        {
            if (UnavailableReason is not null)
                Assert.Ignore(UnavailableReason);
        }

        #endregion

        #region ToPeerPath(LocalPath)

        /// <summary>
        /// The path as a Python peer sees it.
        /// </summary>
        public static String ToPeerPath(String LocalPath)
            => Platform.ToPeerPath(LocalPath);

        #endregion

        #region ResolveHostAsync(CancellationToken)

        /// <summary>
        /// The address a Python peer must dial to reach a listener this process bound on every interface.
        /// </summary>
        public static Task<String?> ResolveHostAsync(CancellationToken CancellationToken)
            => Platform.ResolveHostAsync(CancellationToken);

        #endregion

        #region RunDriverAsync(Driver, Configuration, CancellationToken)

        /// <summary>
        /// Run one of the Python peer drivers in <c>interop/python/</c> and parse its JSON verdict.
        /// </summary>
        /// <param name="Driver">The driver's file name, e.g. <c>paramiko_driver.py</c>.</param>
        /// <param name="Configuration">The driver configuration, serialised to JSON.</param>
        public static Task<PeerRunResult> RunDriverAsync(String                                Driver,
                                                         IReadOnlyDictionary<String, Object?>  Configuration,
                                                         CancellationToken                     CancellationToken)
        {

            var (platform, python, reason) = located.Value;

            if (reason is not null || platform is null || python is null)
                throw new InvalidOperationException(reason ?? "The Python interop peers are unavailable.");

            var driverPath = Path.Combine(WslInterop.InteropDirectory!, "python", Driver);
            if (!File.Exists(driverPath))
                throw new FileNotFoundException($"Peer driver '{Driver}' not found.", driverPath);

            return platform.RunPeerAsync(Driver,
                                         platform.ToPeerPath(python),
                                         [ platform.ToPeerPath(driverPath) ],
                                         Configuration,
                                         CancellationToken);

        }

        #endregion

        #region StartServerAsync(Script, ArgumentsForPort, CancellationToken)

        /// <summary>
        /// Start one of the Python peer servers in <c>interop/python/</c>.
        /// </summary>
        /// <param name="Script">The script's file name, e.g. <c>asyncssh_server.py</c>.</param>
        /// <param name="ArgumentsForPort">Its arguments for a given port.</param>
        public static Task<WslServer> StartServerAsync(String                      Script,
                                                       Func<Int32, String[]>       ArgumentsForPort,
                                                       CancellationToken           CancellationToken)
        {

            var (platform, python, reason) = located.Value;

            if (reason is not null || platform is null || python is null)
                throw new InvalidOperationException(reason ?? "The Python interop peers are unavailable.");

            var scriptPath = platform.ToPeerPath(Path.Combine(WslInterop.InteropDirectory!, "python", Script));

            return platform.StartServerAsync(platform.ToPeerPath(python),
                                             port => [ scriptPath, .. ArgumentsForPort(port) ],
                                             CancellationToken);

        }

        #endregion

    }

}
