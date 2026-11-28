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

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// The real OpenSSH client jumps through our server to a destination of the application's:
    /// <c>ssh -J operator@csms operator@CP001</c>, where the jump host takes "CP001" to a pipe of its own -
    /// a charging station's tunnel - through <see cref="SshServerOptions.Destinations"/>, and SSH runs
    /// end to end through it.
    ///
    /// <para>
    /// The library's own suite has our client make both hops. What only OpenSSH shows is what it puts on
    /// the wire for <c>-J</c> and <c>-W</c>: a second <c>ssh</c> of its own that opens <c>direct-tcpip</c> to
    /// port 22, the host key of the destination checked under its name, and how it reports a destination
    /// the jump host will not open.
    /// </para>
    ///
    /// <para>
    /// <b>Found:</b> OpenSSH writes the host name in lower case before it makes the jump's <c>-W</c> - the
    /// jump host is asked for "cp001", however it was typed -, while <c>-W CP001:22</c> given by hand keeps
    /// the case. A <see cref="SshDestinationFactory"/> must therefore compare names as DNS does, without
    /// regard to case, or <c>ssh -J operator@csms operator@CP001</c> never reaches the station.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshJumpDestinationsInteropTests
    {

        #region Data

        private static readonly TimeSpan Within = TimeSpan.FromSeconds(30);

        #endregion

        #region (private) helpers

        private static String? FindOnPathOrSystem(String Tool)
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { Tool, Tool + ".exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }
            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", Tool + ".exe");
            return File.Exists(system) ? system : null;
        }

        private static String KnownHostsLine(String Pattern, ISshHostKey HostKey)
            => $"{Pattern} ssh-ed25519 {Convert.ToBase64String(HostKey.PublicKeyBlob)}";


        /// <summary>
        /// OpenSSH's client with a key of its own, a configuration file and a known_hosts file of the
        /// test's. The configuration file carries everything, because <c>-J</c> runs a second <c>ssh</c> for
        /// the jump, which is handed <c>-F</c> but none of the other options of the first.
        /// </summary>
        private sealed class OpenSsh : IDisposable
        {

            private readonly String  directory;
            private readonly String  ssh;

            public  String  Config      => Path.Combine(directory, "ssh_config");
            public  String  KnownHosts  => Path.Combine(directory, "known_hosts");
            public  String  Key         => Path.Combine(directory, "id_ed25519");
            public  Byte[]  PublicKey   { get; private set; } = [];

            private OpenSsh(String Directory, String Ssh)
            {
                directory  = Directory;
                ssh        = Ssh;
            }

            public static async Task<OpenSsh> PrepareAsync(IEnumerable<String> KnownHostsLines, CancellationToken CancellationToken)
            {

                var ssh        = FindOnPathOrSystem("ssh");
                var sshKeygen  = FindOnPathOrSystem("ssh-keygen");
                if (ssh is null || sshKeygen is null)
                    Assert.Ignore("No 'ssh'/'ssh-keygen' found.");

                var directory  = Path.Combine(Path.GetTempPath(), "hermod_jump_" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(directory);

                var openSsh    = new OpenSsh(directory, ssh!);

                using (var keygen = Process.Start(new ProcessStartInfo(sshKeygen!) { ArgumentList = { "-t", "ed25519", "-f", openSsh.Key, "-N", "", "-q" }, UseShellExecute = false, CreateNoWindow = true })!)
                    await keygen.WaitForExitAsync(CancellationToken);

                openSsh.PublicKey = Convert.FromBase64String((await File.ReadAllTextAsync(openSsh.Key + ".pub", CancellationToken)).Split(' ')[1]);

                await File.WriteAllLinesAsync(openSsh.KnownHosts, KnownHostsLines, CancellationToken);

                // Forward slashes: OpenSSH reads them on Windows as well, and a backslash is an escape.
                static String Quoted(String FilePath) => "\"" + FilePath.Replace('\\', '/') + "\"";

                await File.WriteAllTextAsync(openSsh.Config,
                                             $"""
                                             Host *
                                                 IdentityFile              {Quoted(openSsh.Key)}
                                                 IdentitiesOnly            yes
                                                 UserKnownHostsFile        {Quoted(openSsh.KnownHosts)}
                                                 GlobalKnownHostsFile      none
                                                 StrictHostKeyChecking     yes
                                                 CheckHostIP               no
                                                 BatchMode                 yes
                                                 PreferredAuthentications  publickey
                                                 PasswordAuthentication    no
                                                 ConnectTimeout            10
                                                 LogLevel                  ERROR

                                             """,
                                             CancellationToken);

                return openSsh;

            }

            /// <summary>
            /// Run <c>ssh -F config</c> with the given arguments, stdin closed, until it exits.
            /// </summary>
            public async Task<(Int32 ExitCode, String StandardOutput, String StandardError)> RunAsync(IEnumerable<String>  Arguments,
                                                                                                      CancellationToken    CancellationToken)
            {

                using var process = new Process { StartInfo = new ProcessStartInfo(ssh) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };

                // Forward slashes here too: on Windows, -J hands -F on to the second ssh through a command
                // line of its own, which takes the backslashes out of the path.
                foreach (var argument in new[] { "-F", Config.Replace('\\', '/') }.Concat(Arguments))
                    process.StartInfo.ArgumentList.Add(argument);

                process.Start();
                process.StandardInput.Close();

                var stdout  = process.StandardOutput.ReadToEndAsync(CancellationToken);
                var stderr  = process.StandardError. ReadToEndAsync(CancellationToken);

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
                timeout.CancelAfter(Within);

                try
                {
                    await process.WaitForExitAsync(timeout.Token);
                }
                catch (OperationCanceledException) when (!CancellationToken.IsCancellationRequested)
                {
                    try { process.Kill(true); } catch { }
                    throw new AssertionException($"ssh did not exit within {Within.TotalSeconds} s.\n{await stderr}");
                }

                return (process.ExitCode, await stdout, await stderr);

            }

            public void Dispose()
            {
                try { Directory.Delete(directory, recursive: true); } catch { }
            }

        }


        /// <summary>
        /// The station: an SSH server that is reached through a pipe alone.
        /// </summary>
        private static SshServer AStation(ISshHostKey HostKey, Byte[] OperatorKey)

            => new (new SshServerOptions {
                   HostKeys       = [ HostKey ],
                   Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(OperatorKey),
                   ExecHandler    = async (context, ct) => {
                                        await context.WriteAsync($"station ran: {context.Command}\n", ct);
                                        return 0;
                                    }
               });

        /// <summary>
        /// The jump host - a CSMS, say: "CP001" is the station, for whoever signed in; any other name is
        /// a port forwarding, to which the given policy applies.
        /// </summary>
        private static async Task<SshServer> AJumpHostAsync(ISshHostKey              HostKey,
                                                            SshUserAuthenticator     Authenticator,
                                                            SshServer                Station,
                                                            ConcurrentQueue<String>  Asked,
                                                            ForwardingPolicy         ForwardingPolicy,
                                                            CancellationToken        CancellationToken)
        {

            var jumpHost = new SshServer(new SshServerOptions {
                               HostKeys          = [ HostKey ],
                               Authenticator     = Authenticator,
                               ForwardingPolicy  = ForwardingPolicy,
                               Destinations      = (session, host, port, ct) => {

                                                       Asked.Enqueue($"{session.Username}@{host}:{port}");

                                                       return ValueTask.FromResult<SshDestinationHandler?>(
                                                                  // As DNS has names: OpenSSH's -J asks for "cp001".
                                                                  String.Equals(host, "CP001", StringComparison.OrdinalIgnoreCase)
                                                                      ? async (context, token) => {

                                                                            var (here, there)  = DuplexPipe.CreateConnectedPair();
                                                                            var serving        = Station.ServeAsync(there, CancellationToken: token);

                                                                            await context.RelayAsync(here, token);

                                                                            await serving.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None).ContinueWith(_ => { });

                                                                        }
                                                                      : null
                                                              );

                                                   }
                           });

            await jumpHost.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);

            return jumpHost;

        }

        #endregion


        #region OpenSsh_JumpsThroughOurServer_ToADestinationOfTheApplication

        /// <summary>
        /// <c>ssh -J operator@jumphost operator@CP001 hostname</c>: OpenSSH's jump asks our server for
        /// "cp001" - in lower case - on port 22, the server hands the channel to the station's pipe, and the command runs on
        /// the station - whose host key OpenSSH checked under the name "CP001", strictly. The jump host
        /// allows no port forwarding at all.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OpenSsh_JumpsThroughOurServer_ToADestinationOfTheApplication(CancellationToken CancellationToken)
        {

            var jumpHostKey  = SshHostKey.GenerateEd25519();
            var stationKey   = SshHostKey.GenerateEd25519();
            var asked        = new ConcurrentQueue<String>();

            using var       openSsh   = await OpenSsh.PrepareAsync([], CancellationToken);
            await using var station   = AStation(stationKey, openSsh.PublicKey);
            await using var jumpHost  = await AJumpHostAsync(jumpHostKey, SshUserAuthenticator.ForAuthorizedKeys(openSsh.PublicKey), station, asked, ForwardingPolicy.None, CancellationToken);

            var jumpPort = jumpHost.LocalEndPoint.Port.ToInt32();

            await File.WriteAllLinesAsync(openSsh.KnownHosts, [ KnownHostsLine($"[127.0.0.1]:{jumpPort}", jumpHostKey),
                                                                KnownHostsLine("CP001",                    stationKey) ], CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync([ "-J", $"operator@127.0.0.1:{jumpPort}", "operator@CP001", "hostname" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode,        Is.EqualTo(0),                                stdErr);
                Assert.That(stdOut,          Is.EqualTo("station ran: hostname\n"),        stdErr);
                Assert.That(asked.ToArray(), Is.EqualTo(new[] { "operator@cp001:22" }),   "the jump asked for the name in lower case, and port 22");
            });

        }

        #endregion

        #region OpenSsh_JumpsThroughOurServer_WithAStationKeyNotKnown_DoesNotGoOn

        /// <summary>
        /// The other side of the end-to-end host key: where the known_hosts file has another key for
        /// "CP001", OpenSSH stops after the jump - the jump host cannot stand in for the station.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OpenSsh_JumpsThroughOurServer_WithAStationKeyNotKnown_DoesNotGoOn(CancellationToken CancellationToken)
        {

            var jumpHostKey  = SshHostKey.GenerateEd25519();
            var stationKey   = SshHostKey.GenerateEd25519();
            var asked        = new ConcurrentQueue<String>();

            using var       openSsh   = await OpenSsh.PrepareAsync([], CancellationToken);
            await using var station   = AStation(stationKey, openSsh.PublicKey);
            await using var jumpHost  = await AJumpHostAsync(jumpHostKey, SshUserAuthenticator.ForAuthorizedKeys(openSsh.PublicKey), station, asked, ForwardingPolicy.None, CancellationToken);

            var jumpPort = jumpHost.LocalEndPoint.Port.ToInt32();

            await File.WriteAllLinesAsync(openSsh.KnownHosts, [ KnownHostsLine($"[127.0.0.1]:{jumpPort}", jumpHostKey),
                                                                KnownHostsLine("CP001",                    SshHostKey.GenerateEd25519()) ], CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync([ "-J", $"operator@127.0.0.1:{jumpPort}", "operator@CP001", "hostname" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode,        Is.Not.EqualTo(0),                            stdErr);
                Assert.That(stdOut,          Does.Not.Contain("station ran"),              stdErr);
                Assert.That(stdErr,          Does.Contain("CP001").IgnoreCase,              "OpenSSH names the host whose key it does not know");
                Assert.That(asked.ToArray(), Is.EqualTo(new[] { "operator@cp001:22" }),   "the jump itself went through");
            });

        }

        #endregion

        #region OpenSsh_StdioForwarding_ReachesTheStation

        /// <summary>
        /// <c>ssh -W CP001:22 operator@jumphost</c> - what <c>-J</c> runs for the jump, and what a
        /// <c>ProxyCommand</c> of old wrote out: the station's SSH identification string comes back on
        /// stdout, from the pipe and not from the network.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OpenSsh_StdioForwarding_ReachesTheStation(CancellationToken CancellationToken)
        {

            var jumpHostKey  = SshHostKey.GenerateEd25519();
            var stationKey   = SshHostKey.GenerateEd25519();
            var asked        = new ConcurrentQueue<String>();

            using var       openSsh   = await OpenSsh.PrepareAsync([], CancellationToken);
            await using var station   = AStation(stationKey, openSsh.PublicKey);
            await using var jumpHost  = await AJumpHostAsync(jumpHostKey, SshUserAuthenticator.ForAuthorizedKeys(openSsh.PublicKey), station, asked, ForwardingPolicy.None, CancellationToken);

            var jumpPort = jumpHost.LocalEndPoint.Port.ToInt32();

            await File.WriteAllLinesAsync(openSsh.KnownHosts, [ KnownHostsLine($"[127.0.0.1]:{jumpPort}", jumpHostKey) ], CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync([ "-W", "CP001:22", "-p", jumpPort.ToString(), "operator@127.0.0.1" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(stdOut,          Does.StartWith("SSH-2.0-"),                   $"the station's identification string came through.\nexit {exitCode}\n{stdErr}");
                Assert.That(asked.ToArray(), Is.EqualTo(new[] { "operator@CP001:22" }),   "-W asks for the name as it was typed - -J does not");
            });

        }

        #endregion

        #region OpenSsh_ToANameTheApplicationDoesNotKnow_IsRefused_AsAForwardingThatIsOff

        /// <summary>
        /// A name the application answers null for is a port forwarding, which this jump host does not
        /// allow: OpenSSH's jump is refused, it says so, and nothing was connected to.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OpenSsh_ToANameTheApplicationDoesNotKnow_IsRefused_AsAForwardingThatIsOff(CancellationToken CancellationToken)
        {

            var jumpHostKey  = SshHostKey.GenerateEd25519();
            var stationKey   = SshHostKey.GenerateEd25519();
            var asked        = new ConcurrentQueue<String>();

            using var       openSsh   = await OpenSsh.PrepareAsync([], CancellationToken);
            await using var station   = AStation(stationKey, openSsh.PublicKey);
            await using var jumpHost  = await AJumpHostAsync(jumpHostKey, SshUserAuthenticator.ForAuthorizedKeys(openSsh.PublicKey), station, asked, ForwardingPolicy.None, CancellationToken);

            var jumpPort = jumpHost.LocalEndPoint.Port.ToInt32();

            await File.WriteAllLinesAsync(openSsh.KnownHosts, [ KnownHostsLine($"[127.0.0.1]:{jumpPort}", jumpHostKey),
                                                                KnownHostsLine("CP002",                    stationKey) ], CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync([ "-J", $"operator@127.0.0.1:{jumpPort}", "operator@CP002", "hostname" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode,        Is.Not.EqualTo(0),                            stdErr);
                Assert.That(stdOut,          Is.Empty,                                     stdErr);
                Assert.That(stdErr,          Does.Contain("open failed").Or.Contain("forwarding failed"),
                                                                                           "OpenSSH reports the refused channel");
                Assert.That(asked.ToArray(), Is.EqualTo(new[] { "operator@cp002:22" }),   "the application was asked, and answered null");
            });

        }

        #endregion

        #region OpenSsh_ToANameTheApplicationDoesNotKnow_IsForwarded_WhereThePolicyAllows

        /// <summary>
        /// Where the forwarding policy allows it, a destination the application answers null for is
        /// forwarded as before - here to the station listening on a loopback port of its own, so OpenSSH
        /// reaches the same server once through the pipe and once through the network.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OpenSsh_ToANameTheApplicationDoesNotKnow_IsForwarded_WhereThePolicyAllows(CancellationToken CancellationToken)
        {

            var jumpHostKey  = SshHostKey.GenerateEd25519();
            var stationKey   = SshHostKey.GenerateEd25519();
            var asked        = new ConcurrentQueue<String>();

            using var       openSsh   = await OpenSsh.PrepareAsync([], CancellationToken);
            await using var station   = AStation(stationKey, openSsh.PublicKey);
            await station.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);

            await using var jumpHost  = await AJumpHostAsync(jumpHostKey, SshUserAuthenticator.ForAuthorizedKeys(openSsh.PublicKey), station, asked, ForwardingPolicy.LoopbackOnly, CancellationToken);

            var jumpPort     = jumpHost.LocalEndPoint.Port.ToInt32();
            var stationPort  = station. LocalEndPoint.Port.ToInt32();

            await File.WriteAllLinesAsync(openSsh.KnownHosts, [ KnownHostsLine($"[127.0.0.1]:{jumpPort}",    jumpHostKey),
                                                                KnownHostsLine($"[127.0.0.1]:{stationPort}", stationKey) ], CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync([ "-J", $"operator@127.0.0.1:{jumpPort}", "-p", stationPort.ToString(), "operator@127.0.0.1", "whoami" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode,        Is.EqualTo(0),                                                      stdErr);
                Assert.That(stdOut,          Is.EqualTo("station ran: whoami\n"),                                stdErr);
                Assert.That(asked.ToArray(), Is.EqualTo(new[] { $"operator@127.0.0.1:{stationPort}" }),          "asked first, and answered null");
            });

        }

        #endregion

        #region OpenSsh_WithARestrictedKey_ReachesTheDestination_ButNoForwarding

        /// <summary>
        /// A key with <c>restrict</c> in the jump host's authorized_keys - no port forwarding, the way an
        /// operator's key on a CSMS should be: OpenSSH still reaches "CP001", which is no port forwarding
        /// and for the application to decide, while 127.0.0.1 is refused, though the policy would allow it.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OpenSsh_WithARestrictedKey_ReachesTheDestination_ButNoForwarding(CancellationToken CancellationToken)
        {

            var jumpHostKey  = SshHostKey.GenerateEd25519();
            var stationKey   = SshHostKey.GenerateEd25519();
            var asked        = new ConcurrentQueue<String>();

            using var       openSsh        = await OpenSsh.PrepareAsync([], CancellationToken);
            await using var station        = AStation(stationKey, openSsh.PublicKey);
            await station.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);

            var             restricted     = SshUserAuthenticator.ForAuthorizedKeys(AuthorizedKeysFile.Parse($"restrict ssh-ed25519 {Convert.ToBase64String(openSsh.PublicKey)} operator"));

            await using var jumpHost       = await AJumpHostAsync(jumpHostKey, restricted, station, asked, ForwardingPolicy.LoopbackOnly, CancellationToken);

            var jumpPort     = jumpHost.LocalEndPoint.Port.ToInt32();
            var stationPort  = station. LocalEndPoint.Port.ToInt32();

            await File.WriteAllLinesAsync(openSsh.KnownHosts, [ KnownHostsLine($"[127.0.0.1]:{jumpPort}",    jumpHostKey),
                                                                KnownHostsLine("CP001",                       stationKey),
                                                                KnownHostsLine($"[127.0.0.1]:{stationPort}", stationKey) ], CancellationToken);

            var toTheStation  = await openSsh.RunAsync([ "-J", $"operator@127.0.0.1:{jumpPort}", "operator@CP001", "hostname" ], CancellationToken);
            var forwarded     = await openSsh.RunAsync([ "-J", $"operator@127.0.0.1:{jumpPort}", "-p", stationPort.ToString(), "operator@127.0.0.1", "whoami" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(toTheStation.ExitCode,        Is.EqualTo(0),                          toTheStation.StandardError);
                Assert.That(toTheStation.StandardOutput,  Is.EqualTo("station ran: hostname\n"),  toTheStation.StandardError);
                Assert.That(forwarded.ExitCode,           Is.Not.EqualTo(0),                      "restrict forbids the port forwarding, whatever the policy allows");
                Assert.That(forwarded.StandardOutput,     Does.Not.Contain("station ran"),        forwarded.StandardError);
                Assert.That(asked.ToArray(),              Is.EqualTo(new[] { "operator@cp001:22", $"operator@127.0.0.1:{stationPort}" }));
            });

        }

        #endregion

    }

}
