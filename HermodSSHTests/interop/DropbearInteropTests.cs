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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Interoperability against <b>Dropbear</b> — the embedded world's SSH implementation, and the first
    /// peer exercised in <b>both</b> directions: <c>dbclient</c> drives our server, and our client drives
    /// <c>dropbear</c>.
    ///
    /// <para>
    /// That second direction is the one worth having. Every other peer so far has driven our server, so
    /// our <i>client</i> had only ever talked to our own code; here it authenticates to, and runs a
    /// command on, an implementation that shares nothing with ours.
    /// </para>
    ///
    /// <para>
    /// Dropbear brings a different set of assumptions to the table: a deliberately small algorithm
    /// portfolio, its own private-key format, and SHA-1 disabled by default since 2025.87. Its key format
    /// is itself an interop surface — <c>dropbearconvert</c> has to read what our generator writes.
    /// </para>
    ///
    /// <para>
    /// Everything runs against an isolated <c>HOME</c> (dbclient honours it) and an isolated
    /// authorized-keys directory (<c>dropbear -D</c>), so the developer's real <c>~/.ssh</c> is never
    /// touched — no test may leave a usable key behind on a real account.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.Dropbear")]
    public class DropbearInteropTests
    {

        #region (private) harness

        private const String Marker = "DROPBEAR_INTEROP_OK";

        /// <summary>
        /// A scratch directory pair: our keys are generated on the Windows side, but everything Dropbear
        /// has to inspect lives in the WSL filesystem.
        ///
        /// <para>
        /// That split is not cosmetic. Under DrvFs a <c>chmod</c> on <c>/mnt/c</c> is silently ignored —
        /// the files stay mode 777 — and Dropbear refuses an <c>authorized_keys</c> anyone could write.
        /// </para>
        /// </summary>
        private sealed record Workspace(String WindowsRoot, String WslRoot)
        {
            public String WslHome            => $"{WslRoot}/home";
            public String WslUserKey         => $"{WslRoot}/user";          // openssh-key-v1, as we write it
            public String WslUserKeyDropbear => $"{WslRoot}/user.db";       // after dropbearconvert
            public String WslAuthorizedDir   => $"{WslRoot}/authorized";
            public String WslHostKey         => $"{WslRoot}/hostkey";
        }


        /// <summary>
        /// Generate a key pair, copy it into a WSL-native scratch directory and lock the permissions down.
        /// </summary>
        private static async Task<(Workspace Workspace, ISshHostKey UserKey)> PrepareAsync(CancellationToken CancellationToken)
        {

            WslInterop.SkipIfUnavailable();

            var identifier  = Guid.NewGuid().ToString("N");
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_dropbear_" + identifier);
            Directory.CreateDirectory(windowsRoot);

            // Under the home directory, not /tmp: Dropbear walks the path up to the root and refuses an
            // authorized-keys directory below a world-writable one, which /tmp (1777) always is.
            var home      = await WslInterop.HomeAsync(CancellationToken);
            var workspace = new Workspace(windowsRoot, $"{home}/.hermod-interop/dropbear_{identifier}");
            var userKey   = SshHostKey.GenerateEd25519();

            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "dropbear-interop", CancellationToken);

            var staging = WslInterop.ToWslPath(windowsRoot);

            var (exitCode, _, stderr) = await WslInterop.RunAsync([
                                            "-e", "bash", "-c",
                                            $"mkdir -p {workspace.WslRoot} {workspace.WslHome}/.ssh {workspace.WslAuthorizedDir} && " +
                                            $"cp {staging}/user {staging}/user.pub {workspace.WslRoot}/ && " +
                                            $"cp {workspace.WslRoot}/user.pub {workspace.WslAuthorizedDir}/authorized_keys && " +
                                            $"chmod 700 {workspace.WslRoot} {workspace.WslHome} {workspace.WslHome}/.ssh {workspace.WslAuthorizedDir} && " +
                                            $"chmod 600 {workspace.WslAuthorizedDir}/authorized_keys {workspace.WslRoot}/user"
                                        ], CancellationToken);

            if (exitCode != 0)
                Assert.Ignore($"Could not prepare the Dropbear workspace inside WSL: {stderr}");

            return (workspace, userKey);

        }

        private static async Task CleanupAsync(Workspace Workspace)
        {
            try { Directory.Delete(Workspace.WindowsRoot, recursive: true); } catch { }
            try { await WslInterop.RunAsync(["-e", "rm", "-rf", Workspace.WslRoot], CancellationToken.None); } catch { }
        }

        /// <summary>Convert our openssh-key-v1 private key into Dropbear's own format.</summary>
        private static async Task<(Int32 ExitCode, String Output)> ConvertKeyAsync(Workspace Workspace, CancellationToken CancellationToken)
        {
            var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                 "-e", "dropbearconvert", "openssh", "dropbear",
                                                 Workspace.WslUserKey, Workspace.WslUserKeyDropbear
                                             ], CancellationToken);
            return (exitCode, stdout + stderr);
        }

        private static Int32 FreePort()
        {
            using var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();
            var port = ((System.Net.IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }

        #endregion


        #region DropbearConvert_ReadsOurPrivateKey

        /// <summary>
        /// Our private-key file read by a third implementation's parser. <c>dropbearconvert</c> has to
        /// recognise the <c>openssh-key-v1</c> container our generator writes and name the key type back
        /// to us — evidence for the key format that does not depend on OpenSSH agreeing with itself.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task DropbearConvert_ReadsOurPrivateKey(CancellationToken CancellationToken)
        {

            var (workspace, _) = await PrepareAsync(CancellationToken);

            try
            {

                var (exitCode, output) = await ConvertKeyAsync(workspace, CancellationToken);

                TestContext.Out.WriteLine($"dropbearconvert said: {output.Trim()}");

                Assert.Multiple(() => {
                    Assert.That(exitCode, Is.EqualTo(0), $"dropbearconvert must read our key: {output}");
                    Assert.That(output,   Does.Contain("ssh-ed25519"),
                                "it must identify the key type it found inside our openssh-key-v1 container");
                });

            }
            finally
            {
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region Dropbear_CompletesTransport_WithOurServer

        /// <summary>
        /// The key-exchange matrix against Dropbear, one method at a time.
        ///
        /// <para>
        /// dbclient has no <c>KexAlgorithms</c> option, so the restriction is applied on our side: the
        /// server offers exactly one method and the handshake either completes or it does not. Completion
        /// is the assertion, because our host-key signature covers the exchange hash — if the two sides
        /// had computed H differently, dbclient would reject the signature and never send NEWKEYS.
        /// Authentication is deliberately out of scope here; it has its own test.
        /// </para>
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        [TestCase("curve25519-sha256")]
        [TestCase("ecdh-sha2-nistp256")]
        [TestCase("ecdh-sha2-nistp521")]
        [TestCase("diffie-hellman-group14-sha256")]
        // Deliberately not diffie-hellman-group16-sha512: Dropbear offers group14 but not group16, so
        // that case would test its algorithm list rather than our interoperability.
        [TestCase("mlkem768x25519-sha256")]
        [TestCase("sntrup761x25519-sha512")]
        public async Task Dropbear_CompletesTransport_WithOurServer(String KeyExchange, CancellationToken CancellationToken)
        {

            var (workspace, _) = await PrepareAsync(CancellationToken);
            var hostKey        = SshHostKey.GenerateEd25519();

            using var listener = SshTcpListener.Start(new IPSocket(IPv4Address.Any, IPPort.Auto));
            var port = listener.LocalEndPoint.Port.ToInt32();

            try
            {

                var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
                if (host is null)
                    Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");

                var serverTask = Task.Run(async () => {

                                     var pipe = await listener.AcceptAsync(CancellationToken);

                                     using var transport = await SshTransport.ServerHandshakeAsync(
                                                               pipe, hostKey,
                                                               KeyExchanges: [ KeyExchange ],
                                                               CancellationToken: CancellationToken);

                                     var algorithms = transport.Algorithms;

                                     // Authentication is another test's subject; close now so dbclient
                                     // stops waiting for a service accept and exits on its own.
                                     await pipe.Output.CompleteAsync();
                                     await pipe.Input. CompleteAsync();

                                     return algorithms;

                                 }, CancellationToken);

                var clientTask = WslInterop.RunAsync([
                                     "-e", "env", $"HOME={workspace.WslHome}",
                                     "dbclient", "-y", "-y",
                                     "-i", workspace.WslUserKeyDropbear,
                                     "-p", port.ToString(),
                                     $"hermoduser@{host}", "true"
                                 ], CancellationToken);

                // Assert on the handshake, not on dbclient's exit: it will always exit non-zero here
                // because the connection is closed before it can authenticate.
                var finished = await Task.WhenAny(serverTask, Task.Delay(TimeSpan.FromSeconds(25), CancellationToken));

                if (finished != serverTask)
                {
                    var (_, _, timedOutStderr) = await clientTask;
                    Assert.Fail($"the handshake never completed — dbclient said:\n{timedOutStderr}");
                }

                var algorithms     = await serverTask;
                var (_, _, stderr) = await clientTask;

                TestContext.Out.WriteLine($"Dropbear agreed on {algorithms.KeyExchange} / {algorithms.CipherClientToServer} / {algorithms.HostKey}");

                Assert.That(algorithms.KeyExchange, Is.EqualTo(KeyExchange),
                            $"dbclient must complete {KeyExchange} with us. stderr:\n{stderr}");

            }
            finally
            {
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region Dropbear_RunsCommand_OnOurServer

        /// <summary>
        /// <c>dbclient</c> against our server: the embedded world's client, with its small algorithm set,
        /// authenticating with our key and reading our command output and exit status.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task Dropbear_RunsCommand_OnOurServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);
            var audit  = new RecordingAuditSink();

            var server = new SshServer(new SshServerOptions {
                             HostKeys      = [ SshHostKey.GenerateEd25519() ],
                             Authenticator = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                             AuditSink     = audit,
                             ExecHandler   = async (context, ct) => {
                                                 await context.WriteAsync($"hermod ran: {context.Command}\n", ct);
                                                 return context.Command == "fail" ? 42 : 0;
                                             }
                         });

            try
            {

                var (convertExit, convertOutput) = await ConvertKeyAsync(workspace, CancellationToken);
                Assert.That(convertExit, Is.EqualTo(0), $"dropbearconvert must read our key: {convertOutput}");

                await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
                if (host is null)
                    Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");

                // -y twice: accept the host key without writing it anywhere. Host-key *verification* is
                // covered by its own test below; here the subject is the session.
                // -v: dbclient's stderr is only ever shown when this test fails, so the protocol trace
                // costs nothing and is exactly what one needs at that moment.
                var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                     "-e", "env", $"HOME={workspace.WslHome}",
                                                     "dbclient", "-y", "-y", "-v",
                                                     "-i", workspace.WslUserKeyDropbear,
                                                     "-p", port.ToString(),
                                                     $"hermoduser@{host}", Command
                                                 ], CancellationToken);

                TestContext.Out.WriteLine($"dbclient stderr: {stderr.Trim()}");

                Assert.Multiple(() => {
                    Assert.That(stdout,   Is.EqualTo($"hermod ran: {Command}\n"),
                                $"our output must reach dbclient.\ndbclient stderr:\n{stderr}\n--- our server's audit ---\n{audit.Report}");
                    Assert.That(exitCode, Is.EqualTo(ExpectedExit), "dbclient must propagate our exit status");
                });

            }
            finally
            {
                await server.DisposeAsync();
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region Dropbear_RejectsAWrongHostKey

        /// <summary>
        /// Host-key verification from Dropbear's side: with a foreign key already trusted for this
        /// address, <c>dbclient</c> must refuse rather than ask or continue. The isolated <c>HOME</c>
        /// makes the known-hosts file ours to write.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Dropbear_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);
            var somebodyElse         = SshHostKey.GenerateEd25519();

            var server = new SshServer(new SshServerOptions {
                             HostKeys      = [ SshHostKey.GenerateEd25519() ],
                             Authenticator = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                             ExecHandler   = async (context, ct) => { await context.WriteAsync("unreachable\n", ct); return 0; }
                         });

            try
            {

                await ConvertKeyAsync(workspace, CancellationToken);

                await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
                if (host is null)
                    Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");

                // Pre-trust somebody else's key. Dropbear keys its known_hosts by host name alone — no
                // "[host]:port" bracket notation as OpenSSH uses — and an entry that does not match makes
                // it abort outright, where an *unknown* host would only prompt.
                var knownHostsLine = $"{host} ssh-ed25519 {Convert.ToBase64String(somebodyElse.PublicKeyBlob)}";
                await WslInterop.RunAsync([
                    "-e", "bash", "-c",
                    $"printf '%s\\n' '{knownHostsLine}' > {workspace.WslHome}/.ssh/known_hosts && " +
                    $"chmod 600 {workspace.WslHome}/.ssh/known_hosts"
                ], CancellationToken);

                // No -y, and stdin closed: dbclient must decide on its own, and must decide against us.
                var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                     "-e", "bash", "-c",
                                                     $"env HOME={workspace.WslHome} dbclient -i {workspace.WslUserKeyDropbear} " +
                                                     $"-p {port} hermoduser@{host} true < /dev/null"
                                                 ], CancellationToken);

                TestContext.Out.WriteLine($"dbclient refused with: {stderr.Trim()}");

                Assert.Multiple(() => {
                    Assert.That(exitCode, Is.Not.EqualTo(0), "dbclient must not succeed against an unexpected host key");
                    Assert.That(stdout,   Does.Not.Contain("unreachable"), "no session may be established");
                    Assert.That(stderr,   Does.Contain("host key").IgnoreCase.Or.Contain("mismatch").IgnoreCase,
                                $"the refusal must be about the host key. stderr:\n{stderr}");
                });

            }
            finally
            {
                await server.DisposeAsync();
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region OurClient_RunsCommand_OnDropbearServer

        /// <summary>
        /// The direction that had never been tested: <b>our client</b> against a third-party <b>server</b>.
        /// It completes the transport with Dropbear, verifies Dropbear's host key, authenticates with a
        /// key our own generator wrote, opens a session and reads back what the remote shell printed.
        ///
        /// <para>
        /// Dropbear runs unprivileged, so it can only authenticate the account it was started under —
        /// hence the WSL user name — and it is pointed at an isolated authorized-keys directory so no
        /// key of ours ever lands in a real account.
        /// </para>
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_RunsCommand_OnDropbearServer(CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);
            var user = await WslInterop.WhoAmIAsync(CancellationToken);
            var port = FreePort();

            // Dropbear needs its host key in its own format; -y prints the public half for us to pin.
            var (keyExit, _, keyError) = await WslInterop.RunAsync([
                                             "-e", "dropbearkey", "-t", "ed25519", "-f", workspace.WslHostKey
                                         ], CancellationToken);
            if (keyExit != 0)
                Assert.Ignore($"dropbearkey failed: {keyError}");

            var (_, publicKeyText, _) = await WslInterop.RunAsync([
                                            "-e", "dropbearkey", "-y", "-f", workspace.WslHostKey
                                        ], CancellationToken);

            var publicLine = publicKeyText.Split('\n').FirstOrDefault(line => line.StartsWith("ssh-ed25519", StringComparison.Ordinal))
                                 ?? throw new InvalidOperationException($"dropbearkey printed no public key:\n{publicKeyText}");

            var expectedHostKey = Convert.FromBase64String(publicLine.Split(' ')[1]);

            await using var dropbear = await WslInterop.StartServerAsync(
                                           $"dropbear -r {workspace.WslHostKey} -D {workspace.WslAuthorizedDir} " +
                                           $"-p 127.0.0.1:{port} -F -E",
                                           port,
                                           CancellationToken);

            try
            {

                SshClient client;
                try
                {
                    client = await SshClient.ConnectAsync(
                                 "127.0.0.1",
                                 (UInt16) port,
                                 new SshClientOptions {
                                     Username      = user,
                                     Credentials   = [ userKey ],
                                     VerifyHostKey = blob => blob.AsSpan().SequenceEqual(expectedHostKey)
                                 },
                                 CancellationToken);
                }
                catch (Exception exception)
                {
                    throw new AssertionException(
                              $"Our client could not connect to Dropbear as '{user}'.\n{exception.Message}\n{dropbear.Output}",
                              exception);
                }

                await using var _ = client;

                var result = await client.ExecuteAsync($"echo {Marker}", CancellationToken);

                TestContext.Out.WriteLine($"dropbear replied: {result.StandardOutput.Trim()} (exit {result.ExitCode})");

                Assert.Multiple(() => {
                    Assert.That(result.StandardOutput, Does.Contain(Marker),
                                $"our client must read the remote command's output.\n{dropbear.Output}");
                    Assert.That(result.ExitCode, Is.EqualTo(0), "and must see the remote exit status");
                });

            }
            finally
            {
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region OurClient_RejectsAWrongDropbearHostKey

        /// <summary>
        /// The same connection with the wrong key pinned: our client must fail closed against a real
        /// third-party server, not just against our own test doubles.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_RejectsAWrongDropbearHostKey(CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);
            var user = await WslInterop.WhoAmIAsync(CancellationToken);
            var port = FreePort();

            var (keyExit, _, keyError) = await WslInterop.RunAsync([
                                             "-e", "dropbearkey", "-t", "ed25519", "-f", workspace.WslHostKey
                                         ], CancellationToken);
            if (keyExit != 0)
                Assert.Ignore($"dropbearkey failed: {keyError}");

            await using var dropbear = await WslInterop.StartServerAsync(
                                           $"dropbear -r {workspace.WslHostKey} -D {workspace.WslAuthorizedDir} " +
                                           $"-p 127.0.0.1:{port} -F -E",
                                           port,
                                           CancellationToken);

            try
            {

                var somebodyElse = SshHostKey.GenerateEd25519();

                Assert.That(async () => await SshClient.ConnectAsync(
                                            "127.0.0.1",
                                            (UInt16) port,
                                            new SshClientOptions {
                                                Username      = user,
                                                Credentials   = [ userKey ],
                                                VerifyHostKey = blob => blob.AsSpan().SequenceEqual(somebodyElse.PublicKeyBlob)
                                            },
                                            CancellationToken),
                            Throws.TypeOf<SshWireException>(),
                            "our client must refuse a host key that is not the one it pinned");

            }
            finally
            {
                await CleanupAsync(workspace);
            }

        }

        #endregion

    }

}
