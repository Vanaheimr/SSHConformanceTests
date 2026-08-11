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
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Interoperability against <b>PuTTY</b> (<c>plink</c>) — the third-oldest SSH lineage still in wide
    /// use, and the one with the most famous quirk of them all.
    ///
    /// <para>
    /// PuTTY shares no ancestry with OpenSSH: separate wire implementation, separate key format, separate
    /// ideas about what a server owes a client. The most consequential of those is
    /// <c>winadj@putty.projects.tartarus.org</c>, a channel request PuTTY sends purely to measure the
    /// round-trip — and one it insists on getting an answer to. A server that silently ignores unknown
    /// requests strands it. <c>CHANNEL_FAILURE</c> is a perfectly good answer; <i>no</i> answer is not.
    /// That is exactly what <see cref="OurServer_AnswersPlinksWinadjRequest"/> pins down, using plink's own
    /// protocol log as the evidence rather than inferring it from a session that merely worked.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.PuTTY")]
    public class PlinkInteropTests
    {

        #region (private) harness

        private sealed record Workspace(String WindowsRoot, String WslRoot)
        {
            public String WslHome    => $"{WslRoot}/home";        // plink keeps its host keys in ~/.putty
            public String WslUserKey => $"{WslRoot}/user";        // openssh-key-v1, which plink reads directly
            public String WslPpk     => $"{WslRoot}/user.ppk";
            public String WslSshLog  => $"{WslRoot}/plink.log";
        }


        private static async Task<(Workspace Workspace, ISshHostKey UserKey)> PrepareAsync(CancellationToken CancellationToken)
        {

            WslInterop.SkipIfUnavailable();

            var (present, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "command -v plink puttygen >/dev/null"], CancellationToken);
            if (present != 0)
                Assert.Ignore("PuTTY tools are not installed inside WSL — run interop/setup-wsl.sh.");

            var identifier  = Guid.NewGuid().ToString("N");
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_plink_" + identifier);
            Directory.CreateDirectory(windowsRoot);

            var home      = await WslInterop.HomeAsync(CancellationToken);
            var workspace = new Workspace(windowsRoot, $"{home}/.hermod-interop/plink_{identifier}");
            var userKey   = SshHostKey.GenerateEd25519();

            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "putty-interop", CancellationToken);

            var staging = WslInterop.ToWslPath(windowsRoot);

            var (exitCode, _, stderr) = await WslInterop.RunAsync([
                                            "-e", "bash", "-c",
                                            $"mkdir -p {workspace.WslRoot} {workspace.WslHome} && " +
                                            $"cp {staging}/user {staging}/user.pub {workspace.WslRoot}/ && " +
                                            $"chmod 700 {workspace.WslRoot} {workspace.WslHome} && chmod 600 {workspace.WslRoot}/user"
                                        ], CancellationToken);

            if (exitCode != 0)
                Assert.Ignore($"Could not prepare the PuTTY workspace inside WSL: {stderr}");

            // plink cannot read an openssh-key-v1 file — "OpenSSH SSH-2 private key (new format)" is
            // exactly what it refuses — so the key goes through puttygen first, the same way Dropbear
            // needs dropbearconvert. That conversion is itself covered by PuttyGen_ReadsOurPrivateKey.
            var (convertExit, convertOut, convertError) = await WslInterop.RunAsync([
                                                              "-e", "puttygen", workspace.WslUserKey,
                                                              "-O", "private", "-o", workspace.WslPpk
                                                          ], CancellationToken);

            if (convertExit != 0)
                Assert.Ignore($"puttygen could not convert our key: {convertOut}{convertError}");

            return (workspace, userKey);

        }

        private static async Task CleanupAsync(Workspace Workspace)
        {
            try { Directory.Delete(Workspace.WindowsRoot, recursive: true); } catch { }
            try { await WslInterop.RunAsync(["-e", "rm", "-rf", Workspace.WslRoot], CancellationToken.None); } catch { }
        }


        /// <summary>
        /// Run plink against our server. The host key is pinned by fingerprint via <c>-hostkey</c>, so the
        /// run never depends on, or writes to, a host-key store — and <c>-batch</c> makes an unexpected key
        /// an error rather than a prompt.
        /// </summary>
        private static Task<(Int32 ExitCode, String StdOut, String StdErr)> PlinkAsync(Workspace          Workspace,
                                                                                       Int32              Port,
                                                                                       String             Host,
                                                                                       String             HostKeyFingerprint,
                                                                                       String             Command,
                                                                                       CancellationToken  CancellationToken,
                                                                                       Boolean            WithProtocolLog = false)
        {

            var arguments = new List<String> {
                                "-e", "env", $"HOME={Workspace.WslHome}",
                                "plink", "-batch", "-ssh",
                                "-i", Workspace.WslPpk,
                                "-P", Port.ToString(),
                                "-hostkey", HostKeyFingerprint
                            };

            if (WithProtocolLog)
            {
                arguments.Add("-sshlog");
                arguments.Add(Workspace.WslSshLog);
            }

            arguments.Add($"hermoduser@{Host}");
            arguments.Add(Command);

            return WslInterop.RunAsync(arguments, CancellationToken);

        }

        #endregion


        #region PuttyGen_ReadsOurPrivateKey

        /// <summary>
        /// A fourth independent parser on our private-key file: <c>puttygen</c> has to read the
        /// <c>openssh-key-v1</c> container our generator writes and convert it into PuTTY's own PPK format.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task PuttyGen_ReadsOurPrivateKey(CancellationToken CancellationToken)
        {

            var (workspace, _) = await PrepareAsync(CancellationToken);

            try
            {

                var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                     "-e", "puttygen", workspace.WslUserKey,
                                                     "-O", "private", "-o", workspace.WslPpk
                                                 ], CancellationToken);

                var (checkExit, ppkListing, _) = await WslInterop.RunAsync([
                                                     "-e", "bash", "-c", $"head -c 64 {workspace.WslPpk}"
                                                 ], CancellationToken);

                TestContext.Out.WriteLine($"puttygen produced: {ppkListing.Split('\n')[0]}");

                Assert.Multiple(() => {
                    Assert.That(exitCode,   Is.EqualTo(0), $"puttygen must read our key: {stdout}{stderr}");
                    Assert.That(checkExit,  Is.EqualTo(0));
                    Assert.That(ppkListing, Does.StartWith("PuTTY-User-Key-File"),
                                "and must have written a PPK carrying the key it found");
                });

            }
            finally
            {
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region Plink_RunsCommand_OnOurServer

        /// <summary>
        /// The whole stack as PuTTY sees it: its own transport, its own auth code reading a key we wrote in
        /// OpenSSH's format, a session channel, our output and our exit status.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task Plink_RunsCommand_OnOurServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);

            var hostKey = SshHostKey.GenerateEd25519();
            var audit   = new RecordingAuditSink();

            var server  = new SshServer(new SshServerOptions {
                              HostKeys      = [ hostKey ],
                              Authenticator = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                              AuditSink     = audit,
                              ExecHandler   = async (context, ct) => {
                                                  await context.WriteAsync($"hermod ran: {context.Command}\n", ct);
                                                  return context.Command == "fail" ? 42 : 0;
                                              }
                          });

            try
            {

                await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
                if (host is null)
                    Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");

                var (exitCode, stdout, stderr) = await PlinkAsync(workspace, port, host!,
                                                                  SshFingerprint.Sha256(hostKey.PublicKeyBlob),
                                                                  Command, CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(stdout,   Is.EqualTo($"hermod ran: {Command}\n"),
                                $"our output must reach plink.\nplink stderr:\n{stderr}\n--- our server's audit ---\n{audit.Report}");
                    Assert.That(exitCode, Is.EqualTo(ExpectedExit), "plink must propagate our exit status");
                });

            }
            finally
            {
                await server.DisposeAsync();
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region OurServer_AnswersPlinksWinadjRequest

        /// <summary>
        /// A quarter-megabyte of output through PuTTY's flow control, and the <c>winadj</c> quirk watched
        /// for while it happens.
        ///
        /// <para>
        /// PuTTY sends <c>winadj@putty.projects.tartarus.org</c> to time its window adjustments and insists
        /// on a reply; a server that drops unknown requests strands it. Whether it sends one is PuTTY's
        /// business, though — plink 0.83 sends none for a plain <c>exec</c>, even under this load — so the
        /// assertion here is conditional and the log says which way it went. The unconditional half of the
        /// contract (an unknown channel request with <c>want_reply</c> is always answered, without it is
        /// never answered) is pinned deterministically in the library's own
        /// <c>ChannelRequestContractTests</c>, where it cannot quietly become vacuous.
        /// </para>
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Plink_TransfersLargeOutput_AndAnyWinadjIsAnswered(CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);

            var hostKey = SshHostKey.GenerateEd25519();

            // PuTTY sends winadj to time its window adjustments, so it only appears once enough data has
            // flowed to make the window move. A one-line reply produces no winadj at all; a few hundred
            // kilobytes reliably does.
            const Int32 chunks    = 64;
            const Int32 chunkSize = 4096;

            var server  = new SshServer(new SshServerOptions {
                              HostKeys      = [ hostKey ],
                              Authenticator = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                              ExecHandler   = async (context, ct) => {
                                                  for (var i = 0; i < chunks; i++)
                                                      await context.WriteAsync(new String('x', chunkSize), ct);
                                                  return 0;
                                              }
                          });

            try
            {

                await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
                if (host is null)
                    Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");

                var (exitCode, stdout, stderr) = await PlinkAsync(workspace, port, host!,
                                                                  SshFingerprint.Sha256(hostKey.PublicKeyBlob),
                                                                  "probe", CancellationToken,
                                                                  WithProtocolLog: true);

                var (_, log, _) = await WslInterop.RunAsync([
                                      "-e", "bash", "-c", $"cat {workspace.WslSshLog} 2>/dev/null || true"
                                  ], CancellationToken);

                var sentWinadj  = log.Contains("winadj@putty.projects.tartarus.org", StringComparison.Ordinal);
                var winadjIndex = log.IndexOf("winadj@putty.projects.tartarus.org", StringComparison.Ordinal);
                var answered    = winadjIndex >= 0 &&
                                  log[winadjIndex..].Contains("CHANNEL_FAILURE", StringComparison.OrdinalIgnoreCase);

                TestContext.Out.WriteLine(sentWinadj
                                              ? $"plink sent winadj and we answered: {answered}"
                                              : "plink sent no winadj request in this session");

                Assert.Multiple(() => {

                    Assert.That(exitCode,      Is.EqualTo(0), $"the session must succeed.\nplink stderr:\n{stderr}");
                    Assert.That(stdout.Length, Is.EqualTo(chunks * chunkSize),
                                "every byte must arrive — winadj exists because PuTTY is measuring this flow");

                    if (sentWinadj)
                        Assert.That(answered, Is.True,
                                    "an unanswered winadj request is what strands PuTTY; CHANNEL_FAILURE is the right answer");

                });

            }
            finally
            {
                await server.DisposeAsync();
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region Plink_CompletesTransport_WithOurServer

        /// <summary>
        /// The key-exchange matrix against PuTTY, one method at a time — restricted on our side, since
        /// plink has no command-line switch for the algorithm list. A completed session proves PuTTY
        /// accepted our host-key signature over that method's exchange hash.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("curve25519-sha256")]
        [TestCase("ecdh-sha2-nistp256")]
        [TestCase("ecdh-sha2-nistp521")]
        [TestCase("diffie-hellman-group14-sha256")]
        [TestCase("mlkem768x25519-sha256")]      // PuTTY has the ML-KEM hybrid since 0.83
        [TestCase("sntrup761x25519-sha512")]     // and NTRU Prime since 0.78
        public async Task Plink_CompletesTransport_WithOurServer(String KeyExchange, CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);

            var hostKey  = SshHostKey.GenerateEd25519();

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

                                     // Authentication is another test's subject; close so plink stops waiting.
                                     await pipe.Output.CompleteAsync();
                                     await pipe.Input. CompleteAsync();

                                     return algorithms;

                                 }, CancellationToken);

                var clientTask = PlinkAsync(workspace, port, host!,
                                            SshFingerprint.Sha256(hostKey.PublicKeyBlob),
                                            "true", CancellationToken);

                var finished = await Task.WhenAny(serverTask, Task.Delay(TimeSpan.FromSeconds(25), CancellationToken));

                if (finished != serverTask)
                {
                    var (_, _, timedOutStderr) = await clientTask;
                    Assert.Fail($"the handshake never completed — plink said:\n{timedOutStderr}");
                }

                var algorithms     = await serverTask;
                var (_, _, stderr) = await clientTask;

                TestContext.Out.WriteLine($"PuTTY agreed on {algorithms.KeyExchange} / {algorithms.CipherClientToServer} / {algorithms.HostKey}");

                Assert.That(algorithms.KeyExchange, Is.EqualTo(KeyExchange),
                            $"plink must complete {KeyExchange} with us. stderr:\n{stderr}");

            }
            finally
            {
                await CleanupAsync(workspace);
            }

        }

        #endregion

        #region Plink_RejectsAWrongHostKey

        /// <summary>
        /// Host-key verification from PuTTY's side: with a foreign fingerprint pinned via <c>-hostkey</c>
        /// and <c>-batch</c> forbidding any prompt, plink must refuse the connection outright.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Plink_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            var (workspace, userKey) = await PrepareAsync(CancellationToken);

            var hostKey      = SshHostKey.GenerateEd25519();
            var somebodyElse = SshHostKey.GenerateEd25519();

            var server = new SshServer(new SshServerOptions {
                             HostKeys      = [ hostKey ],
                             Authenticator = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                             ExecHandler   = async (context, ct) => { await context.WriteAsync("unreachable\n", ct); return 0; }
                         });

            try
            {

                await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
                if (host is null)
                    Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");

                var (exitCode, stdout, stderr) = await PlinkAsync(workspace, port, host!,
                                                                  SshFingerprint.Sha256(somebodyElse.PublicKeyBlob),
                                                                  "true", CancellationToken);

                TestContext.Out.WriteLine($"plink refused with: {stderr.Trim()}");

                Assert.Multiple(() => {
                    Assert.That(exitCode, Is.Not.EqualTo(0), "plink must not accept a host key it did not pin");
                    Assert.That(stdout,   Does.Not.Contain("unreachable"), "no session may be established");
                    Assert.That(stderr,   Does.Contain("host key").IgnoreCase,
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

    }

}
