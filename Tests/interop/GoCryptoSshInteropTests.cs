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
    /// Interoperability against <b>golang.org/x/crypto/ssh</b> — the strictest peer in the suite.
    ///
    /// <para>
    /// Go's implementation is spec-literal and deliberately narrow: no legacy ciphers, no SHA-1 key
    /// exchange, no sntrup761, and <c>mlkem768x25519-sha256</c> first in its default list since v0.38.0.
    /// It also reads our <c>openssh-key-v1</c> private key with <b>no conversion step at all</b>, unlike
    /// Dropbear and PuTTY, which each need their own format — so a successful login is a statement about
    /// our key writer as much as about the protocol.
    /// </para>
    ///
    /// <para>
    /// The peer is a small Go program in <c>interop/go/</c>, compiled on demand inside WSL. Without a Go
    /// toolchain these tests skip with instructions rather than fail; the first build also needs network
    /// access to fetch the module, after which Go's module cache makes it fast.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.Go")]
    public class GoCryptoSshInteropTests
    {

        #region (private) harness — build the Go peer once per fixture

        private static String? harnessBinary;
        private static String? harnessRoot;
        private static String? skipReason;

        [OneTimeSetUp]
        public async Task BuildHarnessAsync()
        {

            if (WslInterop.UnavailableReason is not null)
            {
                skipReason = WslInterop.UnavailableReason;
                return;
            }

            var (hasGo, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "command -v go >/dev/null"], CancellationToken.None);
            if (hasGo != 0)
            {
                skipReason = "No Go toolchain inside WSL — install it (interop/setup-wsl.sh installs golang-go).";
                return;
            }

            var home    = await WslInterop.HomeAsync(CancellationToken.None);
            harnessRoot = $"{home}/.hermod-interop/go_{Guid.NewGuid():N}";

            var source  = WslInterop.ToWslPath(Path.Combine(WslInterop.InteropDirectory!, "go"));

            // Built out of a copy rather than in place: the sources sit on /mnt/d, where builds are slow
            // and where 'go mod tidy' would drop a go.sum into the repository.
            var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                 "-e", "bash", "-c",
                                                 $"mkdir -p {harnessRoot} && cp {source}/go.mod {source}/main.go {harnessRoot}/ && " +
                                                 $"cd {harnessRoot} && go mod tidy && go build -o {harnessRoot}/hermod-interop ."
                                             ], CancellationToken.None);

            if (exitCode != 0)
            {
                skipReason = $"Could not build the Go interop harness (exit {exitCode}).\n{stdout}\n{stderr}";
                return;
            }

            harnessBinary = $"{harnessRoot}/hermod-interop";

        }

        [OneTimeTearDown]
        public async Task RemoveHarnessAsync()
        {
            if (harnessRoot is not null)
                try { await WslInterop.RunAsync(["-e", "rm", "-rf", harnessRoot], CancellationToken.None); } catch { }
        }


        private static void SkipIfUnavailable()
        {
            if (skipReason is not null)
                Assert.Ignore(skipReason);
        }

        private static Task<PeerRunResult> RunAsync(Dictionary<String, Object?> Configuration, CancellationToken CancellationToken)
            => WslInterop.RunPeerAsync("go x/crypto/ssh", ["-e", harnessBinary!], Configuration, CancellationToken);


        /// <summary>Start our server on every interface and work out the address the peer must dial.</summary>
        private static async Task<(SshServer Server, String Host, Int32 Port, ISshHostKey HostKey, String KeyPathWsl, String WindowsRoot, RecordingAuditSink Audit)>
            StartAsync(CancellationToken CancellationToken)
        {

            SkipIfUnavailable();

            var hostKey     = SshHostKey.GenerateEd25519();
            var userKey     = SshHostKey.GenerateEd25519();
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_go_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "go-interop", CancellationToken);

            var audit  = new RecordingAuditSink();

            var server = new SshServer(new SshServerOptions {
                             HostKeys      = [ hostKey ],
                             Authenticator = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                             AuditSink     = audit,
                             ExecHandler   = async (context, ct) => {
                                                 await context.WriteAsync($"hermod ran: {context.Command}\n", ct);
                                                 return context.Command == "fail" ? 42 : 0;
                                             }
                         });

            await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
            var port = server.LocalEndPoint.Port.ToInt32();

            var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
            if (host is null)
            {
                await server.DisposeAsync();
                Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");
            }

            return (server, host!, port, hostKey, WslInterop.ToWslPath(Path.Combine(windowsRoot, "user")), windowsRoot, audit);

        }

        private static Dictionary<String, Object?> Configuration(String Action, String Host, Int32 Port, String KeyPathWsl, ISshHostKey HostKey)
            => new () {
                   ["action"]       = Action,
                   ["host"]         = Host,
                   ["port"]         = Port,
                   ["username"]     = "hermoduser",
                   ["key_path"]     = KeyPathWsl,
                   ["host_key_b64"] = Convert.ToBase64String(HostKey.PublicKeyBlob)
               };

        #endregion


        #region GoCrypto_RunsCommand_OnOurServer

        /// <summary>
        /// The whole stack as Go sees it, including its parser reading the <c>openssh-key-v1</c> file our
        /// generator wrote — no conversion, no helper tool.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task GoCrypto_RunsCommand_OnOurServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            var (server, host, port, hostKey, keyPath, windowsRoot, audit) = await StartAsync(CancellationToken);

            try
            {

                var configuration = Configuration("exec", host, port, keyPath, hostKey);
                configuration["command"] = Command;

                var result = await RunAsync(configuration, CancellationToken);

                TestContext.Out.WriteLine($"Go saw '{result.ServerVersion}'");

                Assert.Multiple(() => {
                    Assert.That(result.Ok,         Is.True, $"Go could not run the command.\n{result.FailureReport}\n--- our server's audit ---\n{audit.Report}");
                    Assert.That(result.StdOut,     Is.EqualTo($"hermod ran: {Command}\n"), "our command output must reach Go");
                    Assert.That(result.ExitStatus, Is.EqualTo(ExpectedExit),               "Go must see our exit status");
                });

            }
            finally
            {
                await server.DisposeAsync();
                try { Directory.Delete(windowsRoot, recursive: true); } catch { }
            }

        }

        #endregion

        #region GoCrypto_CompletesPostQuantumTransport

        /// <summary>
        /// A fourth lineage on our post-quantum hybrid, and the one that puts it first by default:
        /// <c>mlkem768x25519-sha256</c> has led Go's key-exchange list since v0.38.0. The client is allowed
        /// to offer nothing else, so a session that reaches the command stage proves both sides derived the
        /// same ML-KEM-768 + X25519 secret.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task GoCrypto_CompletesPostQuantumTransport(CancellationToken CancellationToken)
        {

            var (server, host, port, hostKey, keyPath, windowsRoot, audit) = await StartAsync(CancellationToken);

            try
            {

                var configuration = Configuration("exec", host, port, keyPath, hostKey);
                configuration["command"]  = "pq";
                configuration["kex_algs"] = new[] { "mlkem768x25519-sha256" };

                var result = await RunAsync(configuration, CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(result.Ok,     Is.True,
                                $"Go must complete the PQ hybrid with us.\n{result.FailureReport}\n--- our server's audit ---\n{audit.Report}");
                    Assert.That(result.StdOut, Is.EqualTo("hermod ran: pq\n"),
                                "traffic after NEWKEYS must decrypt, which only holds if the shared secret matches");
                });

            }
            finally
            {
                await server.DisposeAsync();
                try { Directory.Delete(windowsRoot, recursive: true); } catch { }
            }

        }

        #endregion

        #region GoCrypto_RejectsAWrongHostKey

        /// <summary>
        /// Go's <c>FixedHostKey</c> is as strict as host-key checking gets: any mismatch aborts the
        /// handshake. Proof that the key we present really is the one reaching the peer.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task GoCrypto_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            var (server, host, port, _, keyPath, windowsRoot, _) = await StartAsync(CancellationToken);
            var somebodyElse = SshHostKey.GenerateEd25519();

            try
            {

                var result = await RunAsync(Configuration("connect", host, port, keyPath, somebodyElse), CancellationToken);

                TestContext.Out.WriteLine($"Go rejected us with: {result.ErrorType}: {result.Error}");

                Assert.Multiple(() => {
                    Assert.That(result.Ok,    Is.False, "Go must not accept a host key it did not pin");
                    Assert.That(result.Error, Is.Not.Null.And.Not.Empty);
                });

            }
            finally
            {
                await server.DisposeAsync();
                try { Directory.Delete(windowsRoot, recursive: true); } catch { }
            }

        }

        #endregion

    }

}
