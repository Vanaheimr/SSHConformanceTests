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

using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Interoperability against <b>Apache MINA SSHD</b>, both ways - the Java lineage.
    ///
    /// <para>
    /// MINA SSHD is the SSH stack of the Java world: Jenkins, Gerrit, Eclipse's JGit and a long tail of
    /// Java servers embed it, as client and as server. It shares no code with any C implementation, and
    /// its key parsers, its state machine and its SFTP server are its own.
    /// </para>
    ///
    /// <para>
    /// The peer is a small Java program in <c>interop/mina/</c>, compiled on demand inside WSL against
    /// the distribution's jars (Debian 13: 2.13.2), like the libssh peer. It plays both roles: a client
    /// that speaks the JSON contract of <see cref="WslInterop.RunPeerAsync"/>, and a server that answers
    /// <c>exec</c> and serves MINA's own SFTP server. Both read the key files our generator wrote with
    /// no conversion step.
    /// </para>
    ///
    /// <para>
    /// MINA 2.13 has <c>sntrup761x25519-sha512@openssh.com</c> but no ML-KEM, so the post-quantum
    /// cases are the sntrup761 ones. Its server also still offers <c>aes192-ctr</c>, which lets our
    /// client's side of it be checked as well.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.MinaSshd")]
    public class MinaSshdInteropTests
    {

        #region (private) harness - build the MINA peer once per fixture

        private const  String   Username   = "hermoduser";

        /// <summary>
        /// The distribution's jars: MINA's three modules, its logging facade and the EdDSA and
        /// BouncyCastle providers it finds Ed25519 and friends through.
        /// </summary>
        private const  String   ClassPath  = "/usr/share/java/sshd-common.jar:/usr/share/java/sshd-core.jar:/usr/share/java/sshd-sftp.jar:" +
                                             "/usr/share/java/slf4j-api.jar:/usr/share/java/eddsa.jar:" +
                                             "/usr/share/java/bcprov.jar:/usr/share/java/bcpkix.jar:/usr/share/java/bcutil.jar";

        private static String?  peerRoot;
        private static String?  skipReason;

        [OneTimeSetUp]
        public async Task BuildPeerAsync()
        {

            if (WslInterop.UnavailableReason is not null)
            {
                skipReason = WslInterop.UnavailableReason;
                return;
            }

            var (hasToolchain, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "command -v javac >/dev/null && test -f /usr/share/java/sshd-core.jar"],
                                                                 CancellationToken.None);
            if (hasToolchain != 0)
            {
                skipReason = "No MINA SSHD build toolchain inside WSL - install default-jdk-headless and libmina-sshd-java (interop/setup-wsl.sh does).";
                return;
            }

            var home = await WslInterop.HomeAsync(CancellationToken.None);
            peerRoot = $"{home}/.hermod-interop/mina_{Guid.NewGuid():N}";

            var source = WslInterop.ToWslPath(Path.Combine(WslInterop.InteropDirectory!, "mina", "MinaPeer.java"));

            // -Xlint:-path: the BouncyCastle jars name optional companions in their manifests that the
            // distribution does not ship, which is noise, not a problem.
            var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                 "-e", "bash", "-c",
                                                 $"mkdir -p {peerRoot} && javac -Xlint:-path -d {peerRoot} -cp {ClassPath} {source}"
                                             ], CancellationToken.None);

            if (exitCode != 0)
            {
                skipReason = $"Could not build the MINA SSHD peer (exit {exitCode}).\n{stdout}\n{stderr}";
                peerRoot   = null;
                return;
            }

        }

        [OneTimeTearDown]
        public async Task RemovePeerAsync()
        {
            if (peerRoot is not null)
                try { await WslInterop.RunAsync(["-e", "rm", "-rf", peerRoot], CancellationToken.None); } catch { }
        }


        private static void SkipIfUnavailable()
        {
            if (skipReason is not null)
                Assert.Ignore(skipReason);
        }

        /// <summary>The client stays silent beside its JSON; the server logs through slf4j-simple.</summary>
        private static String JavaClassPath(String Logger)
            => $"{peerRoot}:{ClassPath}:/usr/share/java/{Logger}.jar";

        private static Task<PeerRunResult> RunClientAsync(Dictionary<String, Object?> Configuration, CancellationToken CancellationToken)
            => WslInterop.RunPeerAsync("MINA SSHD", ["-e", "java", "-cp", JavaClassPath("slf4j-nop"), "MinaPeer", "client"], Configuration, CancellationToken);


        private static ISshHostKey GenerateKey(String Type)
            => Type switch {
                   "ssh-ed25519" => SshHostKey.GenerateEd25519(),
                   "ssh-rsa"     => SshHostKey.GenerateRsa(),
                   _             => SshHostKey.GenerateEcdsa(Type)
               };


        /// <summary>
        /// Our server on every interface, the address the peer must dial, and a workspace with the
        /// client's key written by our generator.
        /// </summary>
        private sealed record OurServer(SshServer           Server,
                                        String              Host,
                                        Int32               Port,
                                        ISshHostKey         HostKey,
                                        String              WindowsRoot,
                                        RecordingAuditSink  Audit) : IAsyncDisposable
        {

            public String WslUserKey => WslInterop.ToWslPath(Path.Combine(WindowsRoot, "user"));

            public Dictionary<String, Object?> Configuration(String Action)
                => new () {
                       ["action"]       = Action,
                       ["host"]         = Host,
                       ["port"]         = Port,
                       ["username"]     = Username,
                       ["key_path"]     = WslUserKey,
                       ["host_key_b64"] = Convert.ToBase64String(HostKey.PublicKeyBlob)
                   };

            public async ValueTask DisposeAsync()
            {
                await Server.DisposeAsync();
                try { Directory.Delete(WindowsRoot, recursive: true); } catch { }
            }

        }

        private static async Task<OurServer> StartOurServerAsync(CancellationToken  CancellationToken,
                                                                 ISshHostKey?       HostKey     = null,
                                                                 ISshHostKey?       UserKey     = null,
                                                                 Boolean            ServeSftp   = false)
        {

            SkipIfUnavailable();

            var hostKey     = HostKey ?? SshHostKey.GenerateEd25519();
            var userKey     = UserKey ?? SshHostKey.GenerateEd25519();
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_mina_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "mina-interop", CancellationToken);

            var audit  = new RecordingAuditSink();

            var server = new SshServer(new SshServerOptions {
                             HostKeys       = [ hostKey ],
                             Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                             SftpFileSystem = ServeSftp ? new LocalSftpFileSystem(Path.Combine(windowsRoot, "root")) : null,
                             AuditSink      = audit,
                             ExecHandler    = async (context, ct) => {
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
                Assert.Ignore($"WSL cannot reach the test listener on port {port} - check the Windows firewall.");
            }

            return new OurServer(server, host!, port, hostKey, windowsRoot, audit);

        }


        /// <summary>
        /// A MINA SSHD server in WSL with a host key and an authorized key, both written by our generator.
        /// </summary>
        private sealed record MinaServer(WslServer   Peer,
                                         ISshHostKey HostKey,
                                         ISshHostKey UserKey,
                                         String      WindowsRoot) : IAsyncDisposable
        {

            public Int32  Port    => Peer.Port;
            public String WslRoot => WslInterop.ToWslPath(WindowsRoot);

            public SSHClientOptions ClientOptions(Func<Byte[], Boolean>? VerifyHostKey = null)
                => new () {
                       Username      = User_Id.Parse(Username),
                       Credentials   = [ UserKey ],
                       VerifyHostKey = VerifyHostKey ?? (blob => blob.AsSpan().SequenceEqual(HostKey.PublicKeyBlob))
                   };

            public async ValueTask DisposeAsync()
            {
                await Peer.DisposeAsync();
                try { Directory.Delete(WindowsRoot, recursive: true); } catch { }
            }

        }

        private static async Task<MinaServer> StartMinaServerAsync(CancellationToken  CancellationToken,
                                                                   ISshHostKey?       HostKey  = null,
                                                                   ISshHostKey?       UserKey  = null)
        {

            SkipIfUnavailable();

            var hostKey     = HostKey ?? SshHostKey.GenerateEd25519();
            var userKey     = UserKey ?? SshHostKey.GenerateEd25519();
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_minad_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(hostKey, Path.Combine(windowsRoot, "host"), "mina-interop-host", CancellationToken);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "mina-interop-user", CancellationToken);

            var wslRoot = WslInterop.ToWslPath(windowsRoot);

            // A host key is kept private, as it should be, whether or not the server insists.
            await WslInterop.RunAsync(["-e", "chmod", "600", $"{wslRoot}/host"], CancellationToken);

            var peer = await WslInterop.StartServerAsync(port => $"java -cp {JavaClassPath("slf4j-simple")} MinaPeer server {port} {wslRoot}/host {wslRoot}/user.pub",
                                                         CancellationToken);

            return new MinaServer(peer, hostKey, userKey, windowsRoot);

        }

        #endregion


        #region Mina_RunsCommand_OnOurServer

        /// <summary>
        /// The whole stack as MINA sees it, starting with its parser reading the <c>openssh-key-v1</c>
        /// file our generator wrote: our command output and exit status must reach it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task Mina_RunsCommand_OnOurServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("exec");
            configuration["command"] = Command;

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine($"{result.PeerVersion} saw '{result.ServerVersion}': {result.AlgorithmSummary}");

            Assert.Multiple(() => {
                Assert.That(result.Ok,         Is.True, $"MINA could not run the command.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,     Is.EqualTo($"hermod ran: {Command}\n"), "our command output must reach MINA");
                Assert.That(result.ExitStatus, Is.EqualTo(ExpectedExit),               "MINA must see our exit status");
            });

        }

        #endregion

        #region Mina_CompletesKeyExchange_WithOurServer

        /// <summary>
        /// The key-exchange matrix, one method at a time: MINA may offer only the one, so a login proves
        /// both sides derived the same secret and the same exchange hash. sntrup761 is the post-quantum
        /// hybrid both of us implement independently.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("sntrup761x25519-sha512@openssh.com")]
        [TestCase("curve25519-sha256")]
        [TestCase("curve25519-sha256@libssh.org")]
        [TestCase("ecdh-sha2-nistp256")]
        [TestCase("ecdh-sha2-nistp384")]
        [TestCase("ecdh-sha2-nistp521")]
        [TestCase("diffie-hellman-group14-sha256")]
        [TestCase("diffie-hellman-group16-sha512")]
        public async Task Mina_CompletesKeyExchange_WithOurServer(String KeyExchange, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["kex_algs"] = new[] { KeyExchange };

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine(result.AlgorithmSummary);

            Assert.That(result.Ok, Is.True, $"MINA could not complete {KeyExchange} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
            Assert.That(result.Algorithms?["kex"], Is.EqualTo(KeyExchange));

        }

        #endregion

        #region Mina_CompletesCipher_WithOurServer

        /// <summary>
        /// Every cipher and MAC our server offers, each the only one MINA may use - in both directions,
        /// because the restriction applies to both.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("chacha20-poly1305@openssh.com", null)]
        [TestCase("aes256-gcm@openssh.com",        null)]
        [TestCase("aes128-gcm@openssh.com",        null)]
        [TestCase("aes256-ctr",                    "hmac-sha2-256-etm@openssh.com")]
        [TestCase("aes128-ctr",                    "hmac-sha2-512-etm@openssh.com")]
        public async Task Mina_CompletesCipher_WithOurServer(String Cipher, String? Mac, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("exec");
            configuration["command"] = "hello";
            configuration["ciphers"] = new[] { Cipher };
            if (Mac is not null)
                configuration["macs"] = new[] { Mac };

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine(result.AlgorithmSummary);

            Assert.Multiple(() => {
                Assert.That(result.Ok, Is.True, $"MINA could not use {Cipher}/{Mac} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,                   Is.EqualTo("hermod ran: hello\n"), "data must survive the cipher both ways");
                Assert.That(result.Algorithms?["cipher_out"], Is.EqualTo(Cipher));
                Assert.That(result.Algorithms?["cipher_in"],  Is.EqualTo(Cipher));
                if (Mac is not null)
                    Assert.That(result.Algorithms?["mac_out"], Is.EqualTo(Mac));
            });

        }

        #endregion

        #region Mina_VerifiesOurHostKey

        /// <summary>
        /// Each host-key algorithm we can sign with, as the only one MINA accepts: a completed login
        /// means MINA verified our signature over the exchange hash with it - for RSA, the SHA-2
        /// signatures specifically, never SHA-1.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("ssh-ed25519",         "ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256")]
        [TestCase("ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384")]
        [TestCase("ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521")]
        [TestCase("rsa-sha2-256",        "ssh-rsa")]
        [TestCase("rsa-sha2-512",        "ssh-rsa")]
        public async Task Mina_VerifiesOurHostKey(String Algorithm, String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, HostKey: GenerateKey(KeyType));

            var configuration = server.Configuration("connect");
            configuration["host_key_algs"] = new[] { Algorithm };

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok, Is.True, $"MINA did not accept our {Algorithm} host key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.Algorithms?["host_key"],           Is.EqualTo(KeyType));
                Assert.That(result.Algorithms?["host_key_algorithm"], Is.EqualTo(Algorithm));
            });

        }

        #endregion

        #region Mina_LogsInWithOurKey

        /// <summary>
        /// Every key type our generator writes, read by MINA's own <c>openssh-key-v1</c> parser and used
        /// to sign the login - a statement about our key writer as much as about authentication.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256")]
        [TestCase("ecdsa-sha2-nistp384")]
        [TestCase("ecdsa-sha2-nistp521")]
        [TestCase("ssh-rsa")]
        public async Task Mina_LogsInWithOurKey(String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, UserKey: GenerateKey(KeyType));

            var result = await RunClientAsync(server.Configuration("connect"), CancellationToken);

            Assert.That(result.Ok, Is.True, $"MINA could not log in with our {KeyType} key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

        }

        #endregion

        #region Mina_TransfersFiles_OnOurServer

        /// <summary>
        /// MINA's SFTP client on our subsystem: a directory is made, a file uploaded - with the close
        /// checked, where a server may still refuse it - renamed, linked to, read back through the link
        /// and listed, and the link removed again. What landed on our disk is checked.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task Mina_TransfersFiles_OnOurServer(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, ServeSftp: true);

            var content = RandomNumberGenerator.GetBytes(1_048_576);
            var upload  = Path.Combine(server.WindowsRoot, "upload.bin");
            var back    = Path.Combine(server.WindowsRoot, "back.bin");
            await File.WriteAllBytesAsync(upload, content, CancellationToken);

            var configuration = server.Configuration("sftp");
            configuration["upload_path"]   = WslInterop.ToWslPath(upload);
            configuration["download_path"] = WslInterop.ToWslPath(back);
            configuration["remote_dir"]    = "/mina";

            var result = await RunClientAsync(configuration, CancellationToken);
            var root   = Path.Combine(server.WindowsRoot, "root", "mina");

            Assert.That(result.Ok, Is.True, $"MINA's SFTP client failed in stage '{result.Stage}'.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

            Assert.Multiple(() => {

                Assert.That(File.ReadAllBytes(Path.Combine(root, "data.bin")), Is.EqualTo(content), "the upload landed every byte, and was renamed");
                Assert.That(File.ReadAllBytes(back),                           Is.EqualTo(content), "the download through the link read every byte back");
                Assert.That(File.Exists(Path.Combine(root, "upload.bin")),     Is.False,            "renamed, not copied");
                Assert.That(File.Exists(Path.Combine(root, "link.bin")),       Is.False,            "the link was removed");

                Assert.That(result.Listing, Is.EquivalentTo(new[] { "data.bin", "link.bin" }), "the listing as MINA saw it");
                Assert.That(result.StdOut,  Does.Contain("readlink=data.bin\n")
                                                .And.Contain("lstat_symlink=1\n")
                                                .And.Contain($"stat_size={content.Length}\n"), "the link and the file as MINA saw them");

            });

        }

        #endregion

        #region Mina_RejectsAWrongHostKey

        /// <summary>
        /// With some other key pinned, MINA must stop before it authenticates: proof that the key we
        /// present really is the one that reaches it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Mina_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["host_key_b64"] = Convert.ToBase64String(SshHostKey.GenerateEd25519().PublicKeyBlob);

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok,        Is.False,                "MINA must not accept a host key it did not pin");
                Assert.That(result.ErrorType, Is.EqualTo("HostKeyMismatch"), result.FailureReport);
                Assert.That(result.Stage,     Is.EqualTo("host-key"), "and it must stop there, before authenticating");
            });

        }

        #endregion


        #region OurClient_RunsCommand_OnMinaServer

        /// <summary>
        /// The other direction: our client against MINA's server, which read the host key our generator
        /// wrote. Output and exit status must come back.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task OurClient_RunsCommand_OnMinaServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            await using var mina = await StartMinaServerAsync(CancellationToken);

            SSHClient client;
            try
            {
                client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(mina.Port), mina.ClientOptions(), CancellationToken);
            }
            catch (Exception exception)
            {
                throw new AssertionException($"Our client could not connect to MINA.\n{exception.Message}\n{mina.Peer.Output}", exception);
            }

            await using var _ = client;

            var result = await client.Execute(Command, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.StandardOutput, Is.EqualTo($"mina ran: {Command}\n"), $"our client must read MINA's output.\n{mina.Peer.Output}");
                Assert.That(result.ExitCode,       Is.EqualTo(ExpectedExit),              "and the exit status it sent");
            });

        }

        #endregion

        #region OurClient_CompletesKeyExchange_WithMinaServer

        /// <summary>
        /// Our client's key-exchange matrix against MINA's server, our offer restricted to the one
        /// method. The handshake completing is the assertion: MINA's host-key signature covers the
        /// exchange hash, which we verify.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("sntrup761x25519-sha512@openssh.com")]
        [TestCase("curve25519-sha256")]
        [TestCase("curve25519-sha256@libssh.org")]
        [TestCase("ecdh-sha2-nistp256")]
        [TestCase("ecdh-sha2-nistp384")]
        [TestCase("ecdh-sha2-nistp521")]
        [TestCase("diffie-hellman-group14-sha256")]
        [TestCase("diffie-hellman-group16-sha512")]
        public async Task OurClient_CompletesKeyExchange_WithMinaServer(String KeyExchange, CancellationToken CancellationToken)
        {

            await using var mina = await StartMinaServerAsync(CancellationToken);

            var pipe = await SshTcp.ConnectAsync(new IPSocket(IPv4Address.Localhost, IPPort.Parse(mina.Port)), CancellationToken);

            try
            {

                using var transport = await SshTransport.ClientHandshakeAsync(
                                          pipe,
                                          VerifyHostKey:     blob => blob.AsSpan().SequenceEqual(mina.HostKey.PublicKeyBlob),
                                          KeyExchanges:      [ KeyExchange ],
                                          CancellationToken: CancellationToken);

                TestContext.Out.WriteLine($"MINA agreed on {transport.Algorithms.KeyExchange} / {transport.Algorithms.CipherClientToServer}, strict KEX {transport.Algorithms.StrictKex}");

                Assert.That(transport.Algorithms.KeyExchange, Is.EqualTo(KeyExchange), mina.Peer.Output);

            }
            finally
            {
                await pipe.Output.CompleteAsync();
                await pipe.Input. CompleteAsync();
            }

        }

        #endregion

        #region OurClient_CompletesCipher_WithMinaServer

        /// <summary>
        /// Our client's cipher and MAC matrix against MINA's server, our offer restricted to the one
        /// pair, followed by a login over it - so packets cross the new keys in both directions. MINA's
        /// server still offers <c>aes192-ctr</c>, which no server of ours does by default; this is where
        /// our client's side of it meets a real peer. MINA also offers the encrypt-and-MAC
        /// <c>hmac-sha2-*</c>, which we deliberately do not implement (PLAN.md §0.5).
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("chacha20-poly1305@openssh.com", null)]
        [TestCase("aes256-gcm@openssh.com",        null)]
        [TestCase("aes128-gcm@openssh.com",        null)]
        [TestCase("aes256-ctr",                    "hmac-sha2-256-etm@openssh.com")]
        [TestCase("aes192-ctr",                    "hmac-sha2-512-etm@openssh.com")]
        [TestCase("aes128-ctr",                    "hmac-sha2-256-etm@openssh.com")]
        public async Task OurClient_CompletesCipher_WithMinaServer(String Cipher, String? Mac, CancellationToken CancellationToken)
        {

            await using var mina = await StartMinaServerAsync(CancellationToken);

            var pipe = await SshTcp.ConnectAsync(new IPSocket(IPv4Address.Localhost, IPPort.Parse(mina.Port)), CancellationToken);

            try
            {

                using var transport = await SshTransport.ClientHandshakeAsync(
                                          pipe,
                                          VerifyHostKey:     blob => blob.AsSpan().SequenceEqual(mina.HostKey.PublicKeyBlob),
                                          Ciphers:           [ Cipher ],
                                          Macs:              Mac is not null ? [ Mac ] : null,
                                          CancellationToken: CancellationToken);

                var authenticated = await UserAuthentication.ClientAuthenticateAsync(transport, User_Id.Parse(Username), [ mina.UserKey ], CancellationToken: CancellationToken);

                TestContext.Out.WriteLine($"MINA agreed on {transport.Algorithms.CipherClientToServer} / {transport.Algorithms.MacClientToServer}");

                Assert.Multiple(() => {
                    Assert.That(transport.Algorithms.CipherClientToServer, Is.EqualTo(Cipher), mina.Peer.Output);
                    Assert.That(transport.Algorithms.CipherServerToClient, Is.EqualTo(Cipher));
                    if (Mac is not null)
                    {
                        Assert.That(transport.Algorithms.MacClientToServer, Is.EqualTo(Mac));
                        Assert.That(transport.Algorithms.MacServerToClient, Is.EqualTo(Mac));
                    }
                    Assert.That(authenticated, Is.True, $"the login over {Cipher}/{Mac} must succeed.\n{mina.Peer.Output}");
                });

            }
            finally
            {
                await pipe.Output.CompleteAsync();
                await pipe.Input. CompleteAsync();
            }

        }

        #endregion

        #region OurClient_UsesEachKeyType_WithMinaServer

        /// <summary>
        /// Each key type both ways at once: MINA's server reads a host key of that type from the file our
        /// generator wrote and signs the exchange with it, and accepts our client's signature with a user
        /// key of the same type.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256")]
        [TestCase("ecdsa-sha2-nistp384")]
        [TestCase("ecdsa-sha2-nistp521")]
        [TestCase("ssh-rsa")]
        public async Task OurClient_UsesEachKeyType_WithMinaServer(String KeyType, CancellationToken CancellationToken)
        {

            await using var mina = await StartMinaServerAsync(CancellationToken, HostKey: GenerateKey(KeyType), UserKey: GenerateKey(KeyType));

            SSHClient client;
            try
            {
                client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(mina.Port), mina.ClientOptions(), CancellationToken);
            }
            catch (Exception exception)
            {
                throw new AssertionException($"Our client could not log in to MINA with {KeyType} keys.\n{exception.Message}\n{mina.Peer.Output}", exception);
            }

            await using var _ = client;

            var result = await client.Execute("hello", CancellationToken);

            Assert.That(result.StandardOutput, Is.EqualTo("mina ran: hello\n"), mina.Peer.Output);

        }

        #endregion

        #region OurClient_TransfersFiles_WithMinaSftpServer

        /// <summary>
        /// Our SFTP client against MINA's own SFTP server: a directory is made, a file uploaded with
        /// pipelined writes, renamed, stat'ed, linked to, read back through the link and listed, then
        /// removed with its directory. The link is made with a relative target, and where it points is
        /// checked on disk - the argument order of SSH_FXP_SYMLINK is the classic way to get it backwards.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task OurClient_TransfersFiles_WithMinaSftpServer(CancellationToken CancellationToken)
        {

            await using var mina = await StartMinaServerAsync(CancellationToken);

            var client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(mina.Port), mina.ClientOptions(), CancellationToken);
            await using var _ = client;

            await using var sftp = await client.OpenSFTPClient(CancellationToken);

            var content   = RandomNumberGenerator.GetBytes(1_048_576);
            var directory = $"{mina.WslRoot}/sftp";
            var onDisk    = Path.Combine(mina.WindowsRoot, "sftp");

            await sftp.MakeDirectoryAsync     (directory,                                          CancellationToken);
            await sftp.UploadAsync            ($"{directory}/upload.bin", content,                 CancellationToken);
            await sftp.RenameAsync            ($"{directory}/upload.bin", $"{directory}/data.bin", CancellationToken);
            await sftp.CreateSymbolicLinkAsync($"{directory}/link.bin",   "data.bin",              CancellationToken);

            var attributes = await sftp.StatAsync         ($"{directory}/data.bin", CancellationToken);
            var target     = await sftp.ReadLinkAsync     ($"{directory}/link.bin", CancellationToken);
            var link       = await sftp.LStatAsync        ($"{directory}/link.bin", CancellationToken);
            var downloaded = await sftp.DownloadAsync     ($"{directory}/link.bin", CancellationToken);
            var listing    = await sftp.ListDirectoryAsync(directory,               CancellationToken);

            Assert.Multiple(() => {
                Assert.That(File.ReadAllBytes(Path.Combine(onDisk, "data.bin")),          Is.EqualTo(content), "the upload landed every byte, and was renamed");
                Assert.That(File.Exists(Path.Combine(onDisk, "upload.bin")),              Is.False,            "renamed, not copied");
                Assert.That(new FileInfo(Path.Combine(onDisk, "link.bin")).LinkTarget,    Is.EqualTo("data.bin"), "the link was made where we meant it, pointing where we meant it");
                Assert.That(attributes.Size,                                              Is.EqualTo(content.Length));
                Assert.That(target,                                                       Is.EqualTo("data.bin"));
                Assert.That(link.IsSymbolicLink,                                          Is.True, "lstat must see the link itself");
                Assert.That(downloaded,                                                   Is.EqualTo(content), "the download through the link read every byte back");
                Assert.That(listing.Select(entry => entry.Name),                          Is.EquivalentTo(new[] { "data.bin", "link.bin" }));
            });

            await sftp.RemoveAsync         ($"{directory}/link.bin", CancellationToken);
            await sftp.RemoveAsync         ($"{directory}/data.bin", CancellationToken);
            await sftp.RemoveDirectoryAsync(directory,               CancellationToken);

            Assert.That(Directory.Exists(onDisk), Is.False, "the files and their directory were removed");

        }

        #endregion

        #region OurClient_RejectsAWrongMinaHostKey

        /// <summary>
        /// The same connection with some other key pinned: our client must fail closed against MINA.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_RejectsAWrongMinaHostKey(CancellationToken CancellationToken)
        {

            await using var mina = await StartMinaServerAsync(CancellationToken);

            var somebodyElse = SshHostKey.GenerateEd25519();

            Assert.That(async () => await SSHClient.Connect("127.0.0.1",
                                                            IPPort.Parse(mina.Port),
                                                            mina.ClientOptions(blob => blob.AsSpan().SequenceEqual(somebodyElse.PublicKeyBlob)),
                                                            CancellationToken),
                        Throws.TypeOf<SshHostKeyRejectedException>(),
                        "our client must refuse a host key that is not the one it pinned");

        }

        #endregion

    }

}
