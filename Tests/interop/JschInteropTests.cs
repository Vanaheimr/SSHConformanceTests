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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Interoperability against <b>JSch</b> - the other Java lineage, and the more widely embedded one.
    ///
    /// <para>
    /// Ant's <c>sshexec</c> and <c>scp</c> tasks, Maven wagons, Eclipse, Jenkins plugins, Spring
    /// Integration and a long tail of Java tools carry JSch. JCraft stopped at 0.1.55 in 2018,
    /// before the ETM MACs and AEAD ciphers our server insists on; the maintained line is Matthias Wiede's
    /// fork, 0.2.x, which Debian 13 ships (0.2.19) under the old package name. It shares no code
    /// with Apache MINA SSHD: its transport, its key parsers and its SFTP client are its own.
    /// </para>
    ///
    /// <para>
    /// The peer is a small Java program in <c>interop/jsch/</c>, compiled on demand like the MINA peer:
    /// natively on Windows with the jars <c>setup-windows.ps1</c> fetched, otherwise inside WSL against the
    /// distribution's. JSch is a client only, so there is one direction here:
    /// JSch against our server, speaking the JSON contract of <see cref="PeerPlatform.RunPeerAsync"/>. It
    /// reads the key files our generator wrote with no conversion step.
    /// </para>
    ///
    /// <para>
    /// JSch 0.2.19 has <c>sntrup761x25519-sha512@openssh.com</c> (through BouncyCastle, which is on the
    /// class path for ChaCha20 and Ed25519 as well) but no ML-KEM, so the post-quantum case is sntrup761.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.JSch")]
    public class JschInteropTests
    {

        #region (private) harness - build the JSch peer once per fixture

        private const  String   Username   = "hermoduser";

        /// <summary>
        /// The jars, by their distribution names: JSch, and the BouncyCastle provider its sntrup761,
        /// ChaCha20 and Ed25519 classes are built on.
        /// </summary>
        private static readonly String[] Jars = [ "jsch", "bcprov" ];

        private static JavaToolchain  toolchain = JavaPeers.Linux;
        private static String?        peerRoot;
        private static String?        skipReason;

        private static PeerPlatform Platform
            => toolchain.Platform;

        [OneTimeSetUp]
        public async Task BuildPeerAsync()
        {

            if (JavaPeers.Windows is { } windows && windows.HasJars(Jars))
            {
                await BuildNativelyAsync(windows);
                return;
            }

            if (WslInterop.UnavailableReason is not null)
            {
                skipReason = OperatingSystem.IsWindows()
                                 ? $"{JavaPeers.WhyNotOnWindows(Jars)}, and no WSL to build in: {WslInterop.UnavailableReason}"
                                 : WslInterop.UnavailableReason;
                return;
            }

            var (hasToolchain, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "command -v javac >/dev/null && test -f /usr/share/java/jsch.jar"],
                                                                 CancellationToken.None);
            if (hasToolchain != 0)
            {
                skipReason = "No JSch build toolchain inside WSL - install default-jdk-headless and libjsch-java (interop/setup-wsl.sh does).";
                return;
            }

            var home = await WslInterop.HomeAsync(CancellationToken.None);
            peerRoot = $"{home}/.hermod-interop/jsch_{Guid.NewGuid():N}";

            var source = WslInterop.ToWslPath(Path.Combine(WslInterop.InteropDirectory!, "jsch", "JschPeer.java"));

            // -Xlint:-path: the BouncyCastle jar names optional companions in its manifest that the
            // distribution does not ship, which is noise, not a problem.
            var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                 "-e", "bash", "-c",
                                                 $"mkdir -p {peerRoot} && javac -Xlint:-path -d {peerRoot} -cp {toolchain.ClassPath([], Jars)} {source}"
                                             ], CancellationToken.None);

            if (exitCode != 0)
            {
                skipReason = $"Could not build the JSch peer (exit {exitCode}).\n{stdout}\n{stderr}";
                peerRoot   = null;
                return;
            }

        }

        /// <summary>
        /// Compile the peer with a Java on this Windows machine, against the jars setup-windows.ps1 fetched.
        /// </summary>
        private static async Task BuildNativelyAsync(JavaToolchain Windows)
        {

            toolchain = Windows;
            peerRoot  = Path.Combine(Path.GetTempPath(), "hermod_jsch_peer_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(peerRoot);

            var (exitCode, stdout, stderr) = await Platform.RunAsync(toolchain.Javac,
                                                                     [ "-Xlint:-path", "-d", peerRoot, "-cp", toolchain.ClassPath([], Jars),
                                                                       Path.Combine(WslInterop.InteropDirectory!, "jsch", "JschPeer.java") ],
                                                                     CancellationToken.None);

            if (exitCode != 0)
                skipReason = $"Could not build the JSch peer with {toolchain.Javac} (exit {exitCode}).\n{stdout}\n{stderr}";

        }

        [OneTimeTearDown]
        public async Task RemovePeerAsync()
        {

            if (peerRoot is null)
                return;

            if (Platform == PeerPlatform.Windows)
                try { Directory.Delete(peerRoot, recursive: true); } catch { }

            else
                try { await WslInterop.RunAsync(["-e", "rm", "-rf", peerRoot], CancellationToken.None); } catch { }

        }


        private static void SkipIfUnavailable()
        {
            if (skipReason is not null)
                Assert.Ignore(skipReason);
        }

        private static Task<PeerRunResult> RunClientAsync(Dictionary<String, Object?> Configuration, CancellationToken CancellationToken)
            => Platform.RunPeerAsync("JSch", toolchain.Java, [ "-cp", toolchain.ClassPath([ peerRoot! ], Jars), "JschPeer", "client" ], Configuration, CancellationToken);


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

            public String WslUserKey => Platform.ToPeerPath(Path.Combine(WindowsRoot, "user"));

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
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_jsch_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "jsch-interop", CancellationToken);

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

            var host = await Platform.ResolveHostAsync(CancellationToken);
            if (host is null)
            {
                await server.DisposeAsync();
                Assert.Ignore($"WSL cannot reach the test listener on port {port} - check the Windows firewall.");
            }

            return new OurServer(server, host!, port, hostKey, windowsRoot, audit);

        }

        #endregion


        #region Jsch_RunsCommand_OnOurServer

        /// <summary>
        /// The whole stack as JSch sees it, starting with its parser reading the <c>openssh-key-v1</c>
        /// file our generator wrote: our command output and exit status must reach it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task Jsch_RunsCommand_OnOurServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("exec");
            configuration["command"] = Command;

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine($"{result.PeerVersion} saw '{result.ServerVersion}': {result.AlgorithmSummary}");

            Assert.Multiple(() => {
                Assert.That(result.Ok,         Is.True, $"JSch could not run the command.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,     Is.EqualTo($"hermod ran: {Command}\n"), "our command output must reach JSch");
                Assert.That(result.ExitStatus, Is.EqualTo(ExpectedExit),               "JSch must see our exit status");
            });

        }

        #endregion

        #region Jsch_CompletesKeyExchange_WithOurServer

        /// <summary>
        /// The key-exchange matrix, one method at a time: JSch may offer only the one, so a login proves
        /// both sides derived the same secret and the same exchange hash. sntrup761 is the post-quantum
        /// hybrid both of us implement independently - JSch on BouncyCastle's sntrup761.
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
        public async Task Jsch_CompletesKeyExchange_WithOurServer(String KeyExchange, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["kex_algs"] = new[] { KeyExchange };

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine(result.AlgorithmSummary);

            Assert.That(result.Ok, Is.True, $"JSch could not complete {KeyExchange} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
            Assert.That(result.Algorithms?["kex"], Is.EqualTo(KeyExchange));

        }

        #endregion

        #region Jsch_CompletesCipher_WithOurServer

        /// <summary>
        /// Every cipher and MAC our server offers, each the only one JSch may use - in both directions,
        /// because the restriction applies to both.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("chacha20-poly1305@openssh.com", null)]
        [TestCase("aes256-gcm@openssh.com",        null)]
        [TestCase("aes128-gcm@openssh.com",        null)]
        [TestCase("aes256-ctr",                    "hmac-sha2-256-etm@openssh.com")]
        [TestCase("aes128-ctr",                    "hmac-sha2-512-etm@openssh.com")]
        public async Task Jsch_CompletesCipher_WithOurServer(String Cipher, String? Mac, CancellationToken CancellationToken)
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
                Assert.That(result.Ok, Is.True, $"JSch could not use {Cipher}/{Mac} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,                   Is.EqualTo("hermod ran: hello\n"), "data must survive the cipher both ways");
                Assert.That(result.Algorithms?["cipher_out"], Is.EqualTo(Cipher));
                Assert.That(result.Algorithms?["cipher_in"],  Is.EqualTo(Cipher));
                if (Mac is not null)
                    Assert.That(result.Algorithms?["mac_out"], Is.EqualTo(Mac));
            });

        }

        #endregion

        #region Jsch_VerifiesOurHostKey

        /// <summary>
        /// Each host-key algorithm we can sign with, as the only one JSch accepts: a completed login
        /// means JSch verified our signature over the exchange hash with it - for RSA, the SHA-2
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
        public async Task Jsch_VerifiesOurHostKey(String Algorithm, String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, HostKey: GenerateKey(KeyType));

            var configuration = server.Configuration("connect");
            configuration["host_key_algs"] = new[] { Algorithm };

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok, Is.True, $"JSch did not accept our {Algorithm} host key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.Algorithms?["host_key"],           Is.EqualTo(KeyType));
                Assert.That(result.Algorithms?["host_key_algorithm"], Is.EqualTo(Algorithm));
            });

        }

        #endregion

        #region Jsch_LogsInWithOurKey

        /// <summary>
        /// Every key type our generator writes, read by JSch's own <c>openssh-key-v1</c> parser and used
        /// to sign the login - a statement about our key writer as much as about authentication. RSA
        /// signs with SHA-2, which JSch picks from our <c>server-sig-algs</c>.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256")]
        [TestCase("ecdsa-sha2-nistp384")]
        [TestCase("ecdsa-sha2-nistp521")]
        [TestCase("ssh-rsa")]
        public async Task Jsch_LogsInWithOurKey(String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, UserKey: GenerateKey(KeyType));

            var result = await RunClientAsync(server.Configuration("connect"), CancellationToken);

            Assert.That(result.Ok, Is.True, $"JSch could not log in with our {KeyType} key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

        }

        #endregion

        #region Jsch_TransfersFiles_OnOurServer

        /// <summary>
        /// JSch's SFTP client on our subsystem: a directory is made, a file uploaded - with the close
        /// checked, where a server may still refuse it - renamed, linked to, read back through the link
        /// and listed, and the link removed again. What landed on our disk is checked.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task Jsch_TransfersFiles_OnOurServer(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, ServeSftp: true);

            var content = RandomNumberGenerator.GetBytes(1_048_576);
            var upload  = Path.Combine(server.WindowsRoot, "upload.bin");
            var back    = Path.Combine(server.WindowsRoot, "back.bin");
            await File.WriteAllBytesAsync(upload, content, CancellationToken);

            var configuration = server.Configuration("sftp");
            configuration["upload_path"]   = Platform.ToPeerPath(upload);
            configuration["download_path"] = Platform.ToPeerPath(back);
            configuration["remote_dir"]    = "/jsch";

            var result = await RunClientAsync(configuration, CancellationToken);
            var root   = Path.Combine(server.WindowsRoot, "root", "jsch");

            Assert.That(result.Ok, Is.True, $"JSch's SFTP client failed in stage '{result.Stage}'.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

            Assert.Multiple(() => {

                Assert.That(File.ReadAllBytes(Path.Combine(root, "data.bin")), Is.EqualTo(content), "the upload landed every byte, and was renamed");
                Assert.That(File.ReadAllBytes(back),                           Is.EqualTo(content), "the download through the link read every byte back");
                Assert.That(File.Exists(Path.Combine(root, "upload.bin")),     Is.False,            "renamed, not copied");
                Assert.That(File.Exists(Path.Combine(root, "link.bin")),       Is.False,            "the link was removed");

                Assert.That(result.Listing, Is.EquivalentTo(new[] { "data.bin", "link.bin" }), "the listing as JSch saw it");
                Assert.That(result.StdOut,  Does.Contain("readlink=data.bin\n")
                                                .And.Contain("lstat_symlink=1\n")
                                                .And.Contain($"stat_size={content.Length}\n"), "the link and the file as JSch saw them");

            });

        }

        #endregion

        #region Jsch_RejectsAWrongHostKey

        /// <summary>
        /// With some other key pinned, JSch must stop before it authenticates: proof that the key we
        /// present really is the one that reaches it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Jsch_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["host_key_b64"] = Convert.ToBase64String(SshHostKey.GenerateEd25519().PublicKeyBlob);

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok,        Is.False,                "JSch must not accept a host key it did not pin");
                Assert.That(result.ErrorType, Is.EqualTo("HostKeyMismatch"), result.FailureReport);
                Assert.That(result.Stage,     Is.EqualTo("host-key"), "and it must stop there, before authenticating");
            });

        }

        #endregion

    }

}
