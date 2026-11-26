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
    /// Interoperability against <b>libssh</b>, both ways - the first Tier 3 peer.
    ///
    /// <para>
    /// libssh is the third C lineage beside OpenSSH and Dropbear, and the one that arrives embedded in
    /// other products rather than as a tool of its own: KDE and GNOME's file managers, Ansible's
    /// network modules, and a long tail of appliances and devices link it, as client and as server.
    /// It is not libssh2 - the library behind curl, which <see cref="CurlLibSshInteropTests"/> covers -
    /// but an unrelated code base with its own key parser, its own state machine and its own SFTP
    /// server.
    /// </para>
    ///
    /// <para>
    /// Since libssh ships no command-line client or server, the peer is a small C program in
    /// <c>interop/libssh/</c>, compiled on demand inside WSL against the distribution's libssh (Debian
    /// 13: 0.11.5), like the Go peer. It plays both roles: a client that speaks the JSON contract of
    /// <see cref="WslInterop.RunPeerAsync"/>, and a server that answers <c>exec</c> and serves libssh's
    /// own SFTP server. Both read the key files our generator wrote with no conversion step.
    /// </para>
    ///
    /// <para>
    /// What is deliberately absent: post-quantum key exchange. Debian's libssh 0.11.5 accepts neither
    /// <c>sntrup761x25519-sha512</c> (under either name) nor <c>mlkem768x25519-sha256</c>, so those
    /// cases would test libssh's build rather than our interoperability - and on the Debian leg, where
    /// nothing may skip, they could only fail.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.LibSshC")]
    public class LibSshInteropTests
    {

        #region (private) harness - build the libssh peer once per fixture

        private const  String   Username = "hermoduser";

        private static String?  peerBinary;
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

            var (hasToolchain, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "command -v gcc >/dev/null && pkg-config --exists libssh jansson"],
                                                                 CancellationToken.None);
            if (hasToolchain != 0)
            {
                skipReason = "No libssh build toolchain inside WSL - install gcc, pkg-config, libssh-dev and libjansson-dev (interop/setup-wsl.sh does).";
                return;
            }

            var home = await WslInterop.HomeAsync(CancellationToken.None);
            peerRoot = $"{home}/.hermod-interop/libssh_{Guid.NewGuid():N}";

            var source = WslInterop.ToWslPath(Path.Combine(WslInterop.InteropDirectory!, "libssh", "libssh_peer.c"));

            var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                 "-e", "bash", "-c",
                                                 $"mkdir -p {peerRoot} && " +
                                                 $"gcc -O2 -Wall -o {peerRoot}/libssh-peer {source} $(pkg-config --cflags --libs libssh jansson)"
                                             ], CancellationToken.None);

            if (exitCode != 0)
            {
                skipReason = $"Could not build the libssh peer (exit {exitCode}).\n{stdout}\n{stderr}";
                return;
            }

            peerBinary = $"{peerRoot}/libssh-peer";

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

        private static Task<PeerRunResult> RunClientAsync(Dictionary<String, Object?> Configuration, CancellationToken CancellationToken)
            => WslInterop.RunPeerAsync("libssh", ["-e", peerBinary!, "client"], Configuration, CancellationToken);


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
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_libssh_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "libssh-interop", CancellationToken);

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
        /// A libssh server in WSL with a host key and an authorized key, both written by our generator.
        /// </summary>
        private sealed record LibSshServer(WslServer   Peer,
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

        private static async Task<LibSshServer> StartLibSshServerAsync(CancellationToken  CancellationToken,
                                                                       ISshHostKey?       HostKey  = null,
                                                                       ISshHostKey?       UserKey  = null)
        {

            SkipIfUnavailable();

            var hostKey     = HostKey ?? SshHostKey.GenerateEd25519();
            var userKey     = UserKey ?? SshHostKey.GenerateEd25519();
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_libsshd_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(hostKey, Path.Combine(windowsRoot, "host"), "libssh-interop-host", CancellationToken);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "libssh-interop-user", CancellationToken);

            var wslRoot = WslInterop.ToWslPath(windowsRoot);

            // OpenSSH refuses a private key other users may read; libssh does not care, but the key
            // is kept private anyway, as a host key should be.
            await WslInterop.RunAsync(["-e", "chmod", "600", $"{wslRoot}/host"], CancellationToken);

            var peer = await WslInterop.StartServerAsync(port => $"{peerBinary} server {port} {wslRoot}/host {wslRoot}/user.pub",
                                                         CancellationToken);

            return new LibSshServer(peer, hostKey, userKey, windowsRoot);

        }

        #endregion


        #region LibSsh_RunsCommand_OnOurServer

        /// <summary>
        /// The whole stack as libssh sees it, starting with its parser reading the <c>openssh-key-v1</c>
        /// file our generator wrote: our command output and exit status must reach it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task LibSsh_RunsCommand_OnOurServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("exec");
            configuration["command"] = Command;

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine($"{result.PeerVersion} saw '{result.ServerVersion}': {result.AlgorithmSummary}");

            Assert.Multiple(() => {
                Assert.That(result.Ok,         Is.True, $"libssh could not run the command.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,     Is.EqualTo($"hermod ran: {Command}\n"), "our command output must reach libssh");
                Assert.That(result.ExitStatus, Is.EqualTo(ExpectedExit),               "libssh must see our exit status");
            });

        }

        #endregion

        #region LibSsh_CompletesKeyExchange_WithOurServer

        /// <summary>
        /// The key-exchange matrix, one method at a time: libssh may offer only the one, so a login
        /// proves both sides derived the same secret and the same exchange hash.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("curve25519-sha256")]
        [TestCase("curve25519-sha256@libssh.org")]
        [TestCase("ecdh-sha2-nistp256")]
        [TestCase("ecdh-sha2-nistp384")]
        [TestCase("ecdh-sha2-nistp521")]
        [TestCase("diffie-hellman-group14-sha256")]
        [TestCase("diffie-hellman-group16-sha512")]
        public async Task LibSsh_CompletesKeyExchange_WithOurServer(String KeyExchange, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["kex_algs"] = new[] { KeyExchange };

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine(result.AlgorithmSummary);

            Assert.That(result.Ok, Is.True, $"libssh could not complete {KeyExchange} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
            Assert.That(result.Algorithms?["kex"], Is.EqualTo(KeyExchange));

        }

        #endregion

        #region LibSsh_CompletesCipher_WithOurServer

        /// <summary>
        /// Every cipher and MAC our server offers, each the only one libssh may use - in both directions,
        /// because the restriction applies to both. That is all of them: <c>aes192-ctr</c> and the
        /// encrypt-and-MAC <c>hmac-sha2-*</c> exist on our side, but a server of ours does not offer them
        /// by default, so a case for them would only show the negotiation finding nothing in common.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("chacha20-poly1305@openssh.com", null)]
        [TestCase("aes256-gcm@openssh.com",        null)]
        [TestCase("aes128-gcm@openssh.com",        null)]
        [TestCase("aes256-ctr",                    "hmac-sha2-256-etm@openssh.com")]
        [TestCase("aes128-ctr",                    "hmac-sha2-512-etm@openssh.com")]
        public async Task LibSsh_CompletesCipher_WithOurServer(String Cipher, String? Mac, CancellationToken CancellationToken)
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
                Assert.That(result.Ok, Is.True, $"libssh could not use {Cipher}/{Mac} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,                   Is.EqualTo("hermod ran: hello\n"), "data must survive the cipher both ways");
                Assert.That(result.Algorithms?["cipher_out"], Is.EqualTo(Cipher));
                Assert.That(result.Algorithms?["cipher_in"],  Is.EqualTo(Cipher));
                if (Mac is not null)
                    Assert.That(result.Algorithms?["mac_out"], Is.EqualTo(Mac));
            });

        }

        #endregion

        #region LibSsh_VerifiesOurHostKey

        /// <summary>
        /// Each host-key algorithm we can sign with, as the only one libssh accepts: a completed login
        /// means libssh verified our signature over the exchange hash with it - for RSA, the SHA-2
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
        public async Task LibSsh_VerifiesOurHostKey(String Algorithm, String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, HostKey: GenerateKey(KeyType));

            var configuration = server.Configuration("connect");
            configuration["host_key_algs"] = new[] { Algorithm };

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.That(result.Ok, Is.True, $"libssh did not accept our {Algorithm} host key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
            Assert.That(result.Algorithms?["host_key"], Is.EqualTo(KeyType));

        }

        #endregion

        #region LibSsh_LogsInWithOurKey

        /// <summary>
        /// Every key type our generator writes, read by libssh's own <c>openssh-key-v1</c> parser and
        /// used to sign the login - a statement about our key writer as much as about authentication.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256")]
        [TestCase("ecdsa-sha2-nistp384")]
        [TestCase("ecdsa-sha2-nistp521")]
        [TestCase("ssh-rsa")]
        public async Task LibSsh_LogsInWithOurKey(String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, UserKey: GenerateKey(KeyType));

            var result = await RunClientAsync(server.Configuration("connect"), CancellationToken);

            Assert.That(result.Ok, Is.True, $"libssh could not log in with our {KeyType} key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

        }

        #endregion

        #region LibSsh_TransfersFiles_OnOurServer

        /// <summary>
        /// libssh's SFTP client on our subsystem: a directory is made, a file uploaded - with the close
        /// checked, where a server may still refuse it - renamed, linked to, read back through the link
        /// and listed, and the link removed again. What landed on our disk is checked.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task LibSsh_TransfersFiles_OnOurServer(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, ServeSftp: true);

            var content = RandomNumberGenerator.GetBytes(1_048_576);
            var upload  = Path.Combine(server.WindowsRoot, "upload.bin");
            var back    = Path.Combine(server.WindowsRoot, "back.bin");
            await File.WriteAllBytesAsync(upload, content, CancellationToken);

            var configuration = server.Configuration("sftp");
            configuration["upload_path"]   = WslInterop.ToWslPath(upload);
            configuration["download_path"] = WslInterop.ToWslPath(back);
            configuration["remote_dir"]    = "/libssh";

            var result = await RunClientAsync(configuration, CancellationToken);
            var root   = Path.Combine(server.WindowsRoot, "root", "libssh");

            Assert.That(result.Ok, Is.True, $"libssh's SFTP client failed in stage '{result.Stage}'.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

            Assert.Multiple(() => {

                Assert.That(File.ReadAllBytes(Path.Combine(root, "data.bin")), Is.EqualTo(content), "the upload landed every byte, and was renamed");
                Assert.That(File.ReadAllBytes(back),                           Is.EqualTo(content), "the download through the link read every byte back");
                Assert.That(File.Exists(Path.Combine(root, "upload.bin")),     Is.False,            "renamed, not copied");
                Assert.That(File.Exists(Path.Combine(root, "link.bin")),       Is.False,            "the link was removed");

                Assert.That(result.Listing, Is.EquivalentTo(new[] { "data.bin", "link.bin" }), "the listing as libssh saw it");
                Assert.That(result.StdOut,  Does.Contain("readlink=data.bin\n")
                                                .And.Contain("lstat_symlink=1\n")
                                                .And.Contain($"stat_size={content.Length}\n"), "the link and the file as libssh saw them");

            });

        }

        #endregion

        #region LibSsh_RejectsAWrongHostKey

        /// <summary>
        /// With some other key pinned, libssh must stop before it authenticates: proof that the key we
        /// present really is the one that reaches it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task LibSsh_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["host_key_b64"] = Convert.ToBase64String(SshHostKey.GenerateEd25519().PublicKeyBlob);

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok,        Is.False,                "libssh must not accept a host key it did not pin");
                Assert.That(result.ErrorType, Is.EqualTo("HostKeyMismatch"), result.FailureReport);
                Assert.That(result.Stage,     Is.EqualTo("host-key"), "and it must stop there, before authenticating");
            });

        }

        #endregion


        #region OurClient_RunsCommand_OnLibSshServer

        /// <summary>
        /// The other direction: our client against libssh's server, which read the host key our
        /// generator wrote. Output and exit status must come back.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task OurClient_RunsCommand_OnLibSshServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            await using var libssh = await StartLibSshServerAsync(CancellationToken);

            SSHClient client;
            try
            {
                client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(libssh.Port), libssh.ClientOptions(), CancellationToken);
            }
            catch (Exception exception)
            {
                throw new AssertionException($"Our client could not connect to libssh.\n{exception.Message}\n{libssh.Peer.Output}", exception);
            }

            await using var _ = client;

            var result = await client.Execute(Command, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.StandardOutput, Is.EqualTo($"libssh ran: {Command}\n"), $"our client must read libssh's output.\n{libssh.Peer.Output}");
                Assert.That(result.ExitCode,       Is.EqualTo(ExpectedExit),                "and the exit status it sent");
            });

        }

        #endregion

        #region OurClient_CompletesKeyExchange_WithLibSshServer

        /// <summary>
        /// Our client's key-exchange matrix against libssh's server, our offer restricted to the one
        /// method. The handshake completing is the assertion: libssh's host-key signature covers the
        /// exchange hash, which we verify.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("curve25519-sha256")]
        [TestCase("curve25519-sha256@libssh.org")]
        [TestCase("ecdh-sha2-nistp256")]
        [TestCase("ecdh-sha2-nistp384")]
        [TestCase("ecdh-sha2-nistp521")]
        [TestCase("diffie-hellman-group14-sha256")]
        [TestCase("diffie-hellman-group16-sha512")]
        public async Task OurClient_CompletesKeyExchange_WithLibSshServer(String KeyExchange, CancellationToken CancellationToken)
        {

            await using var libssh = await StartLibSshServerAsync(CancellationToken);

            var pipe = await SshTcp.ConnectAsync(new IPSocket(IPv4Address.Localhost, IPPort.Parse(libssh.Port)), CancellationToken);

            try
            {

                using var transport = await SshTransport.ClientHandshakeAsync(
                                          pipe,
                                          VerifyHostKey:     blob => blob.AsSpan().SequenceEqual(libssh.HostKey.PublicKeyBlob),
                                          KeyExchanges:      [ KeyExchange ],
                                          CancellationToken: CancellationToken);

                TestContext.Out.WriteLine($"libssh agreed on {transport.Algorithms.KeyExchange} / {transport.Algorithms.CipherClientToServer}, strict KEX {transport.Algorithms.StrictKex}");

                Assert.That(transport.Algorithms.KeyExchange, Is.EqualTo(KeyExchange), libssh.Peer.Output);

            }
            finally
            {
                await pipe.Output.CompleteAsync();
                await pipe.Input. CompleteAsync();
            }

        }

        #endregion

        #region OurClient_UsesEachKeyType_WithLibSshServer

        /// <summary>
        /// Each key type both ways at once: libssh's server reads a host key of that type from the file
        /// our generator wrote and signs the exchange with it, and accepts our client's signature with a
        /// user key of the same type.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256")]
        [TestCase("ecdsa-sha2-nistp384")]
        [TestCase("ecdsa-sha2-nistp521")]
        [TestCase("ssh-rsa")]
        public async Task OurClient_UsesEachKeyType_WithLibSshServer(String KeyType, CancellationToken CancellationToken)
        {

            await using var libssh = await StartLibSshServerAsync(CancellationToken, HostKey: GenerateKey(KeyType), UserKey: GenerateKey(KeyType));

            SSHClient client;
            try
            {
                client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(libssh.Port), libssh.ClientOptions(), CancellationToken);
            }
            catch (Exception exception)
            {
                throw new AssertionException($"Our client could not log in to libssh with {KeyType} keys.\n{exception.Message}\n{libssh.Peer.Output}", exception);
            }

            await using var _ = client;

            var result = await client.Execute("hello", CancellationToken);

            Assert.That(result.StandardOutput, Is.EqualTo("libssh ran: hello\n"), libssh.Peer.Output);

        }

        #endregion

        #region OurClient_TransfersFiles_WithLibSshSftpServer

        /// <summary>
        /// Our SFTP client against libssh's own SFTP server - a server implementation we have not met
        /// anywhere else. A directory is made, a file uploaded with pipelined writes, renamed, stat'ed,
        /// downloaded with pipelined reads and listed, then removed with its directory.
        ///
        /// <para>
        /// The rename is allowed to be refused. libssh 0.11's built-in server implements neither
        /// SSH_FXP_RENAME nor <c>posix-rename@openssh.com</c> and answers both with
        /// SSH_FX_OP_UNSUPPORTED (OpenSSH's sftp gets the same answer). What is ours to get right is
        /// that the refusal arrives as exactly that, and that the session goes on as if nothing
        /// happened - a libssh that learns to rename passes too, under the new name.
        /// </para>
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task OurClient_TransfersFiles_WithLibSshSftpServer(CancellationToken CancellationToken)
        {

            await using var libssh = await StartLibSshServerAsync(CancellationToken);

            var client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(libssh.Port), libssh.ClientOptions(), CancellationToken);
            await using var _ = client;

            await using var sftp = await client.OpenSFTPClient(CancellationToken);

            var content   = RandomNumberGenerator.GetBytes(1_048_576);
            var directory = $"{libssh.WslRoot}/sftp";
            var onDisk    = Path.Combine(libssh.WindowsRoot, "sftp");

            await sftp.MakeDirectoryAsync(directory,                          CancellationToken);
            await sftp.UploadAsync       ($"{directory}/upload.bin", content, CancellationToken);

            var name = "data.bin";
            try
            {
                await sftp.RenameAsync($"{directory}/upload.bin", $"{directory}/data.bin", CancellationToken);
            }
            catch (SftpException refused)
            {
                Assert.That(refused.Code, Is.EqualTo(SftpStatusCode.OpUnsupported), $"a rename libssh refused must be refused as unsupported: {refused.Message}");
                TestContext.Out.WriteLine($"libssh's SFTP server does not rename: {refused.Code} '{refused.Message}'");
                name = "upload.bin";
            }

            var attributes = await sftp.StatAsync         ($"{directory}/{name}", CancellationToken);
            var downloaded = await sftp.DownloadAsync     ($"{directory}/{name}", CancellationToken);
            var listing    = await sftp.ListDirectoryAsync(directory,             CancellationToken);

            Assert.Multiple(() => {
                Assert.That(File.ReadAllBytes(Path.Combine(onDisk, name)), Is.EqualTo(content), "the upload landed every byte");
                Assert.That(attributes.Size,                               Is.EqualTo(content.Length));
                Assert.That(downloaded,                                    Is.EqualTo(content), "the download read every byte back");
                Assert.That(listing.Select(entry => entry.Name),           Is.EquivalentTo(new[] { name }));
            });

            await sftp.RemoveAsync         ($"{directory}/{name}",   CancellationToken);
            await sftp.RemoveDirectoryAsync(directory,               CancellationToken);

            Assert.That(Directory.Exists(onDisk), Is.False, "the file and its directory were removed");

        }

        #endregion

        #region OurClient_RejectsAWrongLibSshHostKey

        /// <summary>
        /// The same connection with some other key pinned: our client must fail closed against libssh.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_RejectsAWrongLibSshHostKey(CancellationToken CancellationToken)
        {

            await using var libssh = await StartLibSshServerAsync(CancellationToken);

            var somebodyElse = SshHostKey.GenerateEd25519();

            Assert.That(async () => await SSHClient.Connect("127.0.0.1",
                                                            IPPort.Parse(libssh.Port),
                                                            libssh.ClientOptions(blob => blob.AsSpan().SequenceEqual(somebodyElse.PublicKeyBlob)),
                                                            CancellationToken),
                        Throws.TypeOf<SshHostKeyRejectedException>(),
                        "our client must refuse a host key that is not the one it pinned");

        }

        #endregion

    }

}
