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
    /// Interoperability against <b>wolfSSH</b>, both ways - the embedded C lineage beside Dropbear.
    ///
    /// <para>
    /// wolfSSH is wolfSSL's SSH library for devices, RTOSes and appliances, mostly met as an embedded
    /// server. It is built on wolfCrypt rather than OpenSSL and shares no code with OpenSSH, libssh or
    /// Dropbear: its key parser, its state machine and its SFTP server are its own.
    /// </para>
    ///
    /// <para>
    /// Debian packages wolfSSL but not wolfSSH, so <c>interop/wolfssh/build-wolfssh.sh</c> builds the
    /// pinned upstream release (1.6.0, checked against its SHA-256) against the distribution's
    /// <c>libwolfssl-dev</c> into a cache directory that outlives the run, and the peer - a small C
    /// program in <c>interop/wolfssh/</c>, like the libssh peer - is compiled against it with the same
    /// feature switches. It plays both roles: a client that speaks the JSON contract of
    /// <see cref="WslInterop.RunPeerAsync"/>, and a server that answers <c>exec</c> and serves wolfSSH's
    /// own SFTP server. The client reads the key files our generator wrote with no conversion step. The
    /// server cannot quite: wolfSSH 1.6.0 takes an <c>openssh-key-v1</c> host key only for its ML-DSA
    /// composites, so the peer reads our file with wolfSSH's own reader, takes the private section apart
    /// and has wolfCrypt write it out as DER, which wolfSSH's server then loads.
    /// </para>
    ///
    /// <para>
    /// What the two of us share is narrower than with any other peer here, and the gaps are wolfSSH's:
    /// on Debian's wolfSSL it has no post-quantum key exchange and no ChaCha20, and its MACs are the
    /// encrypt-and-MAC <c>hmac-sha2-*</c> only, which we deliberately do not implement (PLAN.md §0.5) - so
    /// AES-GCM is the one cipher family we have in common, and AES-CTR cannot be negotiated at all. Its
    /// SFTP has no SSH_FXP_SYMLINK or SSH_FXP_READLINK in either role, so the transfers here work
    /// without a link. And it reports what it negotiated only in prose ("ECDH"), so where wolfSSH is the
    /// client the algorithm names are taken from our own server's audit record.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.WolfSsh")]
    public class WolfSshInteropTests
    {

        #region (private) harness - build wolfSSH and the peer once per fixture

        private const  String   Username = "hermoduser";

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

            var (hasToolchain, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c",
                                                                  "command -v gcc >/dev/null && command -v make >/dev/null && command -v autoreconf >/dev/null && " +
                                                                  "command -v libtoolize >/dev/null && command -v curl >/dev/null && " +
                                                                  "test -f /usr/include/wolfssl/options.h && pkg-config --exists jansson"],
                                                                 CancellationToken.None);
            if (hasToolchain != 0)
            {
                skipReason = "No wolfSSH build toolchain inside WSL - install gcc, make, autoconf, automake, libtool, curl, libwolfssl-dev and libjansson-dev (interop/setup-wsl.sh does).";
                return;
            }

            var home    = await WslInterop.HomeAsync(CancellationToken.None);
            var source  = WslInterop.ToWslPath(Path.Combine(WslInterop.InteropDirectory!, "wolfssh"));
            var library = $"{home}/.cache/hermod-interop/wolfssh";

            peerRoot = $"{home}/.hermod-interop/wolfssh_{Guid.NewGuid():N}";

            // The library is built once per version into a directory that outlives the run; the peer is
            // compiled with the feature switches that build used, which wolfSSH's headers depend on.
            var (exitCode, stdout, stderr) = await WslInterop.RunAsync([
                                                 "-e", "bash", "-c",
                                                 $"bash {source}/build-wolfssh.sh {library} && mkdir -p {peerRoot} && " +
                                                 $"gcc -O2 -Wall $(cat {library}/cppflags) -I{library}/include -o {peerRoot}/wolfssh-peer {source}/wolfssh_peer.c " +
                                                 $"-L{library}/lib -Wl,-rpath,{library}/lib -lwolfssh -lwolfssl $(pkg-config --cflags --libs jansson)"
                                             ], CancellationToken.None);

            if (exitCode != 0)
            {
                skipReason = $"Could not build wolfSSH or its peer (exit {exitCode}).\n{stdout}\n{stderr}";
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

        private static Task<PeerRunResult> RunClientAsync(Dictionary<String, Object?> Configuration, CancellationToken CancellationToken)
            => WslInterop.RunPeerAsync("wolfSSH", ["-e", $"{peerRoot}/wolfssh-peer", "client"], Configuration, CancellationToken);


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
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_wolfssh_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "wolfssh-interop", CancellationToken);

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
        /// A wolfSSH server in WSL with a host key and an authorized key, both written by our generator.
        /// </summary>
        private sealed record WolfServer(WslServer   Peer,
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

        private static async Task<WolfServer> StartWolfServerAsync(CancellationToken  CancellationToken,
                                                                   ISshHostKey?       HostKey  = null,
                                                                   ISshHostKey?       UserKey  = null)
        {

            SkipIfUnavailable();

            var hostKey     = HostKey ?? SshHostKey.GenerateEd25519();
            var userKey     = UserKey ?? SshHostKey.GenerateEd25519();
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_wolfsshd_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(hostKey, Path.Combine(windowsRoot, "host"), "wolfssh-interop-host", CancellationToken);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "wolfssh-interop-user", CancellationToken);

            var wslRoot = WslInterop.ToWslPath(windowsRoot);

            // A host key is kept private, as it should be, whether or not the server insists.
            await WslInterop.RunAsync(["-e", "chmod", "600", $"{wslRoot}/host"], CancellationToken);

            var peer = await WslInterop.StartServerAsync(port => $"{peerRoot}/wolfssh-peer server {port} {wslRoot}/host {wslRoot}/user.pub",
                                                         CancellationToken);

            return new WolfServer(peer, hostKey, userKey, windowsRoot);

        }

        #endregion


        #region Wolfssh_RunsCommand_OnOurServer

        /// <summary>
        /// The whole stack as wolfSSH sees it, starting with its parser reading the <c>openssh-key-v1</c>
        /// file our generator wrote: our command output and exit status must reach it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task Wolfssh_RunsCommand_OnOurServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("exec");
            configuration["command"] = Command;

            var result = await RunClientAsync(configuration, CancellationToken);

            TestContext.Out.WriteLine($"{result.PeerVersion}: {server.Audit.LastKeyExchange}");

            Assert.Multiple(() => {
                Assert.That(result.Ok,         Is.True, $"wolfSSH could not run the command.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,     Is.EqualTo($"hermod ran: {Command}\n"), "our command output must reach wolfSSH");
                Assert.That(result.ExitStatus, Is.EqualTo(ExpectedExit),               "wolfSSH must see our exit status");
            });

        }

        #endregion

        #region Wolfssh_CompletesKeyExchange_WithOurServer

        /// <summary>
        /// The key-exchange matrix, one method at a time: wolfSSH may offer only the one, so a login
        /// proves both sides derived the same secret and the same exchange hash. What was negotiated is
        /// read from our server's audit record, since wolfSSH names it only in prose.
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
        public async Task Wolfssh_CompletesKeyExchange_WithOurServer(String KeyExchange, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["kex_algs"] = new[] { KeyExchange };

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.That(result.Ok, Is.True, $"wolfSSH could not complete {KeyExchange} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
            Assert.That(server.Audit.LastKeyExchange?.KeyExchange, Is.EqualTo(KeyExchange), server.Audit.Report);

        }

        #endregion

        #region Wolfssh_CompletesCipher_WithOurServer

        /// <summary>
        /// The ciphers wolfSSH and our server have in common, each the only one wolfSSH may use. That is
        /// AES-GCM and nothing else: wolfSSH's MACs for AES-CTR are the encrypt-and-MAC kind we do not
        /// implement, and it has no ChaCha20 on Debian's wolfSSL. With an AEAD cipher the MAC lists play
        /// no part, so the two disjoint lists must not stop the negotiation.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("aes256-gcm@openssh.com")]
        [TestCase("aes128-gcm@openssh.com")]
        public async Task Wolfssh_CompletesCipher_WithOurServer(String Cipher, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("exec");
            configuration["command"] = "hello";
            configuration["ciphers"] = new[] { Cipher };

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok, Is.True, $"wolfSSH could not use {Cipher} with us.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.StdOut,                          Is.EqualTo("hermod ran: hello\n"), "data must survive the cipher both ways");
                Assert.That(server.Audit.LastKeyExchange?.Cipher,   Is.EqualTo(Cipher),               server.Audit.Report);
            });

        }

        #endregion

        #region Wolfssh_VerifiesOurHostKey

        /// <summary>
        /// Each host-key algorithm we can sign with, as the only one wolfSSH accepts: a completed login
        /// means wolfSSH verified our signature over the exchange hash with it - for RSA, the SHA-2
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
        public async Task Wolfssh_VerifiesOurHostKey(String Algorithm, String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, HostKey: GenerateKey(KeyType));

            var configuration = server.Configuration("connect");
            configuration["host_key_algs"] = new[] { Algorithm };

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok, Is.True, $"wolfSSH did not accept our {Algorithm} host key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");
                Assert.That(result.Algorithms?["host_key"],                Is.EqualTo(KeyType));
                Assert.That(server.Audit.LastKeyExchange?.HostKeyAlgorithm, Is.EqualTo(Algorithm), server.Audit.Report);
            });

        }

        #endregion

        #region Wolfssh_LogsInWithOurKey

        /// <summary>
        /// Every key type our generator writes, read by wolfSSH's own <c>openssh-key-v1</c> parser and
        /// used to sign the login - a statement about our key writer as much as about authentication.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256")]
        [TestCase("ecdsa-sha2-nistp384")]
        [TestCase("ecdsa-sha2-nistp521")]
        [TestCase("ssh-rsa")]
        public async Task Wolfssh_LogsInWithOurKey(String KeyType, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, UserKey: GenerateKey(KeyType));

            var result = await RunClientAsync(server.Configuration("connect"), CancellationToken);

            Assert.That(result.Ok, Is.True, $"wolfSSH could not log in with our {KeyType} key.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

        }

        #endregion

        #region Wolfssh_TransfersFiles_OnOurServer

        /// <summary>
        /// wolfSSH's SFTP client on our subsystem: a directory is made, a file uploaded - with the close
        /// checked, where a server may still refuse it - renamed, stat'ed and read back, a second file
        /// uploaded and removed again, and the directory listed in between. What landed on our disk is
        /// checked. No link: wolfSSH's client cannot make or read one.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task Wolfssh_TransfersFiles_OnOurServer(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, ServeSftp: true);

            var content = RandomNumberGenerator.GetBytes(1_048_576);
            var upload  = Path.Combine(server.WindowsRoot, "upload.bin");
            var back    = Path.Combine(server.WindowsRoot, "back.bin");
            await File.WriteAllBytesAsync(upload, content, CancellationToken);

            var configuration = server.Configuration("sftp");
            configuration["upload_path"]   = WslInterop.ToWslPath(upload);
            configuration["download_path"] = WslInterop.ToWslPath(back);
            configuration["remote_dir"]    = "/wolfssh";

            var result = await RunClientAsync(configuration, CancellationToken);
            var root   = Path.Combine(server.WindowsRoot, "root", "wolfssh");

            Assert.That(result.Ok, Is.True, $"wolfSSH's SFTP client failed in stage '{result.Stage}'.\n{result.FailureReport}\n--- our server's audit ---\n{server.Audit.Report}");

            Assert.Multiple(() => {

                Assert.That(File.ReadAllBytes(Path.Combine(root, "data.bin")), Is.EqualTo(content), "the upload landed every byte, and was renamed");
                Assert.That(File.ReadAllBytes(back),                           Is.EqualTo(content), "the download read every byte back");
                Assert.That(File.Exists(Path.Combine(root, "upload.bin")),     Is.False,            "renamed, not copied");
                Assert.That(File.Exists(Path.Combine(root, "doomed.bin")),     Is.False,            "the second file was removed");

                Assert.That(result.Listing, Is.EquivalentTo(new[] { "data.bin", "doomed.bin" }), "the listing as wolfSSH saw it");
                Assert.That(result.StdOut,  Does.Contain($"stat_size={content.Length}\n"),       "the file as wolfSSH saw it");

            });

        }

        #endregion

        #region Wolfssh_RejectsAWrongHostKey

        /// <summary>
        /// With some other key pinned, wolfSSH must stop before it authenticates: proof that the key we
        /// present really is the one that reaches it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Wolfssh_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var configuration = server.Configuration("connect");
            configuration["host_key_b64"] = Convert.ToBase64String(SshHostKey.GenerateEd25519().PublicKeyBlob);

            var result = await RunClientAsync(configuration, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.Ok,        Is.False,                "wolfSSH must not accept a host key it did not pin");
                Assert.That(result.ErrorType, Is.EqualTo("HostKeyMismatch"), result.FailureReport);
                Assert.That(result.Stage,     Is.EqualTo("host-key"), "and it must stop there, before authenticating");
            });

        }

        #endregion


        #region OurClient_RunsCommand_OnWolfsshServer

        /// <summary>
        /// The other direction: our client against wolfSSH's server, which read the host key our
        /// generator wrote. Output and exit status must come back.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("hello", 0)]
        [TestCase("fail", 42)]
        public async Task OurClient_RunsCommand_OnWolfsshServer(String Command, Int32 ExpectedExit, CancellationToken CancellationToken)
        {

            await using var wolf = await StartWolfServerAsync(CancellationToken);

            SSHClient client;
            try
            {
                client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(wolf.Port), wolf.ClientOptions(), CancellationToken);
            }
            catch (Exception exception)
            {
                throw new AssertionException($"Our client could not connect to wolfSSH.\n{exception.Message}\n{wolf.Peer.Output}", exception);
            }

            await using var _ = client;

            var result = await client.Execute(Command, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(result.StandardOutput, Is.EqualTo($"wolfssh ran: {Command}\n"), $"our client must read wolfSSH's output.\n{wolf.Peer.Output}");
                Assert.That(result.ExitCode,       Is.EqualTo(ExpectedExit),                 "and the exit status it sent");
            });

        }

        #endregion

        #region OurClient_CompletesKeyExchange_WithWolfsshServer

        /// <summary>
        /// Our client's key-exchange matrix against wolfSSH's server, our offer restricted to the one
        /// method. The handshake completing is the assertion: wolfSSH's host-key signature covers the
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
        public async Task OurClient_CompletesKeyExchange_WithWolfsshServer(String KeyExchange, CancellationToken CancellationToken)
        {

            await using var wolf = await StartWolfServerAsync(CancellationToken);

            var pipe = await SshTcp.ConnectAsync(new IPSocket(IPv4Address.Localhost, IPPort.Parse(wolf.Port)), CancellationToken);

            try
            {

                using var transport = await SshTransport.ClientHandshakeAsync(
                                          pipe,
                                          VerifyHostKey:     blob => blob.AsSpan().SequenceEqual(wolf.HostKey.PublicKeyBlob),
                                          KeyExchanges:      [ KeyExchange ],
                                          CancellationToken: CancellationToken);

                TestContext.Out.WriteLine($"wolfSSH agreed on {transport.Algorithms.KeyExchange} / {transport.Algorithms.CipherClientToServer}, strict KEX {transport.Algorithms.StrictKex}");

                Assert.That(transport.Algorithms.KeyExchange, Is.EqualTo(KeyExchange), wolf.Peer.Output);

            }
            finally
            {
                await pipe.Output.CompleteAsync();
                await pipe.Input. CompleteAsync();
            }

        }

        #endregion

        #region OurClient_CompletesCipher_WithWolfsshServer

        /// <summary>
        /// Our client's side of the AES-GCM pair against wolfSSH's server, followed by a login over it -
        /// so packets cross the new keys in both directions. Our MAC list and wolfSSH's share nothing,
        /// which an AEAD cipher must not mind.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("aes256-gcm@openssh.com")]
        [TestCase("aes128-gcm@openssh.com")]
        public async Task OurClient_CompletesCipher_WithWolfsshServer(String Cipher, CancellationToken CancellationToken)
        {

            await using var wolf = await StartWolfServerAsync(CancellationToken);

            var pipe = await SshTcp.ConnectAsync(new IPSocket(IPv4Address.Localhost, IPPort.Parse(wolf.Port)), CancellationToken);

            try
            {

                using var transport = await SshTransport.ClientHandshakeAsync(
                                          pipe,
                                          VerifyHostKey:     blob => blob.AsSpan().SequenceEqual(wolf.HostKey.PublicKeyBlob),
                                          Ciphers:           [ Cipher ],
                                          CancellationToken: CancellationToken);

                var authenticated = await UserAuthentication.ClientAuthenticateAsync(transport, User_Id.Parse(Username), [ wolf.UserKey ], CancellationToken: CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(transport.Algorithms.CipherClientToServer, Is.EqualTo(Cipher), wolf.Peer.Output);
                    Assert.That(transport.Algorithms.CipherServerToClient, Is.EqualTo(Cipher));
                    Assert.That(authenticated, Is.True, $"the login over {Cipher} must succeed.\n{wolf.Peer.Output}");
                });

            }
            finally
            {
                await pipe.Output.CompleteAsync();
                await pipe.Input. CompleteAsync();
            }

        }

        #endregion

        #region OurClient_UsesEachKeyType_WithWolfsshServer

        /// <summary>
        /// Each key type both ways at once: wolfSSH's server reads a host key of that type from the file
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
        public async Task OurClient_UsesEachKeyType_WithWolfsshServer(String KeyType, CancellationToken CancellationToken)
        {

            await using var wolf = await StartWolfServerAsync(CancellationToken, HostKey: GenerateKey(KeyType), UserKey: GenerateKey(KeyType));

            SSHClient client;
            try
            {
                client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(wolf.Port), wolf.ClientOptions(), CancellationToken);
            }
            catch (Exception exception)
            {
                throw new AssertionException($"Our client could not log in to wolfSSH with {KeyType} keys.\n{exception.Message}\n{wolf.Peer.Output}", exception);
            }

            await using var _ = client;

            var result = await client.Execute("hello", CancellationToken);

            Assert.That(result.StandardOutput, Is.EqualTo("wolfssh ran: hello\n"), wolf.Peer.Output);

        }

        #endregion

        #region OurClient_TransfersFiles_WithWolfsshSftpServer

        /// <summary>
        /// Our SFTP client against wolfSSH's own SFTP server: a directory is made, a file uploaded with
        /// pipelined writes, renamed, stat'ed, read back and listed, then removed with its directory.
        /// No link: wolfSSH's server answers neither SSH_FXP_SYMLINK nor SSH_FXP_READLINK.
        /// </summary>
        [Test]
        [CancelAfter(180000)]
        public async Task OurClient_TransfersFiles_WithWolfsshSftpServer(CancellationToken CancellationToken)
        {

            await using var wolf = await StartWolfServerAsync(CancellationToken);

            var client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(wolf.Port), wolf.ClientOptions(), CancellationToken);
            await using var _ = client;

            await using var sftp = await client.OpenSFTPClient(CancellationToken);

            var content   = RandomNumberGenerator.GetBytes(1_048_576);
            var directory = $"{wolf.WslRoot}/sftp";
            var onDisk    = Path.Combine(wolf.WindowsRoot, "sftp");

            await sftp.MakeDirectoryAsync(directory,                                          CancellationToken);
            await sftp.UploadAsync       ($"{directory}/upload.bin", content,                 CancellationToken);
            await sftp.RenameAsync       ($"{directory}/upload.bin", $"{directory}/data.bin", CancellationToken);

            var attributes = await sftp.StatAsync         ($"{directory}/data.bin", CancellationToken);
            var downloaded = await sftp.DownloadAsync     ($"{directory}/data.bin", CancellationToken);
            var listing    = await sftp.ListDirectoryAsync(directory,               CancellationToken);

            Assert.Multiple(() => {
                Assert.That(File.ReadAllBytes(Path.Combine(onDisk, "data.bin")), Is.EqualTo(content), "the upload landed every byte, and was renamed");
                Assert.That(File.Exists(Path.Combine(onDisk, "upload.bin")),     Is.False,            "renamed, not copied");
                Assert.That(attributes.Size,                                     Is.EqualTo(content.Length));
                Assert.That(downloaded,                                          Is.EqualTo(content), "the download read every byte back");
                Assert.That(listing.Select(entry => entry.Name),                 Is.EquivalentTo(new[] { "data.bin" }));
            });

            await sftp.RemoveAsync         ($"{directory}/data.bin", CancellationToken);
            await sftp.RemoveDirectoryAsync(directory,               CancellationToken);

            Assert.That(Directory.Exists(onDisk), Is.False, "the file and its directory were removed");

        }

        #endregion

        #region OurClient_RejectsAWrongWolfsshHostKey

        /// <summary>
        /// The same connection with some other key pinned: our client must fail closed against wolfSSH.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_RejectsAWrongWolfsshHostKey(CancellationToken CancellationToken)
        {

            await using var wolf = await StartWolfServerAsync(CancellationToken);

            var somebodyElse = SshHostKey.GenerateEd25519();

            Assert.That(async () => await SSHClient.Connect("127.0.0.1",
                                                            IPPort.Parse(wolf.Port),
                                                            wolf.ClientOptions(blob => blob.AsSpan().SequenceEqual(somebodyElse.PublicKeyBlob)),
                                                            CancellationToken),
                        Throws.TypeOf<SshHostKeyRejectedException>(),
                        "our client must refuse a host key that is not the one it pinned");

        }

        #endregion

    }

}
