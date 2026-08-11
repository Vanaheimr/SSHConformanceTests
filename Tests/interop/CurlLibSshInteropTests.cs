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
    /// Interoperability against <b>curl</b> over <b>libssh2</b> — our SFTP server reached through a stack
    /// that shares nothing with any other peer here.
    ///
    /// <para>
    /// libssh2 is a third C lineage beside OpenSSH and Dropbear, it is what curl, git and PHP speak SFTP
    /// with, and it arrives at our subsystem as a *library* embedded in a general-purpose transfer tool
    /// rather than as an SSH client with an SFTP mode. That difference is the point: it makes its own
    /// assumptions about paths, about how a transfer ends, and about which SFTP requests are worth
    /// sending.
    /// </para>
    ///
    /// <para>
    /// Note the version in play: libssh2 ≤ 1.11.1 carries CVE-2026-55200, a pre-auth out-of-bounds write
    /// a malicious <i>server</i> can trigger in the client. Debian's 1.11.1-1+deb13u1 backports the fix,
    /// and we are the server here in any case — but this is the one peer where the direction of trust is
    /// worth stating out loud.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.LibSsh")]
    public class CurlLibSshInteropTests
    {

        #region (private) harness

        private sealed record Fixture(SshServer           Server,
                                      String              Host,
                                      Int32               Port,
                                      ISshHostKey         HostKey,
                                      String              WindowsRoot,
                                      InMemorySftpFileSystem FileSystem,
                                      RecordingAuditSink  Audit)
        {

            /// <summary>The key material and scratch files, addressed as WSL sees them.</summary>
            public String WslPrivateKey => WslInterop.ToWslPath(Path.Combine(WindowsRoot, "user"));
            public String WslPublicKey  => WslInterop.ToWslPath(Path.Combine(WindowsRoot, "user.pub"));

            /// <summary>
            /// What <c>--hostpubsha256</c> expects: the base64 SHA-256 of the host-key blob, without the
            /// <c>SHA256:</c> prefix our own fingerprint carries.
            /// </summary>
            public String HostKeyFingerprint
                => SshFingerprint.Sha256(HostKey.PublicKeyBlob)["SHA256:".Length..];

        }


        private static async Task<Fixture> StartAsync(CancellationToken CancellationToken)
        {

            WslInterop.SkipIfUnavailable();

            var (present, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "command -v curl >/dev/null"], CancellationToken);
            if (present != 0)
                Assert.Ignore("curl is not installed inside WSL — run interop/setup-wsl.sh.");

            var (backend, version, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "curl --version | head -1"], CancellationToken);
            if (backend == 0 && !version.Contains("libssh", StringComparison.OrdinalIgnoreCase))
                Assert.Ignore($"This curl has no SSH backend, so it cannot speak SFTP: {version.Trim()}");

            var hostKey     = SshHostKey.GenerateEd25519();
            var userKey     = SshHostKey.GenerateEd25519();
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_curl_" + Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(windowsRoot);
            await SshKeyGenerator.WriteKeyPairAsync(userKey, Path.Combine(windowsRoot, "user"), "curl-interop", CancellationToken);

            var fileSystem = new InMemorySftpFileSystem();
            var audit      = new RecordingAuditSink();

            var server = new SshServer(new SshServerOptions {
                             HostKeys       = [ hostKey ],
                             Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                             SftpFileSystem = fileSystem,
                             AuditSink      = audit
                         });

            await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
            var port = server.LocalEndPoint.Port.ToInt32();

            var host = await WslInterop.ResolveWindowsHostAsync(CancellationToken);
            if (host is null)
            {
                await server.DisposeAsync();
                Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall.");
            }

            return new Fixture(server, host!, port, hostKey, windowsRoot, fileSystem, audit);

        }

        private static async Task StopAsync(Fixture Fixture)
        {
            await Fixture.Server.DisposeAsync();
            try { Directory.Delete(Fixture.WindowsRoot, recursive: true); } catch { }
        }


        /// <summary>Run curl against our SFTP subsystem with the host key pinned.</summary>
        private static Task<(Int32 ExitCode, String StdOut, String StdErr)> CurlAsync(Fixture            Fixture,
                                                                                      IEnumerable<String> Arguments,
                                                                                      CancellationToken   CancellationToken,
                                                                                      String?             FingerprintOverride = null)
            => WslInterop.RunAsync([
                   "-e", "curl", "-sS", "--fail",
                   "--key",           Fixture.WslPrivateKey,
                   "--pubkey",        Fixture.WslPublicKey,
                   "--hostpubsha256", FingerprintOverride ?? Fixture.HostKeyFingerprint,
                   "-u",              "hermoduser:",
                   .. Arguments
               ], CancellationToken);

        #endregion


        #region Curl_UploadsAndDownloads_OverOurSftpSubsystem

        /// <summary>
        /// A full round trip through libssh2: upload a multi-chunk payload into our subsystem, read it back
        /// and compare byte for byte. The bytes are also checked inside the server's own file system, so a
        /// download that merely echoed the upload could not pass.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Curl_UploadsAndDownloads_OverOurSftpSubsystem(CancellationToken CancellationToken)
        {

            var fixture = await StartAsync(CancellationToken);

            var payload      = RandomNumberGenerator.GetBytes(40_000);
            var uploadPath   = Path.Combine(fixture.WindowsRoot, "payload.bin");
            var downloadPath = Path.Combine(fixture.WindowsRoot, "roundtrip.bin");

            try
            {

                await File.WriteAllBytesAsync(uploadPath, payload, CancellationToken);

                var (uploadExit, _, uploadError) = await CurlAsync(fixture, [
                                                       "-T", WslInterop.ToWslPath(uploadPath),
                                                       $"sftp://{fixture.Host}:{fixture.Port}/device.bin"
                                                   ], CancellationToken);

                Assert.That(uploadExit, Is.EqualTo(0),
                            $"curl must upload through our subsystem: {uploadError}\n--- our server's audit ---\n{fixture.Audit.Report}");

                var (downloadExit, _, downloadError) = await CurlAsync(fixture, [
                                                           "-o", WslInterop.ToWslPath(downloadPath),
                                                           $"sftp://{fixture.Host}:{fixture.Port}/device.bin"
                                                       ], CancellationToken);

                Assert.That(downloadExit, Is.EqualTo(0), $"curl must download it again: {downloadError}");

                var downloaded = await File.ReadAllBytesAsync(downloadPath, CancellationToken);

                // The download is a second, independent curl invocation, so the bytes can only have come
                // from our subsystem's storage — nothing here could be echoing the upload.
                Assert.That(downloaded, Is.EqualTo(payload), "the round trip through libssh2 must be byte-for-byte");

            }
            finally
            {
                await StopAsync(fixture);
            }

        }

        #endregion

        #region Curl_RejectsAWrongHostKey

        /// <summary>
        /// Host-key verification through libssh2: with a foreign fingerprint pinned, curl must refuse and
        /// transfer nothing.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task Curl_RejectsAWrongHostKey(CancellationToken CancellationToken)
        {

            var fixture      = await StartAsync(CancellationToken);
            var somebodyElse = SshHostKey.GenerateEd25519();
            var downloadPath = Path.Combine(fixture.WindowsRoot, "should-not-exist.bin");

            try
            {

                fixture.FileSystem.AddFile("/secret.bin", "must not be readable"u8.ToArray());

                var (exitCode, _, stderr) = await CurlAsync(fixture, [
                                                "-o", WslInterop.ToWslPath(downloadPath),
                                                $"sftp://{fixture.Host}:{fixture.Port}/secret.bin"
                                            ], CancellationToken,
                                            FingerprintOverride: SshFingerprint.Sha256(somebodyElse.PublicKeyBlob)["SHA256:".Length..]);

                TestContext.Out.WriteLine($"curl refused with: {stderr.Trim()}");

                Assert.Multiple(() => {
                    Assert.That(exitCode, Is.Not.EqualTo(0), "curl must not accept a host key it did not pin");
                    Assert.That(File.Exists(downloadPath) && new FileInfo(downloadPath).Length > 0, Is.False,
                                "and nothing may have been transferred");
                });

            }
            finally
            {
                await StopAsync(fixture);
            }

        }

        #endregion

    }

}
