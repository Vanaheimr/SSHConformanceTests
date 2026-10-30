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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Our server with three host keys - Ed25519, ECDSA and RSA, as a stock sshd has them - against the
    /// real OpenSSH tools, which choose a key by algorithm: <c>ssh</c> prefers the algorithms of the keys
    /// its <c>known_hosts</c> holds, <c>ssh-keyscan</c> asks for one type per connection. Both used to
    /// see only the first key, because only the first key's algorithms were offered.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshSeveralHostKeysInteropTests
    {

        private static String? FindOnPathOrSystem(String Tool)
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { Tool, Tool + ".exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }
            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", Tool + ".exe");
            return File.Exists(system) ? system : null;
        }

        private static async Task<(Int32 ExitCode, String StandardOutput, String StandardError)> RunAsync(String Tool, IEnumerable<String> Arguments, CancellationToken CancellationToken)
        {

            using var process = new Process { StartInfo = new ProcessStartInfo(Tool) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
            foreach (var argument in Arguments)
                process.StartInfo.ArgumentList.Add(argument);

            process.Start();

            try
            {
                var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken);
                var stderr = process.StandardError.ReadToEndAsync(CancellationToken);
                await process.WaitForExitAsync(CancellationToken);
                return (process.ExitCode, await stdout, await stderr);
            }
            catch
            {
                try { if (!process.HasExited) process.Kill(true); } catch { }
                throw;
            }

        }

        // The key types a stock sshd generates, in sshd's order.
        private static ISshHostKey[] ThreeHostKeys()
            => [ SshHostKey.GenerateEd25519(), SshHostKey.GenerateEcdsa(SshAlgorithmNames.HostKey.EcdsaNistP256), SshHostKey.GenerateRsa(3072) ];


        #region RealOpenSshClient_KnowingOnlyOurRsaHostKey_LogsIn

        /// <summary>
        /// A client that met the host when it had only its RSA key: <c>known_hosts</c> holds that one, and
        /// with <c>StrictHostKeyChecking=yes</c> the Ed25519 key the server used to present would have been
        /// a "host key verification failed".
        /// </summary>
        [Test]
        [CancelAfter(40000)]
        public async Task RealOpenSshClient_KnowingOnlyOurRsaHostKey_LogsIn(CancellationToken CancellationToken)
        {

            var ssh       = FindOnPathOrSystem("ssh");
            var sshKeygen = FindOnPathOrSystem("ssh-keygen");
            if (ssh is null || sshKeygen is null)
                Assert.Ignore("No 'ssh'/'ssh-keygen' found.");

            var keyPath    = Path.Combine(Path.GetTempPath(), "hermod_shk_" + Guid.NewGuid().ToString("N"));
            var knownHosts = Path.Combine(Path.GetTempPath(), "hermod_kh_"  + Guid.NewGuid().ToString("N"));
            var emptyConf  = Path.GetTempFileName();
            var hostKeys   = ThreeHostKeys();

            SshServer? server = null;

            try
            {

                await RunAsync(sshKeygen!, [ "-t", "ed25519", "-f", keyPath, "-N", "", "-q" ], CancellationToken);
                var publicBlob = Convert.FromBase64String((await File.ReadAllTextAsync(keyPath + ".pub", CancellationToken)).Split(' ')[1]);

                server = new SshServer(new SshServerOptions {
                    HostKeys           = hostKeys,
                    Authenticator      = SshUserAuthenticator.ForAuthorizedKeys(publicBlob),
                    ExecHandler        = async (context, ct) => { await context.WriteAsync("several\n", ct); return 0; },
                    AdvertiseHostKeys  = false
                });

                await server.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                await File.WriteAllTextAsync(knownHosts,
                                             $"[127.0.0.1]:{port} ssh-rsa {Convert.ToBase64String(hostKeys[2].PublicKeyBlob)}\n",
                                             CancellationToken);

                var (exitCode, stdout, stderr) = await RunAsync(ssh!, [
                                                     "-F", emptyConf, "-p", port.ToString(), "-v",
                                                     "-o", "StrictHostKeyChecking=yes", "-o", $"UserKnownHostsFile={knownHosts}",
                                                     "-o", "UpdateHostKeys=no",
                                                     "-i", keyPath, "-o", "IdentitiesOnly=yes",
                                                     "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                                                     "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                                                     "hermoduser@127.0.0.1", "hello"
                                                 ], CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(exitCode, Is.EqualTo(0), $"ssh must log in on the RSA key it knows. stderr:\n{stderr}");
                    Assert.That(stdout,   Is.EqualTo("several\n"));
                    // "Server host key: ssh-rsa SHA256:…" - whichever rsa-sha2 signature it asked for.
                    Assert.That(stderr,   Does.Contain("Server host key: ssh-rsa "), stderr);
                });

            }
            finally
            {
                if (server is not null)
                    await server.DisposeAsync();
                try { File.Delete(keyPath);          } catch { }
                try { File.Delete(keyPath + ".pub"); } catch { }
                try { File.Delete(knownHosts);       } catch { }
                try { File.Delete(emptyConf);        } catch { }
            }

        }

        #endregion

        #region RealSshKeyscan_GetsEveryHostKey

        /// <summary>
        /// <c>ssh-keyscan</c> connects once per requested type and offers only that type's algorithms,
        /// so each connection has to be answered with a different key - and each line it prints has to be
        /// the key that signed.
        /// </summary>
        [Test]
        [CancelAfter(40000)]
        public async Task RealSshKeyscan_GetsEveryHostKey(CancellationToken CancellationToken)
        {

            var sshKeyscan = FindOnPathOrSystem("ssh-keyscan");
            if (sshKeyscan is null)
                Assert.Ignore("No 'ssh-keyscan' found.");

            var hostKeys = ThreeHostKeys();
            var audit    = new RecordingAuditSink();

            await using var server = new SshServer(new SshServerOptions {
                                         HostKeys       = hostKeys,
                                         Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(),
                                         AuditSink      = audit
                                     });

            await server.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);
            var port = server.LocalEndPoint.Port.ToInt32();

            var (exitCode, stdout, stderr) = await RunAsync(sshKeyscan!, [ "-v", "-T", "10", "-t", "ed25519,ecdsa,rsa", "-p", port.ToString(), "127.0.0.1" ], CancellationToken);

            // "[127.0.0.1]:port ssh-ed25519 AAAA…", one line per key, comments start with '#'.
            var scanned = stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                                .Where (line => !line.StartsWith('#'))
                                .Select(line => line.Split(' '))
                                .Where (parts => parts.Length >= 3)
                                .Select(parts => parts[2])
                                .ToHashSet();

            Assert.That(scanned,
                        Is.EquivalentTo(hostKeys.Select(key => Convert.ToBase64String(key.PublicKeyBlob))),
                        $"ssh-keyscan exited {exitCode}.\nstdout:\n{stdout}\nstderr:\n{stderr}\nour server:\n{audit.Report}");

        }

        #endregion

    }

}
