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
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// The admin console of a charging station, end to end with the real OpenSSH tools: <c>ssh-keygen</c>
    /// as the CA issues the operator a certificate with an extension of its own, and <c>ssh -tt -s</c>
    /// asks our server for the console with a terminal. The factory grants the console by that extension
    /// (<see cref="SshSessionInfo.Certificate"/>), and the console is given the terminal ssh asked for
    /// (<see cref="SshSubsystemContext.Terminal"/>) - unless the certificate withholds it (<c>no-pty</c>),
    /// and then <c>ssh -t</c> does not get one either.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshAdminConsoleInteropTests
    {

        #region Data

        private const String Admin       = "admin@test.open.charging.cloud";
        private const String AdminGrant  = "admin-console@test.open.charging.cloud";
        private const String Term        = "xterm-256color";

        #endregion

        #region (private) Fixture

        private static String? FindOnPathOrSystem(String Tool)
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { Tool, Tool + ".exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }
            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", Tool + ".exe");
            return File.Exists(system) ? system : null;
        }

        private static async Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(String Tool, CancellationToken CancellationToken, params String[] Arguments)
        {

            using var process = new Process { StartInfo = new ProcessStartInfo(Tool) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };

            foreach (var argument in Arguments)
                process.StartInfo.ArgumentList.Add(argument);

            process.Start();

            var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken);
            var stderr = process.StandardError. ReadToEndAsync(CancellationToken);

            await process.WaitForExitAsync(CancellationToken);

            return (process.ExitCode, await stdout, await stderr);

        }

        /// <summary>
        /// The console: says what terminal it was given and which operator the certificate names, and
        /// ends when the operator types "q".
        /// </summary>
        private static async ValueTask ServeConsoleAsync(SshSubsystemContext Context, CancellationToken CancellationToken)
        {

            var terminal = Context.Pty is SshPty pty ? pty.Term : "no terminal";

            await Context.Channel.SendDataAsync(Encoding.UTF8.GetBytes($"{terminal} for {Context.Session.Certificate?.KeyId}\r\n"), CancellationToken);

            var one = new Byte[1];
            while (await Context.Channel.Input.ReadAsync(one, CancellationToken) > 0 && one[0] != (Byte) 'q')
            { }

        }

        /// <summary>
        /// Issues the operator a certificate with <c>ssh-keygen -s</c> and the given options, starts a server
        /// that trusts the CA and serves the console where the certificate grants it, and runs
        /// <c>ssh -tt -s</c> against it, typing "q".
        /// </summary>
        private static async Task<(Int32 ExitCode, String Stdout, String Stderr)> RunSshAsync(String             KeyId,
                                                                                               String[]           CertificateOptions,
                                                                                               CancellationToken  CancellationToken)
        {

            var ssh        = FindOnPathOrSystem("ssh");
            var sshKeygen  = FindOnPathOrSystem("ssh-keygen");
            if (ssh is null || sshKeygen is null)
                Assert.Ignore("No 'ssh'/'ssh-keygen' found.");

            var dir         = Directory.CreateTempSubdirectory("hermod_admin_");
            var ca          = Path.Combine(dir.FullName, "ca");
            var user        = Path.Combine(dir.FullName, "operator");
            var knownHosts  = Path.Combine(dir.FullName, "known_hosts");
            var emptyConf   = Path.Combine(dir.FullName, "config");

            try
            {

                if ((await RunAsync(sshKeygen!, CancellationToken, "-q", "-t", "ed25519", "-N", "", "-C", "ca",       "-f", ca  )).ExitCode != 0 ||
                    (await RunAsync(sshKeygen!, CancellationToken, "-q", "-t", "ed25519", "-N", "", "-C", "operator", "-f", user)).ExitCode != 0)
                    Assert.Ignore("ssh-keygen could not generate keys.");

                var sign = await RunAsync(sshKeygen!, CancellationToken,
                                          [ "-q", "-s", ca, "-I", KeyId, "-n", "operator", "-V", "-1h:+1h", .. CertificateOptions, user + ".pub" ]);

                if (sign.ExitCode != 0)
                    Assert.Ignore($"ssh-keygen -s failed: {sign.StdErr}");

                var trust    = new SshCertificateAuthorityTrust().TrustCA(SshPublicKey.Parse(await File.ReadAllTextAsync(ca + ".pub", CancellationToken)).Blob);
                var hostKey  = SshHostKey.GenerateEd25519();

                await using var server = new SshServer(new SshServerOptions {
                                             HostKeys       = [ hostKey ],
                                             Authenticator  = new SshAuthenticationPolicy().WithCertificateAuthority(trust),
                                             Subsystems     = (session, name, ct) => ValueTask.FromResult<SshSubsystemHandler?>(
                                                                                         name == Admin &&
                                                                                         session.Certificate is SshCertificate certificate &&
                                                                                         certificate.Extensions.Any(extension => extension.Key == AdminGrant)
                                                                                             ? ServeConsoleAsync
                                                                                             : null)
                                         });

                await server.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                await File.WriteAllTextAsync(knownHosts, $"[127.0.0.1]:{port} ssh-ed25519 {Convert.ToBase64String(hostKey.PublicKeyBlob)}\n", CancellationToken);
                await File.WriteAllTextAsync(emptyConf,  "", CancellationToken);

                // -tt: a terminal although stdin is not one - the operator at a terminal, as a test can have it.
                using var client = new Process { StartInfo = new ProcessStartInfo(ssh!) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
                client.StartInfo.Environment["TERM"] = Term;

                foreach (var arg in new[] {
                    "-F", emptyConf, "-tt", "-s", "-p", port.ToString(), "-l", "operator",
                    "-i", user, "-o", $"CertificateFile={user}-cert.pub", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                    "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=yes", "-o", $"UserKnownHostsFile={knownHosts}", "-o", $"GlobalKnownHostsFile={knownHosts}",
                    "-o", "LogLevel=ERROR",
                    "127.0.0.1", Admin
                })
                    client.StartInfo.ArgumentList.Add(arg);

                client.Start();

                var stdoutTask = client.StandardOutput.ReadToEndAsync(CancellationToken);
                var stderrTask = client.StandardError. ReadToEndAsync(CancellationToken);

                try
                {

                    await client.StandardInput.WriteAsync("q");
                    await client.StandardInput.FlushAsync(CancellationToken);
                    client.StandardInput.Close();

                    await client.WaitForExitAsync(CancellationToken);

                    return (client.ExitCode, await stdoutTask, await stderrTask);

                }
                catch
                {
                    try { if (!client.HasExited) client.Kill(true); } catch { }
                    throw;
                }

            }
            finally
            {
                try { dir.Delete(recursive: true); } catch { }
            }

        }

        #endregion


        #region RealSshClient_ReachesTheAdminConsole_ItsCertificateGrants_WithItsTerminal

        /// <summary>
        /// <c>ssh -tt -s</c> with a certificate that grants the console: the console is served, is given
        /// the terminal ssh asked for - TERM as ssh read it - and knows the operator by the key id.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        public async Task RealSshClient_ReachesTheAdminConsole_ItsCertificateGrants_WithItsTerminal(CancellationToken CancellationToken)
        {

            var (exitCode, stdout, stderr) = await RunSshAsync("operator-17", [ "-O", $"extension:{AdminGrant}" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(stdout,    Does.Contain($"{Term} for operator-17"), "the console was not given ssh's terminal, or did not see the certificate\nssh stderr:\n" + stderr);
                Assert.That(exitCode,  Is.EqualTo(0),                           "ssh exits with the console's exit-status\nssh stderr:\n" + stderr);
            });

        }

        #endregion

        #region RealSshClient_IsRefusedTheTerminal_WhereTheCertificateWithholdsIt

        /// <summary>
        /// A certificate that grants the console but not a terminal (<c>no-pty</c>, so no <c>permit-pty</c>):
        /// the terminal is refused for a subsystem as for a shell. And <c>ssh</c>, told with <c>-t</c> to
        /// have one, gives up rather than carry on without it - OpenSSH's choice, not the server's: a client
        /// that asks for a terminal only where it can (<c>RequestTTY auto</c>) is served the console without.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        public async Task RealSshClient_IsRefusedTheTerminal_WhereTheCertificateWithholdsIt(CancellationToken CancellationToken)
        {

            var (exitCode, stdout, stderr) = await RunSshAsync("operator-18", [ "-O", "no-pty", "-O", $"extension:{AdminGrant}" ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(stderr,    Does.Contain("PTY allocation request failed"), "a certificate without permit-pty was given a terminal");
                Assert.That(stdout,    Does.Not.Contain($"{Term} for operator-18"),    "a certificate without permit-pty was given a terminal");
                Assert.That(exitCode,  Is.Not.EqualTo(0),                             "ssh -tt carried on without the terminal it was told to have\nssh stderr:\n" + stderr);
            });

        }

        #endregion

        #region RealSshClient_IsRefusedTheAdminConsole_WithoutTheGrant

        /// <summary>
        /// A certificate of the same CA without the extension signs in - and is refused the console.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        public async Task RealSshClient_IsRefusedTheAdminConsole_WithoutTheGrant(CancellationToken CancellationToken)
        {

            var (exitCode, stdout, stderr) = await RunSshAsync("operator-19", [], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode,  Is.Not.EqualTo(0));
                Assert.That(stderr,    Does.Contain("subsystem request failed"));
                Assert.That(stdout,    Does.Not.Contain("for operator-19"));
            });

        }

        #endregion

    }

}
