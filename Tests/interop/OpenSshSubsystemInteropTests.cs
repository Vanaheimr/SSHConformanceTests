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
    /// The real OpenSSH client's <c>ssh -s</c> against subsystems of our own on our server
    /// (<see cref="SshServerOptions.Subsystems"/>): plain bytes both ways, and the exit-status a subsystem
    /// ends with - 0 where its handler returned, 1 where it failed, or the one it sent itself. Without an
    /// exit-status, <c>ssh</c> exits 255 after every subsystem, which is what this guards. And the two ways
    /// a subsystem is refused: a name the server does not serve, and a credential confined to another one.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshSubsystemInteropTests
    {

        #region Data

        private const String Hi     = "hi@test.open.charging.cloud";
        private const String Fails  = "fails@test.open.charging.cloud";
        private const String Own    = "own@test.open.charging.cloud";
        private const String Echo   = "echo@test.open.charging.cloud";

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

        /// <summary>
        /// Takes the one key, and confines the session as told.
        /// </summary>
        private sealed class Confining(Byte[] Key, SshSessionRestrictions Restrictions) : ISshUserAuthenticator
        {

            public IReadOnlyList<String> OfferedMethods { get; } = [ "publickey" ];

            public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(Request.PublicKeyBlob.AsSpan().SequenceEqual(Key));

            public ValueTask<SshSessionRestrictions> GetRestrictionsAsync(SshPublicKeyAuthRequest Request, CancellationToken CancellationToken = default)
                => ValueTask.FromResult(Restrictions);

        }

        /// <summary>
        /// The subsystems this server serves; anything else is refused.
        /// </summary>
        private static SshSubsystemHandler? Serve(String Name)

            => Name switch {

                   Hi     => async (context, token) => {
                                 await context.Channel.SendDataAsync("hi\n"u8.ToArray(), token);
                             },

                   Fails  => async (context, token) => {
                                 await context.Channel.SendDataAsync("bye\n"u8.ToArray(), token);
                                 throw new InvalidOperationException("The handler failed.");
                             },

                   Own    => async (context, token) => {
                                 await context.Channel.SendExitStatusAsync(7, token);
                             },

                   Echo   => async (context, token) => {
                                 var buffer = new Byte[4096];
                                 Int32 read;
                                 while ((read = await context.Channel.Input.ReadAsync(buffer, token)) > 0)
                                     await context.Channel.SendDataAsync(buffer.AsMemory(0, read).ToArray(), token);
                             },

                   _      => null

               };

        /// <summary>
        /// Runs <c>ssh -s <paramref name="Subsystem"/></c> against a server of ours, writes
        /// <paramref name="Stdin"/> and closes it, and answers how ssh ended.
        /// </summary>
        private static async Task<(Int32 ExitCode, String Stdout, String Stderr)> RunSshAsync(String                   Subsystem,
                                                                                               String                   Stdin,
                                                                                               SshSessionRestrictions?  Restrictions,
                                                                                               CancellationToken        CancellationToken)
        {

            var ssh        = FindOnPathOrSystem("ssh");
            var sshKeygen  = FindOnPathOrSystem("ssh-keygen");
            if (ssh is null || sshKeygen is null)
                Assert.Ignore("No 'ssh'/'ssh-keygen' found.");

            var keyPath     = Path.Combine(Path.GetTempPath(), "hermod_subsystem_" + Guid.NewGuid().ToString("N"));
            var knownHosts  = keyPath + ".known_hosts";
            var emptyConf   = keyPath + ".config";

            try
            {

                using (var keygen = Process.Start(new ProcessStartInfo(sshKeygen!) { ArgumentList = { "-q", "-t", "ed25519", "-N", "", "-f", keyPath }, UseShellExecute = false, CreateNoWindow = true })!)
                    await keygen.WaitForExitAsync(CancellationToken);

                var publicBlob = Convert.FromBase64String((await File.ReadAllTextAsync(keyPath + ".pub", CancellationToken)).Split(' ')[1]);
                var hostKey    = SshHostKey.GenerateEd25519();

                await using var server = new SshServer(new SshServerOptions {
                                             HostKeys       = [ hostKey ],
                                             Authenticator  = new Confining(publicBlob, Restrictions ?? SshSessionRestrictions.None),
                                             Subsystems     = (session, name, ct) => ValueTask.FromResult(Serve(name))
                                         });

                await server.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                await File.WriteAllTextAsync(knownHosts, $"[127.0.0.1]:{port} ssh-ed25519 {Convert.ToBase64String(hostKey.PublicKeyBlob)}\n", CancellationToken);
                await File.WriteAllTextAsync(emptyConf,  "", CancellationToken);

                using var client = new Process { StartInfo = new ProcessStartInfo(ssh!) { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };
                foreach (var arg in new[] {
                    "-F", emptyConf, "-T", "-s", "-p", port.ToString(), "-l", "station",
                    "-i", keyPath, "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
                    "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=yes", "-o", $"UserKnownHostsFile={knownHosts}", "-o", $"GlobalKnownHostsFile={knownHosts}",
                    "-o", "LogLevel=ERROR",
                    "127.0.0.1", Subsystem
                })
                    client.StartInfo.ArgumentList.Add(arg);

                client.Start();

                var stdoutTask = client.StandardOutput.ReadToEndAsync(CancellationToken);
                var stderrTask = client.StandardError. ReadToEndAsync(CancellationToken);

                try
                {

                    await client.StandardInput.WriteAsync(Stdin);
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
                foreach (var file in new[] { keyPath, keyPath + ".pub", knownHosts, emptyConf })
                    try { File.Delete(file); } catch { }
            }

        }

        #endregion


        #region RealSshClient_ReachesOurSubsystem_WithItsExitStatus

        /// <summary>
        /// A handler that returns ends with 0, one that fails with 1, one that sent its own status with
        /// that status alone; and what each wrote, or echoed of what it was sent, reaches ssh's stdout.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        [TestCase(Hi,     "",               "hi\n",             0)]
        [TestCase(Fails,  "",               "bye\n",            1)]
        [TestCase(Own,    "",               "",                 7)]
        [TestCase(Echo,   "one\ntwo\n",     "one\ntwo\n",       0)]
        public async Task RealSshClient_ReachesOurSubsystem_WithItsExitStatus(String             Subsystem,
                                                                               String             Stdin,
                                                                               String             ExpectedStdout,
                                                                               Int32              ExpectedExit,
                                                                               CancellationToken  CancellationToken)
        {

            var (exitCode, stdout, stderr) = await RunSshAsync(Subsystem, Stdin, null, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(stdout,    Is.EqualTo(ExpectedStdout), "what the subsystem sent reaches ssh's stdout\nssh stderr:\n" + stderr);
                Assert.That(exitCode,  Is.EqualTo(ExpectedExit),   "ssh exits with the subsystem's exit-status\nssh stderr:\n" + stderr);
            });

        }

        #endregion

        #region RealSshClient_IsRefused_ASubsystemNotServed

        /// <summary>
        /// A name the factory does not serve is refused, and ssh says so.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        public async Task RealSshClient_IsRefused_ASubsystemNotServed(CancellationToken CancellationToken)
        {

            var (exitCode, stdout, stderr) = await RunSshAsync("unknown@test.open.charging.cloud", "", null, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode,  Is.Not.EqualTo(0));
                Assert.That(stderr,    Does.Contain("subsystem request failed"));
                Assert.That(stdout,    Is.Empty);
            });

        }

        #endregion

        #region RealSshClient_IsRefused_ASubsystemItsKeyIsNotConfinedTo

        /// <summary>
        /// A credential confined to one subsystem (<see cref="SshSessionRestrictions.PermittedSubsystems"/>)
        /// is refused another that the server does serve - and still reaches its own.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        public async Task RealSshClient_IsRefused_ASubsystemItsKeyIsNotConfinedTo(CancellationToken CancellationToken)
        {

            var confined = new SshSessionRestrictions(PermittedSubsystems: new HashSet<String> { Echo });

            var (refusedExit,  refusedStdout, refusedStderr) = await RunSshAsync(Hi,   "",      confined, CancellationToken);
            var (permitExit,   permitStdout,  permitStderr)  = await RunSshAsync(Echo, "ok\n",  confined, CancellationToken);

            Assert.Multiple(() => {
                Assert.That(refusedExit,    Is.Not.EqualTo(0),                  "the other subsystem is refused");
                Assert.That(refusedStderr,  Does.Contain("subsystem request failed"));
                Assert.That(refusedStdout,  Is.Empty);
                Assert.That(permitStdout,   Is.EqualTo("ok\n"),                 "its own is served\nssh stderr:\n" + permitStderr);
                Assert.That(permitExit,     Is.EqualTo(0));
            });

        }

        #endregion

    }

}
