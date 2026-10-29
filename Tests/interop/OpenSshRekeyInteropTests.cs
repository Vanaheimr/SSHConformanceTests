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
    /// The real <c>ssh</c> client and our server renewing the keys of a connection that is busy moving
    /// data - started by our server once it has sent 64 KiB under a key, or by ssh with
    /// <c>RekeyLimit 64K</c>.
    ///
    /// <para>
    /// Until automatic rekeying existed, our server only ever answered a rekey; it never started one,
    /// so a connection kept the keys of its handshake for as long as it lived. Both directions are
    /// checked by what arrives - every byte, in order - and by the server's audit stream, which records
    /// each rekey.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshRekeyInteropTests
    {

        private static String? FindOnPathOrSystem(String Tool)
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { Tool, Tool + ".exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }
            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", Tool + ".exe");
            return File.Exists(system) ? system : null;
        }


        #region RealOpenSshClient_Rekeys_WithOurServer

        [Test]
        [CancelAfter(60000)]
        [TestCase(true,  TestName = "RealOpenSshClient_Rekeys_WithOurServer(our server starts the rekeys)")]
        [TestCase(false, TestName = "RealOpenSshClient_Rekeys_WithOurServer(ssh starts the rekeys)")]
        public async Task RealOpenSshClient_Rekeys_WithOurServer(Boolean ServerStarts, CancellationToken CancellationToken)
        {

            var ssh       = FindOnPathOrSystem("ssh");
            var sshKeygen = FindOnPathOrSystem("ssh-keygen");
            if (ssh is null || sshKeygen is null)
                Assert.Ignore("No 'ssh'/'ssh-keygen' found.");

            // A pattern rather than zeros, so a lost or repeated packet cannot go unnoticed.
            var output     = Enumerable.Range(0, 2 * 1024 * 1024).Select(i => (Byte) (i % 251)).ToArray();

            var keyPath    = Path.Combine(Path.GetTempPath(), "hermod_rekey_" + Guid.NewGuid().ToString("N"));
            var knownHosts = Path.GetTempFileName();
            var emptyConf  = Path.GetTempFileName();

            try
            {

                using (var keygen = Process.Start(new ProcessStartInfo(sshKeygen!) { ArgumentList = { "-t", "ed25519", "-f", keyPath, "-N", "", "-q" }, UseShellExecute = false, CreateNoWindow = true })!)
                    await keygen.WaitForExitAsync(CancellationToken);

                var publicBlob = Convert.FromBase64String((await File.ReadAllTextAsync(keyPath + ".pub", CancellationToken)).Split(' ')[1]);
                var audit      = new CollectingAuditSink();

                await using var server = new SshServer(new SshServerOptions {
                    HostKeys       = [ SshHostKey.GenerateEd25519() ],
                    Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(publicBlob),
                    AuditSink      = audit,
                    ExecHandler    = async (context, ct) => { await context.WriteAsync(output, ct); return 0; },
                    RekeyLimits    = ServerStarts ? new SshRekeyLimits { DataVolume = 64 * 1024, Interval = null } : null
                });

                await server.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto), CancellationToken);
                var port = server.LocalEndPoint.Port.ToInt32();

                using var client = new Process { StartInfo = new ProcessStartInfo(ssh!) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true } };

                foreach (var arg in new[] {
                             "-F", emptyConf, "-p", port.ToString(),
                             "-o", "StrictHostKeyChecking=no", "-o", $"UserKnownHostsFile={knownHosts}",
                             "-i", keyPath, "-o", "IdentitiesOnly=yes",
                             "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no",
                             "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                             "-o", ServerStarts ? "RekeyLimit=default none" : "RekeyLimit=64K",
                             "-v", "hermoduser@127.0.0.1", "produce" })
                    client.StartInfo.ArgumentList.Add(arg);

                client.Start();

                var stderrTask = client.StandardError.ReadToEndAsync(CancellationToken);
                using var received = new MemoryStream();
                await client.StandardOutput.BaseStream.CopyToAsync(received, CancellationToken);
                await client.WaitForExitAsync(CancellationToken);
                var stderr = await stderrTask;

                // The last rekey's audit record is written as the exchange ends, which may be just after ssh
                // has read its output; give it a moment rather than racing it.
                var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
                while (audit.Events.OfType<RekeyedEvent>().Count() < 8 && DateTimeOffset.UtcNow < deadline)
                    await Task.Delay(50, CancellationToken);

                var rekeys = audit.Events.OfType<RekeyedEvent>().Count();
                TestContext.Out.WriteLine($"{received.Length} bytes, {rekeys} rekeys audited");

                // Our server sends the data, so when it rekeys, its next packet waits for the exchange:
                // its rekeys follow the bytes. When ssh rekeys, as it receives, whatever our server has
                // in flight still arrives under the old key and counts towards it, and how much that is
                // depends on the scheduler - a Windows runner managed 7 where 8 had been asked for. So
                // that case asks for repetition, not for a number.
                var expected = ServerStarts ? 8 : 3;

                Assert.Multiple(() => {
                    Assert.That(client.ExitCode,      Is.EqualTo(0), $"ssh should succeed. ssh -v:\n{stderr}");
                    Assert.That(received.ToArray(),   Is.EqualTo(output), "every byte, in order, across the rekeys");
                    Assert.That(rekeys,               Is.GreaterThanOrEqualTo(expected), $"two megabytes at 64 KiB a key are many rekeys. ssh -v:\n{stderr}");
                });

            }
            finally
            {
                try { File.Delete(keyPath);          } catch { }
                try { File.Delete(keyPath + ".pub"); } catch { }
                try { File.Delete(knownHosts);       } catch { }
                try { File.Delete(emptyConf);        } catch { }
            }

        }

        #endregion

    }

}
