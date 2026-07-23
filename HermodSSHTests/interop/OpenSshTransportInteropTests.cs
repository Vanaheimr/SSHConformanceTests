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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{


    /// <summary>
    /// Interoperability tests against the real OpenSSH client. These prove that our transport (KEX,
    /// key derivation, AES-GCM framing) matches OpenSSH byte-for-byte: the ultimate M1 acceptance test.
    /// Skipped (not failed) when no <c>ssh</c> client is available.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshTransportInteropTests
    {

        #region (static) FindSshClient()

        private static String? FindSshClient()
        {

            var windowsOpenSsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh.exe");
            if (File.Exists(windowsOpenSsh))
                return windowsOpenSsh;

            // Fall back to whatever "ssh" is on PATH (Linux/macOS or Git for Windows).
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
            {
                foreach (var name in new[] { "ssh", "ssh.exe" })
                {
                    try
                    {
                        var candidate = Path.Combine(dir.Trim(), name);
                        if (File.Exists(candidate))
                            return candidate;
                    }
                    catch
                    { /* ignore malformed PATH entries */ }
                }
            }

            return null;

        }

        #endregion


        #region OurServer_CompletesTransport_WithRealOpenSshClient

        [Test]
        [CancelAfter(30000)]
        [TestCase("curve25519-sha256",   "ssh-ed25519",         "chacha20-poly1305@openssh.com", "hmac-sha2-256",          "chacha20-poly1305@openssh.com")]
        [TestCase("curve25519-sha256",   "ssh-ed25519",         "aes256-gcm@openssh.com", "hmac-sha2-256",                 "aes256-gcm@openssh.com")]
        [TestCase("curve25519-sha256",   "ssh-ed25519",         "aes256-ctr",             "hmac-sha2-256-etm@openssh.com", "aes256-ctr")]
        [TestCase("ecdh-sha2-nistp256",  "ssh-ed25519",         "aes256-gcm@openssh.com", "hmac-sha2-256",                 "aes256-gcm@openssh.com")]
        [TestCase("ecdh-sha2-nistp521",  "ssh-ed25519",         "aes256-ctr",             "hmac-sha2-512-etm@openssh.com", "aes256-ctr")]
        [TestCase("curve25519-sha256",   "ecdsa-sha2-nistp256", "aes256-gcm@openssh.com", "hmac-sha2-256",                 "aes256-gcm@openssh.com")]
        [TestCase("curve25519-sha256",   "rsa-sha2-512",        "aes256-gcm@openssh.com", "hmac-sha2-256",                 "aes256-gcm@openssh.com")]
        public async Task OurServer_CompletesTransport_WithRealOpenSshClient(String             SshKex,
                                                                             String             SshHostKeyAlg,
                                                                             String             SshCipher,
                                                                             String             SshMac,
                                                                             String             ExpectedCipher,
                                                                             CancellationToken  CancellationToken)
        {

            var sshClient = FindSshClient();
            if (sshClient is null)
                Assert.Ignore("No 'ssh' client found — skipping OpenSSH transport interop.");

            var hostKey = HostKeyMatrixTests.MakeHostKey(SshHostKeyAlg);

            using var listener = SshTcpListener.Start(new IPSocket(IPv4Address.Localhost, IPPort.Auto));
            var port = listener.LocalEndPoint.Port.ToInt32();

            // The server accepts one connection, completes the handshake, and reads the client's first
            // encrypted packet — which must be SSH_MSG_SERVICE_REQUEST("ssh-userauth").
            var serverTask = Task.Run(async () =>
            {
                var pipe = await listener.AcceptAsync(CancellationToken);
                using var context = await SshHandshake.ServerHandshakeAsync(pipe, hostKey, CancellationToken: CancellationToken);
                // First post-NEWKEYS packet is sequence number 0 (strict-KEX). ReceiveMac is null for AEAD.
                var firstEncryptedPayload = await SshPacketFraming.ReadPacketAsync(pipe.Input, context.ReceiveCipher, 0, context.ReceiveMac, CancellationToken: CancellationToken);
                return (context.Algorithms, firstEncryptedPayload);
            }, CancellationToken);

            var knownHosts = Path.GetTempFileName();
            var emptyConf  = Path.GetTempFileName();

            using var ssh = new Process { StartInfo = new ProcessStartInfo(sshClient!)
            {
                RedirectStandardError   = true,
                RedirectStandardOutput  = true,
                UseShellExecute         = false,
                CreateNoWindow          = true
            }};

            foreach (var arg in new[]
            {
                "-F", emptyConf,                                       // ignore the user's ssh_config
                "-p", port.ToString(),
                "-o", "StrictHostKeyChecking=no",
                "-o", $"UserKnownHostsFile={knownHosts}",
                "-o", $"KexAlgorithms={SshKex}",
                "-o", $"HostKeyAlgorithms={SshHostKeyAlg}",
                "-o", $"Ciphers={SshCipher}",
                "-o", $"MACs={SshMac}",
                "-o", "PreferredAuthentications=none",
                "-o", "PubkeyAuthentication=no",
                "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no",
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=10",
                "-vv",
                "hermod@127.0.0.1",
                "exit"
            })
                ssh.StartInfo.ArgumentList.Add(arg);

            String stderr = "";

            try
            {

                ssh.Start();
                var stderrTask = ssh.StandardError.ReadToEndAsync(CancellationToken);

                var (algorithms, payload) = await serverTask;

                // We have the proof (the decrypted SERVICE_REQUEST). The client would otherwise hang
                // waiting for a SERVICE_ACCEPT we don't send in M1, so stop it now and read its log.
                try { if (!ssh.HasExited) ssh.Kill(entireProcessTree: true); } catch { }
                try { stderr = await stderrTask; } catch { /* torn down */ }

                var reader   = new SshPacketReader(payload);
                var message  = (SshMessageNumber) reader.ReadByte();
                var service  = message == SshMessageNumber.ServiceRequest ? reader.ReadString() : "";

                Assert.Multiple(() => {
                    Assert.That(algorithms.KeyExchange,          Is.EqualTo(SshKex));
                    Assert.That(algorithms.CipherClientToServer, Is.EqualTo(ExpectedCipher));
                    Assert.That(algorithms.StrictKex,            Is.True, "OpenSSH 9.6+ must negotiate strict-KEX with us.");
                    Assert.That(message,                         Is.EqualTo(SshMessageNumber.ServiceRequest),
                                "The real OpenSSH client's first encrypted packet must decrypt to SSH_MSG_SERVICE_REQUEST.");
                    Assert.That(service,                         Is.EqualTo("ssh-userauth"));
                });

            }
            catch (Exception e)
            {
                try   { if (!ssh.HasExited) { /* drain */ } stderr = await ssh.StandardError.ReadToEndAsync(CancellationToken); }
                catch { }
                TestContext.Out.WriteLine("ssh -vv stderr:\n" + stderr);
                throw new AssertionException("The OpenSSH transport interop failed. ssh -vv output:\n" + stderr, e);
            }
            finally
            {
                try { if (!ssh.HasExited) ssh.Kill(entireProcessTree: true); } catch { }
                try { File.Delete(knownHosts); } catch { }
                try { File.Delete(emptyConf);  } catch { }
            }

        }

        #endregion

    }

}
