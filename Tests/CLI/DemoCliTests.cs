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

using System.Net;
using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.CLI;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    using IPAddress = System.Net.IPAddress;

    /// <summary>
    /// M10: the demo CLI's verbs wire the library correctly - the offline ones (keygen / scan / ca), and
    /// <c>forward</c> against <c>serve</c>.
    /// </summary>
    [TestFixture]
    public class DemoCliTests
    {

        private String dir = "";

        [SetUp]
        public void MakeDir()
        {
            dir = Path.Combine(Path.GetTempPath(), "hermod_cli_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
        }

        [TearDown]
        public void CleanDir()
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }


        #region Keygen_Scan_Ca_Pipeline

        [Test]
        [CancelAfter(20000)]
        public async Task Keygen_Scan_Ca_Pipeline(CancellationToken CancellationToken)
        {

            var userKey = Path.Combine(dir, "user");
            var caKey   = Path.Combine(dir, "ca");

            // keygen writes the private key + a .pub, and returns success.
            var kg1 = await Commands.KeygenAsync(["keygen", "-t", "ed25519", "-f", userKey, "-C", "achim@test"], CancellationToken);
            var kg2 = await Commands.KeygenAsync(["keygen", "-t", "ecdsa-sha2-nistp256", "-f", caKey], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(kg1, Is.EqualTo(0));
                Assert.That(kg2, Is.EqualTo(0));
                Assert.That(File.Exists(userKey),          Is.True);
                Assert.That(File.Exists(userKey + ".pub"), Is.True);
            });

            // scan succeeds on the generated public key.
            var scan = await Commands.ScanAsync(["scan", "-f", userKey + ".pub", "-n", "dev.fleet."], CancellationToken);
            Assert.That(scan, Is.EqualTo(0));

            // ca signs the user key with the CA key and writes a *-cert.pub whose blob is a real certificate.
            var ca = await Commands.CaAsync(["ca", "--ca", caKey, "-s", userKey + ".pub", "-I", "achim@2026", "-n", "achim,admin", "-z", "42"], CancellationToken);
            var certFile = userKey + "-cert.pub";

            Assert.Multiple(() => {
                Assert.That(ca, Is.EqualTo(0));
                Assert.That(File.Exists(certFile), Is.True);
            });

            // The emitted certificate parses back and carries what the CLI put in it.
            var line = (await File.ReadAllTextAsync(certFile, CancellationToken)).Split(' ');
            var cert = SshCertificate.Parse(Convert.FromBase64String(line[1]));

            Assert.Multiple(() => {
                Assert.That(cert.Serial,     Is.EqualTo(42UL));
                Assert.That(cert.KeyId,      Is.EqualTo("achim@2026"));
                Assert.That(cert.Principals, Is.EqualTo(new[] { "achim", "admin" }));
            });

        }

        #endregion

        #region Forward_LocalAndRemote_ThroughTheDemoServer

        /// <summary>
        /// <c>forward -L</c> and <c>forward -R</c> against <c>serve</c>, all three verbs running at once as
        /// they would in three terminals: a connection to either forward's port comes out at the same echo
        /// target, and Ctrl+C ends every verb cleanly.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        public async Task Forward_LocalAndRemote_ThroughTheDemoServer(CancellationToken CancellationToken)
        {

            var userKey   = Path.Combine(dir, "user");
            var hostKey   = Path.Combine(dir, "host");
            var authKeys  = Path.Combine(dir, "authorized_keys");

            Assert.That(await Commands.KeygenAsync(["keygen", "-t", "ed25519", "-f", userKey], CancellationToken), Is.EqualTo(0));
            File.Copy(userKey + ".pub", authKeys);

            var echo = new TcpListener(IPAddress.Loopback, 0);
            echo.Start();
            var echoPort = ((IPEndPoint) echo.LocalEndpoint).Port;

            _ = Task.Run(async () => {
                try
                {
                    while (true)
                    {
                        var connection = await echo.AcceptTcpClientAsync(CancellationToken);
                        _ = Task.Run(async () => {
                            using (connection)
                            {
                                var stream = connection.GetStream();
                                var buffer = new Byte[4096];
                                Int32 read;
                                while ((read = await stream.ReadAsync(buffer, CancellationToken)) > 0)
                                    await stream.WriteAsync(buffer.AsMemory(0, read), CancellationToken);
                            }
                        }, CancellationToken);
                    }
                }
                catch { }
            }, CancellationToken);

            var serverPort = FreePort();
            var localPort  = FreePort();
            var remotePort = FreePort();

            using var ctrlC = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);

            try
            {

                var serve = Commands.ServeAsync(["serve", "-a", authKeys, "-k", hostKey, "-p", $"{serverPort}"], ctrlC.Token);
                await ConnectedAsync(serverPort, CancellationToken);

                var local  = Commands.ForwardAsync(["forward", "-i", userKey, "-p", $"{serverPort}", "-L", $"{localPort}:127.0.0.1:{echoPort}",  "achim@127.0.0.1"], ctrlC.Token);
                var remote = Commands.ForwardAsync(["forward", "-i", userKey, "-p", $"{serverPort}", "-R", $"{remotePort}:127.0.0.1:{echoPort}", "achim@127.0.0.1"], ctrlC.Token);

                var throughLocal  = await RoundTripAsync(localPort,  "through -L", CancellationToken);
                var throughRemote = await RoundTripAsync(remotePort, "through -R", CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(throughLocal,  Is.EqualTo("through -L"), "the client's port reached the target through the server");
                    Assert.That(throughRemote, Is.EqualTo("through -R"), "the server's port reached the target through the client");
                });

                await ctrlC.CancelAsync();

                Assert.That(await Task.WhenAll(serve, local, remote), Is.EqualTo(new[] { 0, 0, 0 }), "Ctrl+C ends every verb cleanly");

            }
            finally
            {
                await ctrlC.CancelAsync();
                echo.Stop();
            }

        }

        #endregion

        #region Forward_RefusesWhatItCannotParse

        /// <summary>
        /// A forward spec <c>ssh</c> would not take, or both directions at once, ends in the usage line
        /// before anything is connected.
        /// </summary>
        [TestCase("-L", "8080:example.com")]
        [TestCase("-L", "8080:example.com:http")]
        [TestCase("-L", "a:b:c:d:e")]
        [TestCase("-L", "[::1:8080:example.com:80")]
        [TestCase("-L", "not-an-address:8080:example.com:80")]
        [CancelAfter(10000)]
        public async Task Forward_RefusesWhatItCannotParse(String Option, String Spec, CancellationToken CancellationToken)
        {

            Assert.That(await Commands.ForwardAsync(["forward", "-i", "unused", Option, Spec, "achim@127.0.0.1"], CancellationToken), Is.Not.Zero);

            Assert.That(await Commands.ForwardAsync(["forward", "-i", "unused", "-L", "1:a:2", "-R", "3:b:4", "achim@127.0.0.1"], CancellationToken), Is.Not.Zero,
                        "-L and -R at once");

        }

        #endregion


        #region (private) helpers

        private static Int32 FreePort()
        {
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            var port = ((IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }

        // A verb that was just started listens a moment later; until then a connection is refused.
        private static async Task<TcpClient> ConnectedAsync(Int32 Port, CancellationToken CancellationToken)
        {
            while (true)
            {
                var client = new TcpClient();
                try
                {
                    await client.ConnectAsync(IPAddress.Loopback, Port, CancellationToken);
                    return client;
                }
                catch (SocketException)
                {
                    client.Dispose();
                    await Task.Delay(50, CancellationToken);
                }
            }
        }

        private static async Task<String> RoundTripAsync(Int32 Port, String Text, CancellationToken CancellationToken)
        {

            using var client = await ConnectedAsync(Port, CancellationToken);

            var stream = client.GetStream();
            var sent   = Encoding.UTF8.GetBytes(Text);
            await stream.WriteAsync(sent, CancellationToken);

            var back = new Byte[sent.Length];
            await stream.ReadExactlyAsync(back, CancellationToken);
            return Encoding.UTF8.GetString(back);

        }

        #endregion

    }

}
