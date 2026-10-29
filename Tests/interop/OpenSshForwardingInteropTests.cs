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
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// The real OpenSSH client forwards ports through our server, the way people actually type it:
    /// <c>ssh -R</c> and <c>ssh -L</c>, bytes travelling end to end through the tunnel.
    ///
    /// <para>
    /// The library's own suite covers forwarding between our client and our server, which agree on
    /// whatever they both got wrong. What only a real client shows is what it puts on the wire: a plain
    /// <c>ssh -R 8080:host:80</c> asks the server to bind <c>"localhost"</c>, not an address, and
    /// <c>ssh -R 0:host:80</c> asks for a port the server must choose and report back — and the client
    /// only accepts the <c>forwarded-tcpip</c> channels whose address and port match what it asked for.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshForwardingInteropTests
    {

        #region (private) helpers

        private static String? FindOnPathOrSystem(String Tool)
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { Tool, Tool + ".exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }
            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", Tool + ".exe");
            return File.Exists(system) ? system : null;
        }

        private static UInt16 FreeLoopbackPort()
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = (UInt16) ((System.Net.IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        /// <summary>
        /// A loopback service that answers every line with <c>pong:</c> and the line — the far end of
        /// each tunnel, so a reply proves the bytes made the whole trip.
        /// </summary>
        private sealed class EchoService : IDisposable
        {

            private readonly System.Net.Sockets.TcpListener  listener = new (System.Net.IPAddress.Loopback, 0);
            private readonly CancellationTokenSource         cts      = new ();

            public UInt16 Port { get; }

            public EchoService()
            {

                listener.Start();
                Port = (UInt16) ((System.Net.IPEndPoint) listener.LocalEndpoint).Port;

                _ = Task.Run(async () => {
                    while (!cts.IsCancellationRequested)
                    {
                        var client = await listener.AcceptTcpClientAsync(cts.Token);
                        _ = Task.Run(async () => {
                            using (client)
                            {
                                var stream = client.GetStream();
                                var reader = new StreamReader(stream, Encoding.ASCII);
                                var line   = await reader.ReadLineAsync(cts.Token);
                                var reply  = Encoding.ASCII.GetBytes($"pong:{line}\n");
                                await stream.WriteAsync(reply, cts.Token);
                            }
                        });
                    }
                });

            }

            public void Dispose()
            {
                cts.Cancel();
                listener.Stop();
            }

        }

        /// <summary>
        /// Connect to the entry of a tunnel and ask it once. Retries while the entry is not listening yet
        /// — the forward is only set up once <c>ssh</c> has authenticated — and gives up as soon as
        /// <c>ssh</c> itself has exited, since then nothing will ever listen.
        /// </summary>
        private static async Task<String> AskThroughAsync(UInt16 EntryPort, Process Ssh, CancellationToken CancellationToken)
        {

            var deadline = DateTimeOffset.UtcNow.AddSeconds(15);

            while (true)
            {

                if (Ssh.HasExited)
                    throw new AssertionException($"ssh exited with {Ssh.ExitCode} before the tunnel on port {EntryPort} answered.");

                try
                {

                    using var client = new System.Net.Sockets.TcpClient();
                    await client.ConnectAsync(System.Net.IPAddress.Loopback, EntryPort, CancellationToken);

                    var stream = client.GetStream();
                    await stream.WriteAsync(Encoding.ASCII.GetBytes("ping\n"), CancellationToken);

                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
                    timeout.CancelAfter(TimeSpan.FromSeconds(5));

                    var reply = await new StreamReader(stream, Encoding.ASCII).ReadLineAsync(timeout.Token);
                    if (reply is not null)
                        return reply;

                }
                catch (System.Net.Sockets.SocketException) when (DateTimeOffset.UtcNow < deadline)
                {
                    // not listening yet
                }
                catch (IOException) when (DateTimeOffset.UtcNow < deadline)
                {
                    // accepted and dropped: the entry exists but the tunnel behind it does not work (yet)
                }

                if (DateTimeOffset.UtcNow >= deadline)
                    throw new AssertionException($"Nothing answered through the tunnel on port {EntryPort} within 15 s.");

                await Task.Delay(200, CancellationToken);

            }

        }

        /// <summary>
        /// Run <c>ssh -N</c> with the given forwarding arguments against a fresh server of ours that
        /// permits loopback forwarding, and hand the running client to <paramref name="Exercise"/>.
        /// </summary>
        private static async Task RunAsync(String[]                                        ForwardArguments,
                                           Func<Process, Func<String>, Task>               Exercise,
                                           CancellationToken                               CancellationToken)
        {

            var ssh       = FindOnPathOrSystem("ssh");
            var sshKeygen = FindOnPathOrSystem("ssh-keygen");
            if (ssh is null || sshKeygen is null)
                Assert.Ignore("No 'ssh'/'ssh-keygen' found.");

            var keyPath    = Path.Combine(Path.GetTempPath(), "hermod_fwd_" + Guid.NewGuid().ToString("N"));
            var knownHosts = Path.GetTempFileName();
            var emptyConf  = Path.GetTempFileName();

            try
            {

                using (var keygen = Process.Start(new ProcessStartInfo(sshKeygen!) { ArgumentList = { "-t", "ed25519", "-f", keyPath, "-N", "", "-q" }, UseShellExecute = false, CreateNoWindow = true })!)
                    await keygen.WaitForExitAsync(CancellationToken);

                var publicBlob = Convert.FromBase64String((await File.ReadAllTextAsync(keyPath + ".pub", CancellationToken)).Split(' ')[1]);

                await using var server = new SshServer(new SshServerOptions {
                    HostKeys          = [ SshHostKey.GenerateEd25519() ],
                    Authenticator     = SshUserAuthenticator.ForAuthorizedKeys(publicBlob),
                    ForwardingPolicy  = ForwardingPolicy.LoopbackOnly
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
                             "-o", "ExitOnForwardFailure=yes",
                             "-N" }.Concat(ForwardArguments).Append("hermoduser@127.0.0.1"))
                    client.StartInfo.ArgumentList.Add(arg);

                // stderr is collected line by line while ssh runs: it is where ssh reports an allocated
                // port, and the only diagnostic when a forward is refused.
                var stderr = new StringBuilder();
                client.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (stderr) stderr.AppendLine(e.Data); };

                client.Start();
                client.BeginErrorReadLine();

                String Stderr() { lock (stderr) return stderr.ToString(); }

                try
                {
                    await Exercise(client, Stderr);
                }
                catch (Exception e) when (e is not IgnoreException)
                {
                    try { if (!client.HasExited) client.Kill(true); } catch { }
                    throw new AssertionException($"OpenSSH forwarding interop failed:\n{e.Message}\nssh stderr:\n{Stderr()}", e);
                }
                finally
                {
                    try { if (!client.HasExited) client.Kill(true); } catch { }
                }

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


        #region RealOpenSshClient_RemoteForwards_ThroughOurServer

        /// <summary>
        /// <c>ssh -R [bind:]port:host:hostport</c>: our server listens, and a connection to it comes out
        /// at the client's end. Without a bind address — the way it is usually typed — OpenSSH asks for
        /// <c>"localhost"</c>, which a server that only takes IP literals refuses.
        /// </summary>
        [Test]
        [CancelAfter(45000)]
        [TestCase("",           TestName = "RealOpenSshClient_RemoteForwards_ThroughOurServer(no bind address)")]
        [TestCase("localhost:", TestName = "RealOpenSshClient_RemoteForwards_ThroughOurServer(localhost)")]
        [TestCase("127.0.0.1:", TestName = "RealOpenSshClient_RemoteForwards_ThroughOurServer(127.0.0.1)")]
        public async Task RealOpenSshClient_RemoteForwards_ThroughOurServer(String BindPrefix, CancellationToken CancellationToken)
        {

            using var echo  = new EchoService();
            var entryPort   = FreeLoopbackPort();

            await RunAsync([ "-R", $"{BindPrefix}{entryPort}:127.0.0.1:{echo.Port}" ], async (ssh, stderr) => {

                var reply = await AskThroughAsync(entryPort, ssh, CancellationToken);
                Assert.That(reply, Is.EqualTo("pong:ping"), "the bytes must come back through -R and the echo service");

            }, CancellationToken);

        }

        #endregion

        #region RealOpenSshClient_RemoteForwards_OnAnAllocatedPort

        /// <summary>
        /// <c>ssh -R 0:host:hostport</c>: the server picks the port, must say which one in its
        /// <c>REQUEST_SUCCESS</c> (RFC 4254 §7.1), and must then name that port — not 0 — in every
        /// <c>forwarded-tcpip</c> channel, or the client refuses the channel as unrequested.
        /// </summary>
        [Test]
        [CancelAfter(45000)]
        public async Task RealOpenSshClient_RemoteForwards_OnAnAllocatedPort(CancellationToken CancellationToken)
        {

            using var echo = new EchoService();

            await RunAsync([ "-R", $"0:127.0.0.1:{echo.Port}" ], async (ssh, stderr) => {

                var deadline = DateTimeOffset.UtcNow.AddSeconds(15);
                Match allocated;

                while (!(allocated = Regex.Match(stderr(), @"Allocated port (\d+) for remote forward")).Success)
                {
                    if (ssh.HasExited || DateTimeOffset.UtcNow >= deadline)
                        throw new AssertionException("ssh never reported the port our server allocated.");
                    await Task.Delay(100, CancellationToken);
                }

                var entryPort = UInt16.Parse(allocated.Groups[1].Value);

                Assert.That(entryPort, Is.Not.Zero, "the allocated port must be a real one");

                var reply = await AskThroughAsync(entryPort, ssh, CancellationToken);
                Assert.That(reply, Is.EqualTo("pong:ping"), "the bytes must come back through the allocated port");

            }, CancellationToken);

        }

        #endregion

        #region RealOpenSshClient_LocalForwards_ThroughOurServer

        /// <summary>
        /// <c>ssh -L port:host:hostport</c>: the client listens and opens a <c>direct-tcpip</c> channel
        /// per connection, which our server dials under its forwarding policy.
        /// </summary>
        [Test]
        [CancelAfter(45000)]
        public async Task RealOpenSshClient_LocalForwards_ThroughOurServer(CancellationToken CancellationToken)
        {

            using var echo  = new EchoService();
            var entryPort   = FreeLoopbackPort();

            await RunAsync([ "-L", $"127.0.0.1:{entryPort}:127.0.0.1:{echo.Port}" ], async (ssh, stderr) => {

                var reply = await AskThroughAsync(entryPort, ssh, CancellationToken);
                Assert.That(reply, Is.EqualTo("pong:ping"), "the bytes must come back through -L and the echo service");

            }, CancellationToken);

        }

        #endregion

    }

}
