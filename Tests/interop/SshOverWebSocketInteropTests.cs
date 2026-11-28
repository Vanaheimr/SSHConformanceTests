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

using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// SSH over WebSocket (Hermod's <c>SSH/README.md</c>, "Over a WebSocket") with a WebSocket that is
    /// not ours: Python's <c>websockets</c>, in <c>interop/python/websocket_bridge.py</c>, written from
    /// that README alone, and OpenSSH as the SSH on its far side.
    ///
    /// <para>
    /// The hermetic <c>SshOverWebSocketTests</c> have our WebSocket at both ends, and .NET's own
    /// <c>ClientWebSocket</c> at most. Here each of our two WebSocket halves meets one of another
    /// lineage, and the SSH carried through it is OpenSSH's wherever ours is not under test:
    /// </para>
    /// <list type="bullet">
    ///   <item>a charging station that may only connect out - our <c>SshServer.ConnectOut</c> - opens the
    ///         WebSocket to their endpoint, and OpenSSH's client drives the station through it;</item>
    ///   <item>our client opens the WebSocket to their endpoint, with an <c>sshd</c> behind it;</item>
    ///   <item>OpenSSH's client opens it with theirs as its <c>ProxyCommand</c>, to our endpoint with our
    ///         server behind it;</item>
    ///   <item>their client breaks the rules of our endpoint: no subprotocol, another one, no
    ///         credentials, a text message, an offer of compression.</item>
    /// </list>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.WebSocket")]
    public class SshOverWebSocketInteropTests
    {

        #region Data

        private const String  Script     = "websocket_bridge.py";
        private const String  Alias      = "hermod-over-websocket";

        private static readonly TimeSpan Within = TimeSpan.FromSeconds(20);

        // Parses the bridge's closing line: what it carried, and the largest message it was given.
        private static readonly Regex Tally = new (@"BRIDGE ws-close code=(?<code>\S+) sent=(?<sent>\d+) received=(?<received>\d+) largest=(?<largest>\d+)");

        #endregion


        #region (private) harness

        /// <summary>
        /// Our SSH server: it runs every command by saying it back, and "repeat &lt;n&gt;" by sending n
        /// bytes that say where they are, so that a byte out of place is seen.
        /// </summary>
        private static SshServer OurSshServer(ISshHostKey HostKey, ISshHostKey UserKey)

            => new (new SshServerOptions {
                   HostKeys       = [ HostKey ],
                   Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(UserKey.PublicKeyBlob),
                   ExecHandler    = async (context, ct) => {

                                        if (context.Command.StartsWith("repeat ", StringComparison.Ordinal))
                                            await context.WriteAsync(Repeated(Int32.Parse(context.Command["repeat ".Length..])), ct);
                                        else
                                            await context.WriteAsync($"ran: {context.Command}\n", ct);

                                        return 0;

                                    }
               });

        private static Byte[] Repeated(Int32 Count)
        {

            var bytes = new Byte[Count];

            for (var i = 0; i < Count; i++)
                bytes[i] = (Byte) ('a' + i % 26);

            return bytes;

        }


        /// <summary>
        /// Our endpoint on <c>/ssh</c>, with our SSH server behind it, bound on every interface: a peer
        /// inside WSL cannot reach a loopback-only listener on the Windows host.
        ///
        /// <para>
        /// It asks for HTTP authentication, as it does unless told otherwise: who may reach SSH at all is
        /// the upgrade's to say. <see cref="Url"/> carries the station's credentials, as user information
        /// that their client turns into HTTP Basic itself; <see cref="Anonymous"/> carries none.
        /// </para>
        /// </summary>
        private sealed class OurEndpoint(HTTPServer Http, SshWebSocketEndpoint Endpoint, String Host, ConcurrentQueue<String?> Logins) : IAsyncDisposable
        {

            public String                    Url        => $"ws://{Station}:{Password}@{Host}:{Http.TCPPort}/ssh";
            public String                    Anonymous  => $"ws://{Host}:{Http.TCPPort}/ssh";
            public ConcurrentQueue<String?>  Logins     { get; } = Logins;

            public async ValueTask DisposeAsync()
            {
                await Endpoint.DisposeAsync();
                await Http.    DisposeAsync();
            }

        }

        private const String Station   = "CP001";
        private const String Password  = "the-stations-password";

        private static async Task<OurEndpoint> StartOurEndpointAsync(SshServer Ssh, CancellationToken CancellationToken)
        {

            PythonPeers.SkipIfUnavailable();

            var logins    = new ConcurrentQueue<String?>();
            var http      = await HTTPServer.StartNew(IPAddress: IPv4Address.Any);
            var endpoint  = new SshWebSocketEndpoint((connection, ct) => {
                                                          logins.Enqueue(connection.Login);
                                                          return Ssh.ServeAsync(connection.Pipe, CancellationToken: ct);
                                                      });

            endpoint.AddOrUpdateHTTPBasicAuth(Station, Password);

            http.AddHTTPAPI().AddHandler(HTTPMethod.GET,
                                         HTTPPath.Parse("/ssh"),
                                         HTTPDelegate: WebSocketUpgrade.For(endpoint));

            var host = await PythonPeers.ResolveHostAsync(CancellationToken);
            if (host is null)
            {
                await endpoint.DisposeAsync();
                await http.    DisposeAsync();
                Assert.Ignore($"WSL cannot reach the test listener on port {http.TCPPort} — check the Windows firewall for the test host process.");
            }

            return new OurEndpoint(http, endpoint, host!, logins);

        }


        /// <summary>
        /// OpenSSH runs where WSL or Linux is, and the Python peers must run there too when they meet it:
        /// as its <c>ProxyCommand</c>, or on a port it dials.
        /// </summary>
        private static void RequireOpenSshBesideThePythonPeers()
        {

            PythonPeers.SkipIfUnavailable();
            WslInterop.SkipIfUnavailable();

            if (PythonPeers.Platform != PeerPlatform.Linux)
                Assert.Ignore("OpenSSH meets the Python peers only where both run on Linux or in WSL; here the Python peers run natively on Windows.");

        }

        /// <summary>
        /// The bridge as OpenSSH's <c>ProxyCommand</c> to the given URL, in the venv's interpreter.
        /// </summary>
        private static String ProxyCommandTo(String Url)

            => $"{WslInterop.ToWslPath(WslInterop.VenvPython!)} " +
               $"{WslInterop.ToWslPath(Path.Combine(WslInterop.InteropDirectory!, "python", Script))} client {Url}";


        /// <summary>
        /// Where OpenSSH's client finds its key and the one host key it may accept: a directory of its own
        /// on the Linux side, since ssh refuses a key file others may read, and /mnt/c cannot say otherwise.
        /// </summary>
        private sealed class OpenSshClient(String Directory, String WindowsRoot) : IAsyncDisposable
        {

            /// <summary>
            /// Run ssh with the given options to the destination, and the command there.
            /// </summary>
            public Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(String             Options,
                                                                                String             Destination,
                                                                                String             Command,
                                                                                CancellationToken  CancellationToken)

                => WslInterop.RunAsync([
                       "-e", "bash", "-c",
                       $"ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={Directory}/known_hosts " +
                       $"-i {Directory}/user -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o ConnectTimeout=20 " +
                       $"{Options} {Destination} '{Command}'"
                   ], CancellationToken);

            public async ValueTask DisposeAsync()
            {
                try { System.IO.Directory.Delete(WindowsRoot, recursive: true); } catch { }
                try { await WslInterop.RunAsync(["-e", "rm", "-rf", Directory], CancellationToken.None); } catch { }
            }

        }

        private static async Task<OpenSshClient> AnOpenSshClientAsync(ISshHostKey UserKey, String KnownHostsLine, CancellationToken CancellationToken)
        {

            var identifier  = Guid.NewGuid().ToString("N");
            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_ws_" + identifier);
            Directory.CreateDirectory(windowsRoot);

            await SshKeyGenerator.WriteKeyPairAsync(UserKey, Path.Combine(windowsRoot, "user"), "ws-interop", CancellationToken);
            await File.WriteAllTextAsync(Path.Combine(windowsRoot, "known_hosts"), KnownHostsLine + "\n", CancellationToken);

            var directory = $"{await WslInterop.HomeAsync(CancellationToken)}/.hermod-interop/ws_{identifier}";
            var staging   = WslInterop.ToWslPath(windowsRoot);

            var (exitCode, _, error) = await WslInterop.RunAsync([
                                           "-e", "bash", "-c",
                                           $"mkdir -p {directory} && chmod 700 {directory} && " +
                                           $"cp {staging}/user {staging}/known_hosts {directory}/ && chmod 600 {directory}/user"
                                       ], CancellationToken);

            if (exitCode != 0)
                Assert.Fail($"Could not prepare OpenSSH's client directory: {error}");

            return new OpenSshClient(directory, windowsRoot);

        }


        /// <summary>
        /// The bridge's closing tally, once it has written it: a WebSocket closes a moment after the SSH
        /// in it is done.
        /// </summary>
        private static async Task<Match> TallyOfAsync(WslServer Bridge, CancellationToken CancellationToken)
        {

            var until = DateTimeOffset.UtcNow + Within;

            while (true)
            {

                var tally = Tally.Match(Bridge.Output);

                if (tally.Success || DateTimeOffset.UtcNow > until)
                    return tally;

                await Task.Delay(100, CancellationToken);

            }

        }

        private static String ItsOpening(String Extensions = "none")
            => $"BRIDGE ws-open subprotocol={SshOverWebSocket.Subprotocol} extensions={Extensions}";

        #endregion


        #region OurServer_ConnectsOut_ToTheirEndpoint_AndOpenSshDrivesIt

        /// <summary>
        /// The charging station's case, and the reason SSH over WebSocket exists: our SSH server opens the
        /// WebSocket - out through whatever lets HTTPS out -, their endpoint takes it, and OpenSSH's client
        /// on the back end's side runs a command on the station through it. Once OpenSSH is done, their
        /// endpoint closes the WebSocket, and the station's server has ended too.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OurServer_ConnectsOut_ToTheirEndpoint_AndOpenSshDrivesIt(CancellationToken CancellationToken)
        {

            RequireOpenSshBesideThePythonPeers();

            var hostKey  = SshHostKey.GenerateEd25519();
            var userKey  = SshHostKey.GenerateEd25519();
            var tcpPort  = WslInterop.AllocatePort();

            await using var station    = OurSshServer(hostKey, userKey);
            await using var bridge     = await PythonPeers.StartServerAsync(Script, port => [ "server", port.ToString(), "accept", tcpPort.ToString() ], CancellationToken);

            using var       webSocket  = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{bridge.Port}/ssh"));
            var             serving    = station.ConnectOut(webSocket, CancellationToken);

            await using var openSsh    = await AnOpenSshClientAsync(userKey, $"[127.0.0.1]:{tcpPort} ssh-ed25519 {Convert.ToBase64String(hostKey.PublicKeyBlob)}", CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync($"-p {tcpPort}", "operator@127.0.0.1", "hostname", CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode, Is.EqualTo(0),                 $"OpenSSH ran the command on our station through their endpoint.\n{stdErr}\n{bridge.Output}");
                Assert.That(stdOut,   Is.EqualTo("ran: hostname\n"), stdErr);
            });

            Assert.That(await Task.WhenAny(serving, Task.Delay(Within, CancellationToken)), Is.SameAs(serving),
                        $"the station's server ended with the WebSocket their endpoint closed.\n{bridge.Output}");

            await serving;

            // Our client offered the subprotocol and asked for no compression, which their endpoint would have given.
            Assert.That(bridge.Output, Does.Contain(ItsOpening()), bridge.Output);

        }

        #endregion

        #region OurClient_ThroughTheirEndpoint_RunsACommandOnOpenSsh

        /// <summary>
        /// Our client opens the WebSocket to their endpoint, and an <c>sshd</c> is behind it: a megabyte
        /// comes back through, whole, in messages their endpoint cut where its reads ended - which means
        /// nothing, as the README says.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OurClient_ThroughTheirEndpoint_RunsACommandOnOpenSsh(CancellationToken CancellationToken)
        {

            RequireOpenSshBesideThePythonPeers();

            var daemon = await OpenSshServerInteropTests.StartSshdAsync(CancellationToken);

            try
            {

                await using var bridge     = await PythonPeers.StartServerAsync(Script, port => [ "server", port.ToString(), "forward", "127.0.0.1", daemon.Port.ToString() ], CancellationToken);
                using var       webSocket  = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{bridge.Port}/ssh"));

                await using (var client = await SSHClient.Connect(webSocket, new SSHClientOptions {
                                                                       Username       = User_Id.Parse(await OpenSshServerInteropTests.WhoAsync(CancellationToken)),
                                                                       VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(daemon.HostKeyBlob),
                                                                       Credentials    = [ daemon.UserKey ]
                                                                   }, CancellationToken))
                {

                    var result = await client.Execute("head -c 1000000 /dev/zero | tr '\\0' x", CancellationToken);

                    Assert.Multiple(() => {
                        Assert.That(result.ExitCode,               Is.EqualTo(0),                      $"{result.StandardError}\n{bridge.Output}");
                        Assert.That(result.StandardOutput.Length,  Is.EqualTo(1_000_000),              bridge.Output);
                        Assert.That(result.StandardOutput,         Is.EqualTo(new String('x', 1_000_000)));
                        Assert.That(client.ServerHostKey,          Is.EqualTo(daemon.HostKeyBlob),     "it was sshd's host key that came through");
                    });

                }

                var tally = await TallyOfAsync(bridge, CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(bridge.Output,  Does.Contain(ItsOpening()),  "our client offered the subprotocol, and no compression");
                    Assert.That(tally.Success,  Is.True,                     $"their endpoint closed the WebSocket once our client was done.\n{bridge.Output}");
                });

                Assert.That(Int32.Parse(tally.Groups["largest"].Value), Is.LessThanOrEqualTo(SshOverWebSocket.DefaultMessageSize),
                            "our client sends at most 32 KiB a message");

            }
            finally
            {
                await OpenSshServerInteropTests.StopAsync(daemon);
            }

        }

        #endregion

        #region OpenSsh_ThroughTheirClient_RunsACommandOnOurServer

        /// <summary>
        /// OpenSSH's client, with their WebSocket client as its <c>ProxyCommand</c>, reaches our server
        /// through our endpoint: a megabyte comes out whole, in messages of at most 32 KiB, and of the
        /// compression their client offered our endpoint took none.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OpenSsh_ThroughTheirClient_RunsACommandOnOurServer(CancellationToken CancellationToken)
        {

            RequireOpenSshBesideThePythonPeers();

            var hostKey  = SshHostKey.GenerateEd25519();
            var userKey  = SshHostKey.GenerateEd25519();

            await using var server    = OurSshServer(hostKey, userKey);
            await using var endpoint  = await StartOurEndpointAsync(server, CancellationToken);
            await using var openSsh   = await AnOpenSshClientAsync(userKey, $"{Alias} ssh-ed25519 {Convert.ToBase64String(hostKey.PublicKeyBlob)}", CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync($"-o HostKeyAlias={Alias} -o ProxyCommand='{ProxyCommandTo(endpoint.Url)}'",
                                                                    $"operator@{Alias}",
                                                                    "repeat 1000000",
                                                                    CancellationToken);

            var tally = Tally.Match(stdErr);

            Assert.Multiple(() => {
                Assert.That(exitCode,         Is.EqualTo(0),                                      stdErr);
                Assert.That(stdOut.Length,    Is.EqualTo(1_000_000),                              stdErr);
                Assert.That(stdOut,           Is.EqualTo(Encoding.ASCII.GetString(Repeated(1_000_000))));
                Assert.That(stdErr,           Does.Contain(ItsOpening()),                         "our endpoint chose the subprotocol, and no compression");
                Assert.That(tally.Success,    Is.True,                                            stdErr);
                Assert.That(endpoint.Logins,  Is.EqualTo(new[] { Station }),                      "the HTTP Basic their client sent is who the endpoint says connected");
            });

            Assert.Multiple(() => {
                Assert.That(Int32.Parse(tally.Groups["largest"] .Value), Is.LessThanOrEqualTo(SshOverWebSocket.DefaultMessageSize), "our endpoint sends at most 32 KiB a message");
                Assert.That(Int32.Parse(tally.Groups["received"].Value), Is.GreaterThan(1_000_000 / SshOverWebSocket.DefaultMessageSize), "a megabyte, so many messages");
            });

        }

        #endregion


        #region TheirClient_WithoutOurSubprotocol_IsAnswered400

        /// <summary>
        /// A client that offers no subprotocol, or only another one - OCPP's, say -, is answered 400
        /// before anything is upgraded.
        /// </summary>
        [TestCase("none")]
        [TestCase("other")]
        [CancelAfter(60000)]
        public async Task TheirClient_WithoutOurSubprotocol_IsAnswered400(String Case, CancellationToken CancellationToken)
        {

            var hostKey  = SshHostKey.GenerateEd25519();

            await using var server    = OurSshServer(hostKey, SshHostKey.GenerateEd25519());
            await using var endpoint  = await StartOurEndpointAsync(server, CancellationToken);

            var result = await PythonPeers.RunDriverAsync(Script, new Dictionary<String, Object?> { ["case"] = Case, ["url"] = endpoint.Url }, CancellationToken);

            Assert.That(result.Ok, Is.True, result.FailureReport);
            Assert.That(result.Extra!["status"].GetInt32(), Is.EqualTo(400));

        }

        #endregion

        #region TheirClient_WithoutCredentials_IsAnswered401

        /// <summary>
        /// A client that offers the subprotocol but no credentials is answered 401, and SSH behind the
        /// endpoint never hears of it.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task TheirClient_WithoutCredentials_IsAnswered401(CancellationToken CancellationToken)
        {

            await using var server    = OurSshServer(SshHostKey.GenerateEd25519(), SshHostKey.GenerateEd25519());
            await using var endpoint  = await StartOurEndpointAsync(server, CancellationToken);

            var result = await PythonPeers.RunDriverAsync(Script, new Dictionary<String, Object?> { ["case"] = "anonymous", ["url"] = endpoint.Anonymous }, CancellationToken);

            Assert.That(result.Ok, Is.True, result.FailureReport);

            Assert.Multiple(() => {
                Assert.That(result.Extra!["status"].GetInt32(),  Is.EqualTo(401));
                Assert.That(endpoint.Logins,                     Is.Empty,  "no connection was handed on");
            });

        }

        #endregion

        #region TheirClient_SendingText_IsClosedWith1003

        /// <summary>
        /// SSH goes in binary messages alone. Their client is upgraded, sees our server's identification
        /// arrive as a binary message, sends one as text, and is closed with 1003 (unsupported data).
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task TheirClient_SendingText_IsClosedWith1003(CancellationToken CancellationToken)
        {

            await using var server    = OurSshServer(SshHostKey.GenerateEd25519(), SshHostKey.GenerateEd25519());
            await using var endpoint  = await StartOurEndpointAsync(server, CancellationToken);

            var result = await PythonPeers.RunDriverAsync(Script, new Dictionary<String, Object?> { ["case"] = "text", ["url"] = endpoint.Url }, CancellationToken);

            Assert.That(result.Ok, Is.True, result.FailureReport);

            var messages = result.Extra!["messages"].EnumerateArray().ToArray();

            Assert.Multiple(() => {
                Assert.That(result.Extra["status"].     GetInt32(),   Is.EqualTo(101));
                Assert.That(result.Extra["subprotocol"].GetString(),  Is.EqualTo(SshOverWebSocket.Subprotocol));
                Assert.That(result.Extra["close_code"]. GetInt32(),   Is.EqualTo(1003));
                Assert.That(messages,                                 Is.Not.Empty,  "our server spoke first");
            });

            Assert.Multiple(() => {
                Assert.That(messages[0].GetProperty("binary").GetBoolean(),  Is.True);
                Assert.That(messages[0].GetProperty("text").  GetString(),   Does.StartWith("SSH-2.0-"));
            });

        }

        #endregion

        #region TheirClient_OfferingCompression_IsNotCompressed

        /// <summary>
        /// Their client offers permessage-deflate, as most clients do; our endpoint takes the
        /// subprotocol and leaves the offer: SSH's packets are encrypted, and compressing them only
        /// costs.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task TheirClient_OfferingCompression_IsNotCompressed(CancellationToken CancellationToken)
        {

            await using var server    = OurSshServer(SshHostKey.GenerateEd25519(), SshHostKey.GenerateEd25519());
            await using var endpoint  = await StartOurEndpointAsync(server, CancellationToken);

            var result = await PythonPeers.RunDriverAsync(Script, new Dictionary<String, Object?> { ["case"] = "deflate", ["url"] = endpoint.Url }, CancellationToken);

            Assert.That(result.Ok, Is.True, result.FailureReport);

            Assert.Multiple(() => {
                Assert.That(result.Extra!["status"].    GetInt32(),   Is.EqualTo(101));
                Assert.That(result.Extra["subprotocol"].GetString(),  Is.EqualTo(SshOverWebSocket.Subprotocol));
                Assert.That(result.Extra["extensions"]. ValueKind,    Is.EqualTo(System.Text.Json.JsonValueKind.Null), "no Sec-WebSocket-Extensions in our answer");
                Assert.That(result.Extra["messages"][0].GetProperty("text").GetString(), Does.StartWith("SSH-2.0-"));
            });

        }

        #endregion

    }

}
