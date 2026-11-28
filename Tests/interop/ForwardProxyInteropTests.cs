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
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

using Newtonsoft.Json.Linq;

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
    /// SSH over WebSocket through a forward proxy that is not ours: what a charging station behind a
    /// corporate network does before anything else, asking the proxy with <c>CONNECT</c> (RFC 9110,
    /// Section 9.3.6) for a tunnel to the back end (Hermod's <c>HTTP1/WebSocket/README.md</c>, "Through
    /// a forward proxy").
    ///
    /// <para>
    /// The hermetic <c>ForwardProxyTests</c> have Hermod's own test proxy in between. Here it is a real
    /// one, started by <c>interop/forward-proxy.sh</c>, and the WebSocket on its far side is not ours
    /// either: Python's <c>websockets</c> in <c>interop/python/websocket_bridge.py</c>, with OpenSSH
    /// behind it or in front of it. Ours is the WebSocket client that goes through the proxy - as an
    /// SSH client, and as the station's SSH server that may only connect out.
    /// </para>
    ///
    /// <para>
    /// Everything but our client runs where WSL or Linux is: the proxy dials the endpoint on its own
    /// loopback, and our client reaches the proxy through WSL's localhost forwarding. Each check asks
    /// the proxy's own log what it was asked for: a tunnel to the endpoint's host and port, and never
    /// the path of the upgrade, which goes inside the tunnel.
    /// </para>
    /// </summary>
    public abstract class AForwardProxyInteropTests
    {

        #region Data

        protected const String  Script    = "websocket_bridge.py";
        protected const String  User      = "CP001";
        protected const String  Password  = "the-stations-proxy-password";

        protected static readonly TimeSpan Within = TimeSpan.FromSeconds(20);

        #endregion

        #region Properties

        /// <summary>
        /// The proxy, as forward-proxy.sh names it.
        /// </summary>
        protected abstract String          Kind                          { get; }

        /// <summary>
        /// The realm of the Basic challenge the proxy sends with its 407.
        /// </summary>
        protected abstract String          Realm                         { get; }

        /// <summary>
        /// What the proxy answers a CONNECT with credentials it does not take.
        /// </summary>
        protected abstract HTTPStatusCode  WrongCredentialsAnsweredWith  { get; }

        /// <summary>
        /// The line of the proxy's log that says it opened a tunnel to the target, for the given user.
        /// </summary>
        protected abstract Regex           ATunnelTo(String Target, String? User);

        #endregion


        #region (protected) harness

        /// <summary>
        /// A proxy that forward-proxy.sh started, and where it is.
        /// </summary>
        protected sealed class RealProxy(WslServer Server, String Directory, String Scheme) : IAsyncDisposable
        {

            public URL     URL     => URL.Parse($"{Scheme}://127.0.0.1:{Server.Port}");
            public String  Output  => Server.Output;

            public async ValueTask DisposeAsync()
            {
                await Server.DisposeAsync();
                try { await WslInterop.RunAsync(["-e", "rm", "-rf", Directory], CancellationToken.None); } catch { }
            }

        }

        /// <summary>
        /// Start the proxy, opening tunnels to the one port given: with HTTP Basic or none, and over TLS
        /// with the certificate given or without.
        /// </summary>
        protected async Task<RealProxy> StartProxyAsync(Int32                                  AllowedPort,
                                                        Boolean                                Basic,
                                                        (String Certificate, String Key)?      TLS,
                                                        CancellationToken                      CancellationToken)
        {

            // Under /tmp rather than the home directory: Squid started as root runs as "proxy", and so
            // does the helper that reads its password file.
            var directory  = $"/tmp/hermod-interop-proxy-{Guid.NewGuid():N}";
            var script     = WslInterop.ToWslPath(Path.Combine(WslInterop.InteropDirectory!, "forward-proxy.sh"));

            var server     = await WslInterop.StartServerAsync(port => $"bash '{script}' {Kind} {port} {directory} {AllowedPort}" +
                                                                       (Basic                 ? $" basic {User} {Password}" : "") +
                                                                       (TLS is { } tls        ? $" tls '{tls.Certificate}' '{tls.Key}'" : ""),
                                                               CancellationToken);

            return new RealProxy(server, directory, TLS is null ? "http" : "https");

        }

        protected async Task RequireTheProxyAsync(CancellationToken CancellationToken)
        {

            PythonPeers.SkipIfUnavailable();
            WslInterop.SkipIfUnavailable();

            // The proxy dials the endpoint on its own loopback, so the endpoint runs beside it.
            if (PythonPeers.Platform != PeerPlatform.Linux)
                Assert.Ignore($"{Kind} meets the Python peers only where both run on Linux or in WSL; here the Python peers run natively on Windows.");

            var (exitCode, _, _) = await WslInterop.RunAsync(["-e", "sh", "-c", $"command -v {Kind}"], CancellationToken);

            if (exitCode != 0)
                Assert.Ignore($"{Kind} is not installed - run interop/setup-wsl.sh.");

        }


        /// <summary>
        /// Their endpoint on <c>/ssh</c>, carrying every WebSocket on to the sshd given, as "ws" or with
        /// the certificate given as "wss".
        /// </summary>
        protected static Task<WslServer> StartTheirEndpointAsync(Int32                              SshdPort,
                                                                 (String Certificate, String Key)?  TLS,
                                                                 CancellationToken                  CancellationToken,
                                                                 (String User, String Password)?    Basic   = null)

            => PythonPeers.StartServerAsync(Script,
                                            port => [ "server", port.ToString(), "forward", "127.0.0.1", SshdPort.ToString(),
                                                      .. TLS   is { } tls   ? new[] { "tls",   tls.Certificate, tls.Key }        : [],
                                                      .. Basic is { } basic ? new[] { "basic", basic.User,      basic.Password } : [] ],
                                            CancellationToken);


        /// <summary>
        /// A self-signed certificate for 127.0.0.1, in PEM files of a directory of its own: the key the
        /// client pins, and the files the peer reads.
        /// </summary>
        protected sealed class PemCertificate(String Directory, ECDsa Key) : IDisposable
        {

            public ECDsa   Key          { get; } = Key;
            public String  Certificate  => Path.Combine(Directory, "certificate.pem");
            public String  PrivateKey   => Path.Combine(Directory, "key.pem");

            public (String Certificate, String Key) ForThePeer
                => (WslInterop.ToWslPath(Certificate), WslInterop.ToWslPath(PrivateKey));

            public KeyPinPolicy Pinned
                => KeyPinPolicy.PinnedTo(KeyPin.FromKey(Key));

            public void Dispose()
            {
                Key.Dispose();
                try { System.IO.Directory.Delete(Directory, recursive: true); } catch { }
            }

        }

        protected static async Task<PemCertificate> APemCertificateAsync(CancellationToken CancellationToken)
        {

            var directory  = Path.Combine(Path.GetTempPath(), "hermod_proxy_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            var key        = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request    = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256);
            var names      = new SubjectAlternativeNameBuilder();
            names.AddIpAddress(System.Net.IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());

            var now        = TimeProvider.System.GetUtcNow();
            using var certificate = request.CreateSelfSigned(now.AddHours(-1), now.AddDays(1));

            var pem        = new PemCertificate(directory, key);

            await File.WriteAllTextAsync(pem.Certificate, certificate.ExportCertificatePem(), CancellationToken);
            await File.WriteAllTextAsync(pem.PrivateKey,  key.ExportPkcs8PrivateKeyPem(),     CancellationToken);

            return pem;

        }


        protected static HTTPBasicAuthentication TheStationsCredentials
            => HTTPBasicAuthentication.Create(User, Password);

        private protected static async Task<SSHClientOptions> ToTheSshdAsync(OpenSshServerInteropTests.Daemon Daemon, CancellationToken CancellationToken)

            => new () {
                   Username       = User_Id.Parse(await OpenSshServerInteropTests.WhoAsync(CancellationToken)),
                   VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(Daemon.HostKeyBlob),
                   Credentials    = [ Daemon.UserKey ]
               };


        /// <summary>
        /// The proxy's output once the given line is in it: Squid writes its access log line as a tunnel
        /// ends, a moment after the SSH in it is done.
        /// </summary>
        protected static async Task<String> OutputOnceAsync(RealProxy Proxy, Regex Line, CancellationToken CancellationToken)
        {

            var until = DateTimeOffset.UtcNow + Within;

            while (!Line.IsMatch(Proxy.Output) && DateTimeOffset.UtcNow < until)
                await Task.Delay(100, CancellationToken);

            return Proxy.Output;

        }

        /// <summary>
        /// What the proxy saw of the WebSocket: its host and port, and nothing of the upgrade - neither
        /// the path nor the subprotocol, both of which went inside the tunnel.
        /// </summary>
        protected static void SawNothingButTheTunnel(String ProxyOutput)
        {
            Assert.Multiple(() => {
                Assert.That(ProxyOutput, Does.Not.Contain("/ssh"),                    "the upgrade's path went inside the tunnel");
                Assert.That(ProxyOutput, Does.Not.Contain(SshOverWebSocket.Subprotocol), "so did its subprotocol");
            });
        }

        #endregion


        #region OurClient_ThroughTheProxy_RunsACommandOnOpenSsh

        /// <summary>
        /// Our client asks the proxy for a tunnel, telling it who is connecting in Proxy-Authorization,
        /// and opens the WebSocket to their endpoint inside it, with an sshd behind it: a megabyte comes
        /// back whole. The proxy's log has the tunnel, under the station's name, and nothing else.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OurClient_ThroughTheProxy_RunsACommandOnOpenSsh(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            var daemon = await OpenSshServerInteropTests.StartSshdAsync(CancellationToken);

            try
            {

                await using var endpoint   = await StartTheirEndpointAsync(daemon.Port, null, CancellationToken);
                await using var proxy      = await StartProxyAsync(endpoint.Port, Basic: true, TLS: null, CancellationToken);

                using var       webSocket  = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                                    Proxy: new HTTPProxy(proxy.URL) { Authentication = TheStationsCredentials });

                await using (var client = await SSHClient.Connect(webSocket, await ToTheSshdAsync(daemon, CancellationToken), CancellationToken))
                {

                    var result = await client.Execute("head -c 1000000 /dev/zero | tr '\\0' x", CancellationToken);

                    Assert.Multiple(() => {
                        Assert.That(result.ExitCode,               Is.EqualTo(0),                    $"{result.StandardError}\n{proxy.Output}\n{endpoint.Output}");
                        Assert.That(result.StandardOutput,         Is.EqualTo(new String('x', 1_000_000)));
                        Assert.That(client.ServerHostKey,          Is.EqualTo(daemon.HostKeyBlob),   "it was sshd's host key that came through");
                    });

                }

                var tunnel  = ATunnelTo($"127.0.0.1:{endpoint.Port}", User);
                var output  = await OutputOnceAsync(proxy, tunnel, CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(tunnel.Matches(output),  Has.Count.EqualTo(1),  $"one tunnel, to their endpoint, for the station.\n{output}");
                    Assert.That(endpoint.Output,         Does.Contain($"BRIDGE ws-open subprotocol={SshOverWebSocket.Subprotocol} extensions=none"), endpoint.Output);
                });

                SawNothingButTheTunnel(output);

            }
            finally
            {
                await OpenSshServerInteropTests.StopAsync(daemon);
            }

        }

        #endregion

        #region OurStation_ConnectsOutThroughTheProxy_AndOpenSshDrivesIt

        /// <summary>
        /// The charging station's case: our SSH server may only connect out, and only through the proxy.
        /// It opens the WebSocket to their endpoint through a tunnel, and OpenSSH's client on the back
        /// end's side runs a command on the station through it.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task OurStation_ConnectsOutThroughTheProxy_AndOpenSshDrivesIt(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            var hostKey  = SshHostKey.GenerateEd25519();
            var userKey  = SshHostKey.GenerateEd25519();
            var tcpPort  = WslInterop.AllocatePort();

            await using var station    = new SshServer(new SshServerOptions {
                                                           HostKeys       = [ hostKey ],
                                                           Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                                                           ExecHandler    = async (context, ct) => {
                                                                                await context.WriteAsync($"ran: {context.Command}\n", ct);
                                                                                return 0;
                                                                            }
                                                       });

            await using var endpoint   = await PythonPeers.StartServerAsync(Script, port => [ "server", port.ToString(), "accept", tcpPort.ToString() ], CancellationToken);
            await using var proxy      = await StartProxyAsync(endpoint.Port, Basic: true, TLS: null, CancellationToken);

            using var       webSocket  = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                                Proxy: new HTTPProxy(proxy.URL) { Authentication = TheStationsCredentials });

            var             serving    = station.ConnectOut(webSocket, CancellationToken);

            await using var openSsh    = await OpenSshThroughTheBackEnd.PrepareAsync(userKey, $"[127.0.0.1]:{tcpPort} ssh-ed25519 {Convert.ToBase64String(hostKey.PublicKeyBlob)}", CancellationToken);

            var (exitCode, stdOut, stdErr) = await openSsh.RunAsync(tcpPort, "hostname", CancellationToken);

            Assert.Multiple(() => {
                Assert.That(exitCode,  Is.EqualTo(0),                  $"OpenSSH ran the command on our station through the tunnel.\n{stdErr}\n{proxy.Output}\n{endpoint.Output}");
                Assert.That(stdOut,    Is.EqualTo("ran: hostname\n"),  stdErr);
            });

            Assert.That(await Task.WhenAny(serving, Task.Delay(Within, CancellationToken)), Is.SameAs(serving),
                        $"the station's server ended with the WebSocket their endpoint closed.\n{endpoint.Output}");

            await serving;

            var tunnel  = ATunnelTo($"127.0.0.1:{endpoint.Port}", User);
            var output  = await OutputOnceAsync(proxy, tunnel, CancellationToken);

            Assert.That(tunnel.Matches(output), Has.Count.EqualTo(1), $"the station's tunnel, under its name.\n{output}");

            SawNothingButTheTunnel(output);

        }

        #endregion


        #region WithoutCredentials_TheProxyAsksForThem_AndTheEndpointIsNeverReached

        /// <summary>
        /// Told nothing about who is connecting, the proxy answers 407 with its Basic challenge, which
        /// comes back to the caller as the proxy sent it. Our client goes no further: their endpoint
        /// never sees a WebSocket.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task WithoutCredentials_TheProxyAsksForThem_AndTheEndpointIsNeverReached(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            await using var endpoint  = await StartTheirEndpointAsync(1, null, CancellationToken);
            await using var proxy     = await StartProxyAsync(endpoint.Port, Basic: true, TLS: null, CancellationToken);

            await using var client    = new WebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                            SecWebSocketProtocols: [ SshOverWebSocket.Subprotocol ]) {
                                            Proxy            = new HTTPProxy(proxy.URL),
                                            ReconnectPolicy  = null
                                        };

            var (connection, response) = await client.Connect(CancellationToken: CancellationToken);

            var challenges = response.HTTPBodyAsJSONObject?["proxyAuthenticate"]?.Values<String>().ToArray() ?? [];

            Assert.Multiple(() => {
                Assert.That(connection,               Is.Null);
                Assert.That(response.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.ProxyAuthenticationRequired),  response.HTTPBodyAsUTF8String);
                Assert.That(challenges,               Has.Some.EqualTo($"Basic realm=\"{Realm}\""),            response.HTTPBodyAsUTF8String);
            });

            // SSH over WebSocket says the same, and says it was the proxy.
            using var webSocket = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                         Proxy: new HTTPProxy(proxy.URL));

            var refusal = await Assert.ThrowsAsync<SshWebSocketException>(async () => await webSocket.OpenAsync(CancellationToken));

            Assert.Multiple(() => {
                Assert.That(refusal.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.ProxyAuthenticationRequired),  refusal.Message);
                Assert.That(refusal.FromProxy,       Is.True,                                                 refusal.Message);
                Assert.That((refusal.InnerException as HTTPProxyException)?.ProxyAuthenticate,
                                                     Has.Some.EqualTo($"Basic realm=\"{Realm}\""),            refusal.Message);
                Assert.That(endpoint.Output,         Does.Not.Contain("BRIDGE ws-open"),                     "no WebSocket reached their endpoint");
            });

        }

        #endregion

        #region WithWrongCredentials_IsRefused_AndTheEndpointIsNeverReached

        /// <summary>
        /// Credentials the proxy does not take are refused, with what the proxy answers them with - and
        /// the station's SSH server, which connects out, says so rather than waiting.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task WithWrongCredentials_IsRefused_AndTheEndpointIsNeverReached(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            await using var endpoint   = await StartTheirEndpointAsync(1, null, CancellationToken);
            await using var proxy      = await StartProxyAsync(endpoint.Port, Basic: true, TLS: null, CancellationToken);

            using var       webSocket  = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                                Proxy: new HTTPProxy(proxy.URL) { Authentication = HTTPBasicAuthentication.Create(User, "not-the-password") });

            var refusal = await Assert.ThrowsAsync<SshWebSocketException>(async () => await webSocket.OpenAsync(CancellationToken));

            Assert.Multiple(() => {
                Assert.That(refusal.HTTPStatusCode,  Is.EqualTo(WrongCredentialsAnsweredWith),  refusal.Message);
                Assert.That(refusal.FromProxy,       Is.True,                                   "it was the proxy that refused, whatever its status");
                Assert.That(refusal.InnerException,  Is.InstanceOf<HTTPProxyException>(),       refusal.Message);
                Assert.That(endpoint.Output,         Does.Not.Contain("BRIDGE ws-open"),        "no WebSocket reached their endpoint");
            });

        }

        #endregion

        #region ToAPortTheProxyDoesNotOpen_IsRefusedWith403

        /// <summary>
        /// A proxy opens tunnels to the ports it was told to - a corporate one to 443 alone. A CONNECT to
        /// any other is refused with 403, which comes back to the caller.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task ToAPortTheProxyDoesNotOpen_IsRefusedWith403(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            await using var endpoint   = await StartTheirEndpointAsync(1, null, CancellationToken);
            await using var proxy      = await StartProxyAsync(endpoint.Port == 443 ? 444 : 443, Basic: true, TLS: null, CancellationToken);

            using var       webSocket  = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                                Proxy: new HTTPProxy(proxy.URL) { Authentication = TheStationsCredentials });

            var refusal = await Assert.ThrowsAsync<SshWebSocketException>(async () => await webSocket.OpenAsync(CancellationToken));

            Assert.Multiple(() => {
                Assert.That(refusal.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Forbidden),  refusal.Message);
                Assert.That(refusal.FromProxy,       Is.True,                               "a 403 of the proxy, not of the server");
                Assert.That(refusal.InnerException,  Is.InstanceOf<HTTPProxyException>(),   refusal.Message);
                Assert.That(endpoint.Output,         Does.Not.Contain("BRIDGE ws-open"),    "no WebSocket reached their endpoint");
            });

        }

        #endregion

        #region TheEndpointsOwnRefusal_ThroughTheTunnel_IsNotTheProxys

        /// <summary>
        /// The other side of FromProxy: the proxy opens the tunnel, and it is their endpoint, behind
        /// HTTP Basic, that answers 401 - the status tinyproxy gives wrong proxy credentials, but here the
        /// server's, and said so. With the endpoint's credentials, the same tunnel takes the upgrade.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task TheEndpointsOwnRefusal_ThroughTheTunnel_IsNotTheProxys(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            await using var endpoint   = await StartTheirEndpointAsync(1, null, CancellationToken, Basic: ("operator", "the-endpoints-password"));
            await using var proxy      = await StartProxyAsync(endpoint.Port, Basic: true, TLS: null, CancellationToken);

            using var       refused    = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                                HTTPAuthentication:  HTTPBasicAuthentication.Create("operator", "not-the-password"),
                                                                Proxy:               new HTTPProxy(proxy.URL) { Authentication = TheStationsCredentials });

            var refusal = await Assert.ThrowsAsync<SshWebSocketException>(async () => await refused.OpenAsync(CancellationToken));

            Assert.Multiple(() => {
                Assert.That(refusal.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.Unauthorized),           refusal.Message);
                Assert.That(refusal.FromProxy,       Is.False,                                          "the proxy opened the tunnel; the server refused");
                Assert.That(refusal.InnerException,  Is.Null,                                           refusal.Message);
                Assert.That(endpoint.Output,         Does.Contain("BRIDGE refused authorization=wrong"), endpoint.Output);
                Assert.That(endpoint.Output,         Does.Not.Contain("BRIDGE ws-open"),                endpoint.Output);
            });

            using var       admitted   = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                                HTTPAuthentication:  HTTPBasicAuthentication.Create("operator", "the-endpoints-password"),
                                                                Proxy:               new HTTPProxy(proxy.URL) { Authentication = TheStationsCredentials });

            // The upgrade is taken - OpenAsync returns -, and nothing more is asked of it: behind this
            // endpoint is no sshd, so it closes the WebSocket again before it would log one.
            Assert.That(async () => await admitted.OpenAsync(CancellationToken), Throws.Nothing,
                        $"the same tunnel takes the upgrade with the endpoint's credentials.\n{endpoint.Output}");

            Assert.That(Regex.Matches(endpoint.Output, "BRIDGE refused"), Has.Count.EqualTo(1),
                        $"the endpoint refused the first client alone.\n{endpoint.Output}");

        }

        #endregion

        #region TheTLSToTheEndpoint_RunsInsideTheTunnel

        /// <summary>
        /// Their endpoint is "wss": the TLS to it is our client's and theirs, end to end inside the
        /// tunnel, checked against the key our client pinned. The proxy carries bytes it cannot read -
        /// nor does its log say anything but the host and port.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task TheTLSToTheEndpoint_RunsInsideTheTunnel(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            using var certificate  = await APemCertificateAsync(CancellationToken);
            var       daemon       = await OpenSshServerInteropTests.StartSshdAsync(CancellationToken);

            try
            {

                await using var endpoint   = await StartTheirEndpointAsync(daemon.Port, certificate.ForThePeer, CancellationToken);
                await using var proxy      = await StartProxyAsync(endpoint.Port, Basic: true, TLS: null, CancellationToken);

                using var       webSocket  = new SshWebSocketClient(URL.Parse($"wss://127.0.0.1:{endpoint.Port}/ssh"),
                                                                    RemoteCertificateValidator:  KeyPinValidator.ForServerCertificates<IWebSocketClient>(certificate.Pinned),
                                                                    Proxy:                       new HTTPProxy(proxy.URL) { Authentication = TheStationsCredentials });

                await using (var client = await SSHClient.Connect(webSocket, await ToTheSshdAsync(daemon, CancellationToken), CancellationToken))
                {

                    var result = await client.Execute("echo through-tls-in-the-tunnel", CancellationToken);

                    Assert.Multiple(() => {
                        Assert.That(result.ExitCode,        Is.EqualTo(0),                                  $"{result.StandardError}\n{proxy.Output}\n{endpoint.Output}");
                        Assert.That(result.StandardOutput,  Is.EqualTo("through-tls-in-the-tunnel\n"));
                        Assert.That(webSocket.TLSSession,   Is.Not.Null,                                    "the TLS was to their endpoint");
                    });

                }

                var tunnel  = ATunnelTo($"127.0.0.1:{endpoint.Port}", User);
                var output  = await OutputOnceAsync(proxy, tunnel, CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(tunnel.Matches(output),  Has.Count.EqualTo(1),         output);
                    Assert.That(endpoint.Output,         Does.Contain(" tls=TLSv1."),  $"their endpoint spoke TLS with our client.\n{endpoint.Output}");
                });

                SawNothingButTheTunnel(output);

            }
            finally
            {
                await OpenSshServerInteropTests.StopAsync(daemon);
            }

        }

        #endregion


        #region (protected) OpenSshThroughTheBackEnd

        /// <summary>
        /// OpenSSH's client on the back end's side, with its key and the one host key it may accept in a
        /// directory of its own on the Linux side: ssh refuses a key file others may read, and /mnt/c
        /// cannot say otherwise.
        /// </summary>
        protected sealed class OpenSshThroughTheBackEnd(String Directory, String WindowsRoot) : IAsyncDisposable
        {

            public Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(Int32              Port,
                                                                                String             Command,
                                                                                CancellationToken  CancellationToken)

                => WslInterop.RunAsync([
                       "-e", "bash", "-c",
                       $"ssh -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile={Directory}/known_hosts " +
                       $"-i {Directory}/user -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o ConnectTimeout=20 " +
                       $"-p {Port} operator@127.0.0.1 '{Command}'"
                   ], CancellationToken);

            public static async Task<OpenSshThroughTheBackEnd> PrepareAsync(ISshHostKey UserKey, String KnownHostsLine, CancellationToken CancellationToken)
            {

                var identifier  = Guid.NewGuid().ToString("N");
                var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_proxy_ssh_" + identifier);
                System.IO.Directory.CreateDirectory(windowsRoot);

                await SshKeyGenerator.WriteKeyPairAsync(UserKey, Path.Combine(windowsRoot, "user"), "proxy-interop", CancellationToken);
                await File.WriteAllTextAsync(Path.Combine(windowsRoot, "known_hosts"), KnownHostsLine + "\n", CancellationToken);

                var directory = $"{await WslInterop.HomeAsync(CancellationToken)}/.hermod-interop/proxy_ssh_{identifier}";
                var staging   = WslInterop.ToWslPath(windowsRoot);

                var (exitCode, _, error) = await WslInterop.RunAsync([
                                               "-e", "bash", "-c",
                                               $"mkdir -p {directory} && chmod 700 {directory} && " +
                                               $"cp {staging}/user {staging}/known_hosts {directory}/ && chmod 600 {directory}/user"
                                           ], CancellationToken);

                if (exitCode != 0)
                    Assert.Fail($"Could not prepare OpenSSH's client directory: {error}");

                return new OpenSshThroughTheBackEnd(directory, windowsRoot);

            }

            public async ValueTask DisposeAsync()
            {
                try { System.IO.Directory.Delete(WindowsRoot, recursive: true); } catch { }
                try { await WslInterop.RunAsync(["-e", "rm", "-rf", Directory], CancellationToken.None); } catch { }
            }

        }

        #endregion

    }


    /// <summary>
    /// Through Squid, the proxy of most corporate networks - and the one of them that also speaks TLS to
    /// its clients, an "https" proxy.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.WebSocket")]
    public class SquidForwardProxyInteropTests : AForwardProxyInteropTests
    {

        protected override String          Kind                          => "squid";
        protected override String          Realm                         => "hermod-interop";
        protected override HTTPStatusCode  WrongCredentialsAnsweredWith  => HTTPStatusCode.ProxyAuthenticationRequired;

        // Its access log: "<time> <ms> <client> TCP_TUNNEL/200 <bytes> CONNECT <host:port> <user> HIER_DIRECT/<address> -",
        // written as the tunnel ends.
        protected override Regex ATunnelTo(String Target, String? User)
            => new ($@"TCP_TUNNEL/200 \d+ CONNECT {Regex.Escape(Target)} {Regex.Escape(User ?? "-")} ");


        #region ThroughAnHttpsProxy_TLSInTLS

        /// <summary>
        /// An "https" proxy: our client speaks TLS 1.3 to Squid, checked against the key it pinned, and
        /// the TLS to their "wss" endpoint inside that - TLS in TLS, of which Squid reads the outer one.
        /// </summary>
        [Test]
        [CancelAfter(90000)]
        public async Task ThroughAnHttpsProxy_TLSInTLS(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            using var proxyCertificate     = await APemCertificateAsync(CancellationToken);
            using var endpointCertificate  = await APemCertificateAsync(CancellationToken);

            var daemon = await OpenSshServerInteropTests.StartSshdAsync(CancellationToken);

            try
            {

                await using var endpoint   = await StartTheirEndpointAsync(daemon.Port, endpointCertificate.ForThePeer, CancellationToken);
                await using var proxy      = await StartProxyAsync(endpoint.Port, Basic: true, TLS: proxyCertificate.ForThePeer, CancellationToken);

                using var       webSocket  = new SshWebSocketClient(URL.Parse($"wss://127.0.0.1:{endpoint.Port}/ssh"),
                                                                    RemoteCertificateValidator:  KeyPinValidator.ForServerCertificates<IWebSocketClient>(endpointCertificate.Pinned),
                                                                    Proxy:                       new HTTPProxy(proxy.URL) {
                                                                                                     Authentication  = TheStationsCredentials,
                                                                                                     ServerKeyPins   = proxyCertificate.Pinned
                                                                                                 });

                await using (var client = await SSHClient.Connect(webSocket, await ToTheSshdAsync(daemon, CancellationToken), CancellationToken))
                {

                    var result = await client.Execute("echo tls-in-tls", CancellationToken);

                    Assert.Multiple(() => {
                        Assert.That(result.ExitCode,             Is.EqualTo(0),        $"{result.StandardError}\n{proxy.Output}\n{endpoint.Output}");
                        Assert.That(result.StandardOutput,       Is.EqualTo("tls-in-tls\n"));
                        Assert.That(webSocket.ProxyTLSSession,   Is.Not.Null,          "TLS to the proxy");
                        Assert.That(webSocket.TLSSession,        Is.Not.Null,          "and TLS to their endpoint inside it");
                    });

                }

                var tunnel  = ATunnelTo($"127.0.0.1:{endpoint.Port}", User);
                var output  = await OutputOnceAsync(proxy, tunnel, CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(tunnel.Matches(output),  Has.Count.EqualTo(1),         output);
                    Assert.That(endpoint.Output,         Does.Contain(" tls=TLSv1."),  endpoint.Output);
                });

                SawNothingButTheTunnel(output);

            }
            finally
            {
                await OpenSshServerInteropTests.StopAsync(daemon);
            }

        }

        #endregion

        #region AnHttpsProxyWithAnotherKey_IsNotTold_WhoIsConnecting

        /// <summary>
        /// An "https" proxy whose key is not the one pinned is no proxy to tell the station's credentials
        /// to: the TLS to it ends before any CONNECT, which Squid's log never sees, and the caller is
        /// answered 502 - the proxy was not reached as configured.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task AnHttpsProxyWithAnotherKey_IsNotTold_WhoIsConnecting(CancellationToken CancellationToken)
        {

            await RequireTheProxyAsync(CancellationToken);

            using var proxyCertificate  = await APemCertificateAsync(CancellationToken);
            using var anotherKey        = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            await using var endpoint    = await StartTheirEndpointAsync(1, null, CancellationToken);
            await using var proxy       = await StartProxyAsync(endpoint.Port, Basic: true, TLS: proxyCertificate.ForThePeer, CancellationToken);

            using var       webSocket   = new SshWebSocketClient(URL.Parse($"ws://127.0.0.1:{endpoint.Port}/ssh"),
                                                                 Proxy: new HTTPProxy(proxy.URL) {
                                                                            Authentication  = TheStationsCredentials,
                                                                            ServerKeyPins   = KeyPinPolicy.PinnedTo(KeyPin.FromKey(anotherKey))
                                                                        });

            var refusal = await Assert.ThrowsAsync<SshWebSocketException>(async () => await webSocket.OpenAsync(CancellationToken));

            Assert.Multiple(() => {
                Assert.That(refusal.HTTPStatusCode,  Is.EqualTo(HTTPStatusCode.BadGateway),  refusal.Message);
                Assert.That(refusal.FromProxy,       Is.True,                                "the proxy was never through, so neither was the server");
                Assert.That(proxy.Output,           Does.Not.Contain("CONNECT"),            "no CONNECT reached the proxy, and no credentials");
                Assert.That(endpoint.Output,         Does.Not.Contain("BRIDGE ws-open"),     "nor any WebSocket their endpoint");
            });

        }

        #endregion

    }


    /// <summary>
    /// Through tinyproxy, the small proxy of routers and embedded Linux - a station's own network may
    /// well have one.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.WebSocket")]
    public class TinyproxyForwardProxyInteropTests : AForwardProxyInteropTests
    {

        protected override String          Kind                          => "tinyproxy";
        protected override String          Realm                         => "Tinyproxy";

        // tinyproxy asks with 407 where it was told nothing, and answers credentials it does not take
        // with 401 - and no challenge -, where RFC 9110, Section 15.5.8 has 407 for both.
        protected override HTTPStatusCode  WrongCredentialsAnsweredWith  => HTTPStatusCode.Unauthorized;

        // Its CONNECT log level: "Request (file descriptor <n>): CONNECT <host:port> HTTP/1.1". It is logged
        // as the request comes in, before the credentials are checked, and names no user: that the tunnel
        // was opened, and for whom, the command that ran through it says.
        protected override Regex ATunnelTo(String Target, String? User)
            => new ($@"Request \(file descriptor \d+\): CONNECT {Regex.Escape(Target)} HTTP/1\.1");

    }

}
