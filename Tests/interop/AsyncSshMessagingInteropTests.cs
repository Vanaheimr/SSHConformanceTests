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
using System.Text.Json;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;
using org.GraphDefined.Vanaheimr.Hermod.Messaging;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Hermod's message protocol over an SSH subsystem (<c>libs/Hermod/Hermod/SSH/Messaging/README.md</c>)
    /// against an implementation that is not ours: <c>interop/python/asyncssh_messaging.py</c>, written
    /// from the specification alone on top of AsyncSSH, as a client against our
    /// <see cref="SshMessageServer"/> and as a server for our <see cref="SshMessageClient"/>.
    ///
    /// <para>
    /// Until these tests, both ends of every message test were Hermod's - so a misreading of the
    /// specification shared by both ends could not show. Here the other end knows only the text: the
    /// handshake, every kind of frame, the limits that are judged before a payload is read, invalid
    /// UTF-8, the range kept for extensions, a refusal with <c>retryAfter</c>, a second client of the same
    /// login and the probe of the first, and a server that chooses a subprotocol the client never offered.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.AsyncSSH")]
    public class AsyncSshMessagingInteropTests
    {

        #region Data

        private const String  Subsystem  = "messages@test.open.charging.cloud";
        private const String  Script     = "asyncssh_messaging.py";

        private const Byte    HELLO      = 0x01;
        private const Byte    WELCOME    = 0x02;
        private const Byte    REFUSED    = 0x03;
        private const Byte    TEXT       = 0x10;
        private const Byte    BINARY     = 0x11;
        private const Byte    PING       = 0x20;
        private const Byte    PONG       = 0x21;
        private const Byte    CLOSE      = 0x30;

        private static readonly TimeSpan Within = TimeSpan.FromSeconds(20);

        #endregion


        #region (private) their client against our server

        /// <summary>
        /// Our message server, behind our SSH server bound on every interface, and what it saw.
        /// </summary>
        private sealed class OurServer : IAsyncDisposable
        {

            public required SshServer                                 Ssh          { get; init; }
            public required SshMessageServer                          Messages     { get; init; }
            public required String                                    Host         { get; init; }
            public required Int32                                     Port         { get; init; }
            public required String                                    KeyPath      { get; init; }
            public required String                                    KnownHosts   { get; init; }

            public ConcurrentQueue<SshMessageHello>                   Hellos       { get; } = new ();
            public ConcurrentQueue<String>                            Pongs        { get; } = new ();
            public ConcurrentQueue<SshMessageCloseInfo>               Closes       { get; } = new ();
            public TaskCompletionSource<SshDuplicateConnection>       Duplicate    { get; } = new (TaskCreationOptions.RunContinuationsAsynchronously);

            public async ValueTask DisposeAsync()
            {
                await Ssh.DisposeAsync();
                foreach (var file in new[] { KeyPath, KeyPath + ".pub", KnownHosts })
                    try { File.Delete(file); } catch { }
            }

        }

        /// <summary>
        /// Start our message server: it speaks ocpp2.1 and ocpp2.0.1, takes TEXT and BINARY of up to
        /// 1024 bytes, echoes them - "hold" only after a second, so that its PINGs come first - and
        /// answers the HELLO as <paramref name="Verdict"/> says, or welcomes it.
        /// </summary>
        private static async Task<OurServer> StartOurServerAsync(CancellationToken           CancellationToken,
                                                                 Func<SshHelloVerdict>?      Verdict    = null,
                                                                 TimeSpan?                   PingEvery  = null)
        {

            PythonPeers.SkipIfUnavailable();

            var hostKey   = SshHostKey.GenerateEd25519();
            var userKey   = SshHostKey.GenerateEd25519();

            var messages  = new SshMessageServer(new SshMessageServerOptions {
                                Subsystem         = Subsystem,
                                Subprotocols      = [ "ocpp2.1", "ocpp2.0.1" ],
                                MaxMessageSizeIn  = 1024,
                                PingEvery         = PingEvery
                            });

            var ssh       = new SshServer(new SshServerOptions {
                                HostKeys       = [ hostKey ],
                                Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                                Subsystems     = (session, name, ct) => ValueTask.FromResult<SshSubsystemHandler?>(name == Subsystem ? messages.Handler : null)
                            });

            // Bound on Any: a peer inside WSL cannot reach a loopback-only listener on the Windows host.
            await ssh.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
            var port = ssh.LocalEndPoint.Port.ToInt32();

            var host = await PythonPeers.ResolveHostAsync(CancellationToken);
            if (host is null)
            {
                await ssh.DisposeAsync();
                Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall for the test host process.");
            }

            var keyPath     = Path.Combine(Path.GetTempPath(), "hermod_messaging_" + Guid.NewGuid().ToString("N"));
            var knownHosts  = keyPath + ".known_hosts";

            await SshKeyGenerator.WriteKeyPairAsync(userKey, keyPath, "messaging-interop", CancellationToken);
            await File.WriteAllTextAsync(knownHosts, $"[{host}]:{port} ssh-ed25519 {Convert.ToBase64String(hostKey.PublicKeyBlob)}\n", CancellationToken);

            var ours = new OurServer {
                           Ssh         = ssh,
                           Messages    = messages,
                           Host        = host!,
                           Port        = port,
                           KeyPath     = keyPath,
                           KnownHosts  = knownHosts
                       };

            messages.ValidateHello            = (server, context, hello, subprotocol, ct) => {
                                                    ours.Hellos.Enqueue(hello);
                                                    return ValueTask.FromResult(Verdict?.Invoke() ?? SshHelloVerdict.Accept(new JObject { ["server"] = "hermod" }));
                                                };

            // "hold" is echoed a second later, but not by the handler: it runs on the connection's reading,
            // and a handler that waited would leave their PONGs unread until our pings gave them up.
            messages.OnTextMessageReceived   += async (timestamp, sender, connection, text, ct) => {
                                                    if (text == "hold")
                                                        _ = Task.Run(async () => {
                                                                await Task.Delay(TimeSpan.FromSeconds(1), CancellationToken.None);
                                                                await connection.SendTextMessage(text, CancellationToken.None);
                                                            }, CancellationToken.None);
                                                    // "after-duplicate" is echoed once a second connection of its identity has been decided on.
                                                    else if (text == "after-duplicate")
                                                        _ = Task.Run(async () => {
                                                                await ours.Duplicate.Task.WaitAsync(Within, CancellationToken.None);
                                                                await connection.SendTextMessage(text, CancellationToken.None);
                                                            }, CancellationToken.None);
                                                    else
                                                        await connection.SendTextMessage(text, ct);
                                                };

            messages.OnBinaryMessageReceived += async (timestamp, sender, connection, bytes, ct) => await connection.SendBinaryMessage(bytes, ct);
            messages.OnPongReceived          += (timestamp, sender, connection, payload, ct) => { ours.Pongs. Enqueue(Convert.ToHexStringLower(payload)); return Task.CompletedTask; };
            messages.OnConnectionClosed      += (timestamp, sender, connection, close,   ct) => { ours.Closes.Enqueue(close);                              return Task.CompletedTask; };
            messages.OnDuplicateConnection   += (timestamp, sender, duplicate,           ct) => { ours.Duplicate.TrySetResult(duplicate);                  return Task.CompletedTask; };

            return ours;

        }

        /// <summary>
        /// Run AsyncSSH's client against our server with the given steps, and read the frames it got.
        /// </summary>
        private static async Task<(PeerRunResult Result, JsonElement[] Frames, String[] Pings)> RunTheirClientAsync(OurServer                                   Server,
                                                                                                                     IEnumerable<Dictionary<String, Object?>>    Steps,
                                                                                                                     CancellationToken                           CancellationToken)
        {

            var result = await PythonPeers.RunDriverAsync(Script, new Dictionary<String, Object?> {
                                                              ["host"]         = Server.Host,
                                                              ["port"]         = Server.Port,
                                                              ["username"]     = "station",
                                                              ["key_path"]     = PythonPeers.ToPeerPath(Server.KeyPath),
                                                              ["known_hosts"]  = PythonPeers.ToPeerPath(Server.KnownHosts),
                                                              ["subsystem"]    = Subsystem,
                                                              ["steps"]        = Steps.ToArray()
                                                          }, CancellationToken);

            Assert.That(result.Ok, Is.True, $"AsyncSSH's message client broke off.\n{result.FailureReport}");

            var frames = result.Extra?.TryGetValue("frames", out var f) == true ? f.EnumerateArray().ToArray()                                   : [];
            var pings  = result.Extra?.TryGetValue("pings",  out var p) == true ? p.EnumerateArray().Select(ping => ping.GetString()!).ToArray() : [];

            return (result, frames, pings);

        }

        private static Dictionary<String, Object?> Hello(params String[] Subprotocols)

            => new () {
                   ["op"]    = "frame",
                   ["kind"]  = HELLO,
                   ["json"]  = new Dictionary<String, Object?> {
                                   ["subprotocols"]      = Subprotocols,
                                   ["maxMessageSize"]    = 2048,
                                   ["networkingNodeId"]  = "cs001"
                               }
               };

        private static Dictionary<String, Object?> Text   (String Text)            => new () { ["op"] = "frame",  ["kind"] = TEXT,   ["text"] = Text };
        private static Dictionary<String, Object?> Frame  (Byte Kind, String Hex)  => new () { ["op"] = "frame",  ["kind"] = Kind,   ["hex"]  = Hex  };
        private static Dictionary<String, Object?> Header (Byte Kind, Int64 Length) => new () { ["op"] = "header", ["kind"] = Kind, ["length"] = Length };
        private static Dictionary<String, Object?> Close  (Int32 Code, String Reason) => new () { ["op"] = "close", ["code"] = Code, ["reason"] = Reason };
        private static Dictionary<String, Object?> Receive()                       => new () { ["op"] = "recv" };
        private static Dictionary<String, Object?> ReceiveToTheEnd()               => new () { ["op"] = "recv_until_eof" };
        private static Dictionary<String, Object?> Sleep  (Double Seconds)         => new () { ["op"] = "sleep",  ["seconds"] = Seconds };

        /// <summary>
        /// Wait until our server serves a connection of the given identity - their first client, before a
        /// second one comes.
        /// </summary>
        private static async Task WaitForConnectionOfAsync(OurServer Server, String Identity, Task FirstClient, CancellationToken CancellationToken)
        {

            var until = DateTimeOffset.UtcNow + Within;

            while (Server.Messages.ConnectionsOf(Identity).Count == 0)
            {

                if (FirstClient.IsCompleted)
                    await FirstClient;  // its failure, if it failed

                Assert.That(FirstClient.IsCompleted, Is.False,            $"their first client ended before our server served it as '{Identity}'");
                Assert.That(DateTimeOffset.UtcNow,   Is.LessThan(until),  $"our server did not serve their first client as '{Identity}' within {Within.TotalSeconds} s");

                await Task.Delay(50, CancellationToken);

            }

        }

        private static Byte   KindOf(JsonElement Frame) => Frame.TryGetProperty("kind", out var kind) ? kind.GetByte() : (Byte) 0;
        private static Int32? CodeOf(JsonElement Frame) => Frame.TryGetProperty("code", out var code) ? code.GetInt32() : null;
        private static Boolean IsEof(JsonElement Frame) => Frame.TryGetProperty("eof",  out var eof)  && eof.GetBoolean();

        private static String Describe(JsonElement[] Frames)
            => String.Join("\n", Frames.Select(frame => frame.GetRawText()));

        #endregion


        #region TheirClient_SpeaksTheProtocol_WithOurServer

        /// <summary>
        /// The whole conversation as the specification has it: HELLO with two subprotocols and a property
        /// of the application's, WELCOME with the first one our server speaks and its limit, TEXT and
        /// BINARY echoed, PING answered with the PING's bytes, and CLOSE answered with the same code
        /// before the channel ends.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task TheirClient_SpeaksTheProtocol_WithOurServer(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var (_, frames, _) = await RunTheirClientAsync(server, [
                                     Hello("ocpp1.6", "ocpp2.0.1", "ocpp2.1"),  Receive(),
                                     Text("Grüß Gott 🔌"),                       Receive(),
                                     Frame(BINARY, "00ff10fe"),                  Receive(),
                                     Frame(PING,   "c0ffee"),                    Receive(),
                                     Close(1000, "done"),                        ReceiveToTheEnd()
                                 ], CancellationToken);

            var all = Describe(frames);

            Assert.That(frames, Has.Length.EqualTo(6), all);

            var welcome = frames[0];
            var hello   = server.Hellos.Single();

            Assert.Multiple(() => {
                Assert.That(KindOf(welcome),                                                      Is.EqualTo(WELCOME),     all);
                Assert.That(welcome.GetProperty("json").GetProperty("subprotocol").GetString(),   Is.EqualTo("ocpp2.0.1"), "not the client's first choice that the server speaks");
                Assert.That(welcome.GetProperty("json").GetProperty("maxMessageSize").GetInt64(), Is.EqualTo(1024),        "WELCOME does not say the server's limit");
                Assert.That(welcome.GetProperty("json").GetProperty("server").GetString(),        Is.EqualTo("hermod"),    "the validator's WELCOME properties are missing");
                Assert.That(hello.Subprotocols,                                                   Is.EqualTo(new[] { "ocpp1.6", "ocpp2.0.1", "ocpp2.1" }));
                Assert.That(hello.MaxMessageSize,                                                 Is.EqualTo(2048));
                Assert.That(hello.JSON["networkingNodeId"]?.ToString(),                           Is.EqualTo("cs001"),     "a property of the application's did not reach the validator");

                Assert.That(KindOf(frames[1]),                                                    Is.EqualTo(TEXT));
                Assert.That(frames[1].GetProperty("text").GetString(),                            Is.EqualTo("Grüß Gott 🔌"));
                Assert.That(KindOf(frames[2]),                                                    Is.EqualTo(BINARY));
                Assert.That(frames[2].GetProperty("hex").GetString(),                             Is.EqualTo("00ff10fe"));
                Assert.That(KindOf(frames[3]),                                                    Is.EqualTo(PONG));
                Assert.That(frames[3].GetProperty("hex").GetString(),                             Is.EqualTo("c0ffee"),    "a PONG carries the PING's bytes");
                Assert.That(KindOf(frames[4]),                                                    Is.EqualTo(CLOSE));
                Assert.That(CodeOf(frames[4]),                                                    Is.EqualTo(1000),        "a CLOSE is answered with the same code");
                Assert.That(IsEof (frames[5]),                                                    Is.True,                 "the channel did not end after the CLOSE");
            });

        }

        #endregion

        #region TheirClient_AnswersOurPings

        /// <summary>
        /// Our server's PINGs (<see cref="SshMessageServerOptions.PingEvery"/>) reach their client while it
        /// waits for an answer, and the PONGs it sends back reach us with the PING's bytes.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task TheirClient_AnswersOurPings(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken, PingEvery: TimeSpan.FromMilliseconds(200));

            var (_, frames, pings) = await RunTheirClientAsync(server, [
                                         Hello("ocpp2.1"),  Receive(),
                                         Text("hold"),      Receive(),
                                         Close(1000, ""),   ReceiveToTheEnd()
                                     ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(frames[1].GetProperty("text").GetString(), Is.EqualTo("hold"), Describe(frames));
                Assert.That(pings,                                     Is.Not.Empty,       "no PING of our server reached their client within a second");
                Assert.That(server.Pongs,                              Is.Not.Empty,       "no PONG of theirs reached our server");
                Assert.That(server.Pongs.All(pong => pings.Contains(pong)), Is.True,      "a PONG that does not carry the bytes of a PING we sent");
            });

        }

        #endregion

        #region TheirClient_IsRefused_AsTheSpecificationSays

        /// <summary>
        /// The three refusals of the handshake: a client that offers only subprotocols our server does not
        /// speak, a client whose first frame is not HELLO, and a validator's own refusal with a
        /// <c>retryAfter</c> - each a REFUSED, and then the end of the channel.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("unsupported-subprotocol")]
        [TestCase("hello-expected")]
        [TestCase("connection-exists")]
        public async Task TheirClient_IsRefused_AsTheSpecificationSays(String Code, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken,
                                                               Verdict: Code == "connection-exists"
                                                                            ? () => SshHelloVerdict.Refuse("connection-exists", "cs001 is connected already", TimeSpan.FromSeconds(30))
                                                                            : null);

            var first = Code switch {
                            "unsupported-subprotocol"  => Hello("ocpp1.6"),
                            "hello-expected"           => Text("not a HELLO"),
                            _                          => Hello("ocpp2.1")
                        };

            var (_, frames, _) = await RunTheirClientAsync(server, [ first, ReceiveToTheEnd() ], CancellationToken);

            var all = Describe(frames);

            Assert.That(frames, Has.Length.EqualTo(2), all);

            var refusal = frames[0].GetProperty("json");

            Assert.Multiple(() => {
                Assert.That(KindOf(frames[0]),                         Is.EqualTo(REFUSED), all);
                Assert.That(refusal.GetProperty("code").GetString(),  Is.EqualTo(Code),    all);
                Assert.That(IsEof(frames[1]),                          Is.True,             "the channel did not end after the REFUSED");
            });

            if (Code == "connection-exists")
                Assert.That(refusal.GetProperty("retryAfter").GetInt32(), Is.EqualTo(30), "retryAfter is a whole number of seconds");

        }

        #endregion

        #region TheirSecondClient_IsRefused_WhileTheFirstAnswersTheProbe

        /// <summary>
        /// "A second connection of an identity", with Hermod's default policy: a second client of their's
        /// with the same login comes while the first is connected. Our server probes the first with a PING
        /// of 16 random bytes; the first answers it as it answers any PING, so it keeps its connection, and
        /// the second gets REFUSED <c>connection-exists</c> with a <c>retryAfter</c> of 30 s plus up to 30 s.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task TheirSecondClient_IsRefused_WhileTheFirstAnswersTheProbe(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var first = RunTheirClientAsync(server, [
                            Hello("ocpp2.1"),          Receive(),
                            Text("after-duplicate"),   Receive(),
                            Close(1000, "done"),       ReceiveToTheEnd()
                        ], CancellationToken);

            await WaitForConnectionOfAsync(server, "station", first, CancellationToken);

            var (_, second, _)      = await RunTheirClientAsync(server, [ Hello("ocpp2.1"), ReceiveToTheEnd() ], CancellationToken);
            var (_, frames, pings)  = await first;
            var duplicate           = await server.Duplicate.Task.WaitAsync(Within, CancellationToken);

            Assert.That(second, Has.Length.EqualTo(2), Describe(second));

            var refusal = second[0].GetProperty("json");

            Assert.Multiple(() => {
                Assert.That(KindOf(second[0]),                            Is.EqualTo(REFUSED),                      Describe(second));
                Assert.That(refusal.GetProperty("code").GetString(),     Is.EqualTo("connection-exists"),          Describe(second));
                Assert.That(refusal.GetProperty("retryAfter").GetInt32(), Is.InRange(30, 60),                       "retryAfter is 30 s plus up to 30 s");
                Assert.That(IsEof(second[1]),                             Is.True,                                  "the channel did not end after the REFUSED");

                Assert.That(pings,                                        Has.Some.Length.EqualTo(32),              "no PING of 16 bytes - the probe - reached their first client");
                Assert.That(frames[1].GetProperty("text").GetString(),    Is.EqualTo("after-duplicate"),            "their first client lost its connection: " + Describe(frames));
                Assert.That(CodeOf(frames[2]),                            Is.EqualTo(1000),                         Describe(frames));

                Assert.That(duplicate.Identity,                           Is.EqualTo("station"));
                Assert.That(duplicate.Policy,                             Is.EqualTo(SshDuplicatePolicy.Probe));
                Assert.That(duplicate.Decision,                           Is.EqualTo(SshDuplicateDecision.Refused));
            });

        }

        #endregion

        #region TheirSecondClient_IsServed_WhenTheFirstDoesNotAnswerTheProbe

        /// <summary>
        /// The same, but their first client reads nothing while the second comes, so the probe stays
        /// unanswered: our server closes the first with CLOSE <c>4001</c> (unresponsive) after
        /// <see cref="SshMessageServerOptions.ProbeTimeout"/>, and welcomes the second.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task TheirSecondClient_IsServed_WhenTheFirstDoesNotAnswerTheProbe(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            // Ten seconds: long enough for the second client's SSH handshake and our 3 s probe, on a busy machine as well.
            var first = RunTheirClientAsync(server, [
                            Hello("ocpp2.1"),   Receive(),
                            Sleep(10),          ReceiveToTheEnd()
                        ], CancellationToken);

            await WaitForConnectionOfAsync(server, "station", first, CancellationToken);

            var (_, second, _)  = await RunTheirClientAsync(server, [
                                      Hello("ocpp2.1"),      Receive(),
                                      Close(1000, "done"),   ReceiveToTheEnd()
                                  ], CancellationToken);
            var (_, frames, _)  = await first;
            var duplicate       = await server.Duplicate.Task.WaitAsync(Within, CancellationToken);

            Assert.That(frames, Has.Length.EqualTo(3), Describe(frames));

            Assert.Multiple(() => {
                Assert.That(KindOf(second[0]),     Is.EqualTo(WELCOME),                                  "the second client was not served: " + Describe(second));
                Assert.That(CodeOf(second[1]),     Is.EqualTo(1000),                                     Describe(second));

                Assert.That(KindOf(frames[0]),     Is.EqualTo(WELCOME),                                  Describe(frames));
                Assert.That(KindOf(frames[1]),     Is.EqualTo(CLOSE),                                    Describe(frames));
                Assert.That(CodeOf(frames[1]),     Is.EqualTo(4001),                                     "the first client was not closed as unresponsive");
                Assert.That(IsEof (frames[2]),     Is.True,                                              "the channel did not end after the CLOSE");

                Assert.That(duplicate.Decision,    Is.EqualTo(SshDuplicateDecision.ReplacedUnresponsive));
            });

        }

        #endregion

        #region TheirClient_BreakingTheRules_EndsTheConnection_WithTheCodeTheSpecificationGives

        /// <summary>
        /// After WELCOME, every frame the specification rules out ends the connection with the close code
        /// it names - and the limits are judged on the length alone: the frames that are too long are
        /// sent as their header only, so a server that waited for the payload would never answer.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("text above the limit",       1009)]
        [TestCase("binary above the limit",     1009)]
        [TestCase("ping above 64 KiB",          1002)]
        [TestCase("text that is not UTF-8",     1007)]
        [TestCase("unknown kind below 0x80",    1002)]
        [TestCase("a second HELLO",             1002)]
        public async Task TheirClient_BreakingTheRules_EndsTheConnection_WithTheCodeTheSpecificationGives(String Case, Int32 ExpectedCode, CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var offence = Case switch {
                              "text above the limit"     => Header(TEXT,   1 + 1025),
                              "binary above the limit"   => Header(BINARY, 1 + 1025),
                              "ping above 64 KiB"        => Header(PING,   1 + 64 * 1024 + 1),
                              "text that is not UTF-8"   => Frame (TEXT,   "c328"),
                              "unknown kind below 0x80"  => Frame (0x05,   "00"),
                              _                          => Hello("ocpp2.1")
                          };

            var (_, frames, _) = await RunTheirClientAsync(server, [ Hello("ocpp2.1"), Receive(), offence, ReceiveToTheEnd() ], CancellationToken);

            var all = Describe(frames);

            Assert.Multiple(() => {
                Assert.That(KindOf(frames[0]),          Is.EqualTo(WELCOME),        all);
                Assert.That(KindOf(frames[1]),          Is.EqualTo(CLOSE),          $"{Case}: no CLOSE\n{all}");
                Assert.That(CodeOf(frames[1]),          Is.EqualTo(ExpectedCode),   $"{Case}: the wrong close code\n{all}");
                Assert.That(IsEof (frames[^1]),         Is.True,                    $"{Case}: the channel did not end\n{all}");
            });

        }

        #endregion

        #region TheirClient_IsHeard_AfterAFrameOfAnExtension

        /// <summary>
        /// A frame from <c>0x80</c> on is kept for extensions and skipped: the TEXT after it is answered as
        /// if it had not been there.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task TheirClient_IsHeard_AfterAFrameOfAnExtension(CancellationToken CancellationToken)
        {

            await using var server = await StartOurServerAsync(CancellationToken);

            var (_, frames, _) = await RunTheirClientAsync(server, [
                                     Hello("ocpp2.1"),             Receive(),
                                     Frame(0x80, "657874656e73696f6e"),
                                     Text("still here"),           Receive(),
                                     Close(1000, ""),              ReceiveToTheEnd()
                                 ], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(KindOf(frames[1]),                          Is.EqualTo(TEXT),          Describe(frames));
                Assert.That(frames[1].GetProperty("text").GetString(),  Is.EqualTo("still here"),  "the frame of an extension was not skipped");
            });

        }

        #endregion


        #region (private) our client against their server

        private sealed record TheirServer(WslServer Server, ISshHostKey UserKey, Byte[] HostKeyBlob, String Root) : IAsyncDisposable
        {

            public IPPort Port
                => IPPort.Parse((UInt16) Server.Port);

            public async ValueTask DisposeAsync()
            {
                await Server.DisposeAsync();
                try { Directory.Delete(Root, recursive: true); } catch { }
            }

        }

        /// <summary>
        /// Start AsyncSSH's message server (see the script's header for <paramref name="Configuration"/>).
        /// </summary>
        private static async Task<TheirServer> StartTheirServerAsync(Dictionary<String, Object?> Configuration, CancellationToken CancellationToken)
        {

            PythonPeers.SkipIfUnavailable();

            var root        = Path.Combine(Path.GetTempPath(), "hermod_messaging_server_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(root);

            var userKey     = SshHostKey.GenerateEd25519();
            var hostKeyPath = Path.Combine(root, "hostkey.pub");
            var configPath  = Path.Combine(root, "config.json");

            Configuration["host_key_path"]   = PythonPeers.ToPeerPath(hostKeyPath);
            Configuration["authorized_key"]  = $"ssh-ed25519 {Convert.ToBase64String(userKey.PublicKeyBlob)}";
            Configuration["subsystem"]       = Subsystem;

            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(Configuration), CancellationToken);

            var server = await PythonPeers.StartServerAsync(Script,
                                                            port => [ "server", port.ToString(), PythonPeers.ToPeerPath(configPath) ],
                                                            CancellationToken);

            // Written before the server listens, so a port that answers means a key on disk.
            var hostKeyBlob = Convert.FromBase64String((await File.ReadAllTextAsync(hostKeyPath, CancellationToken)).Split(' ')[1]);

            return new TheirServer(server, userKey, hostKeyBlob, root);

        }

        private static SshMessageClient OurClient(TheirServer Server, UInt64 MaxMessageSizeIn = 1024, params String[] Subprotocols)

            => new (new SshMessageClientOptions {
                       Host              = "127.0.0.1",
                       Port              = Server.Port,
                       Ssh               = new SSHClientOptions {
                                               Username       = User_Id.Parse("csms"),
                                               VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(Server.HostKeyBlob),
                                               Credentials    = [ Server.UserKey ]
                                           },
                       Subsystem         = Subsystem,
                       Subprotocols      = Subprotocols,
                       HelloProperties   = new JObject { ["networkingNodeId"] = "csms01" },
                       MaxMessageSizeIn  = MaxMessageSizeIn
                   });

        /// <summary>
        /// Wait until their server has logged a line that starts with <paramref name="Prefix"/>, and answer it.
        /// </summary>
        private static async Task<String?> LoggedAsync(TheirServer Server, String Prefix, CancellationToken CancellationToken)
        {

            var until = DateTimeOffset.UtcNow + Within;

            while (DateTimeOffset.UtcNow < until)
            {

                var line = Server.Server.Output.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.StartsWith(Prefix, StringComparison.Ordinal));
                if (line is not null)
                    return line;

                await Task.Delay(50, CancellationToken);

            }

            return null;

        }

        private static async Task<T> WithinAsync<T>(TaskCompletionSource<T> Source, String What)
        {
            if (await Task.WhenAny(Source.Task, Task.Delay(Within)) != Source.Task)
                Assert.Fail($"Not within {Within.TotalSeconds:0} s: {What}");
            return await Source.Task;
        }

        #endregion


        #region OurClient_SpeaksTheProtocol_WithTheirServer

        /// <summary>
        /// Our client against their server: the subprotocol it chose of the ones we offered, its limit
        /// taken as ours for sending, TEXT and BINARY echoed, our PING answered, theirs answered by us, a
        /// frame of an extension skipped, and our CLOSE heard with its code and reason.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_SpeaksTheProtocol_WithTheirServer(CancellationToken CancellationToken)
        {

            await using var server = await StartTheirServerAsync(new () {
                                                                    ["subprotocols"]      = new[] { "ocpp2.0.1" },
                                                                    ["max_message_size"]  = 4096
                                                                }, CancellationToken);

            await using var client = OurClient(server, 1024, "ocpp2.1", "ocpp2.0.1");

            var texts   = new ConcurrentQueue<String>();
            var binary  = new TaskCompletionSource<Byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            var pong    = new TaskCompletionSource<Byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            var echoed  = new SemaphoreSlim(0);

            client.OnTextMessageReceived   += (timestamp, sender, connection, text,    ct) => { texts.Enqueue(text); echoed.Release(); return Task.CompletedTask; };
            client.OnBinaryMessageReceived += (timestamp, sender, connection, bytes,   ct) => { binary.TrySetResult(bytes);             return Task.CompletedTask; };
            client.OnPongReceived          += (timestamp, sender, connection, payload, ct) => { pong.  TrySetResult(payload);           return Task.CompletedTask; };

            var connection = await client.ConnectAsync(CancellationToken);

            var tooLong    = await connection.SendTextMessage(new String('x', 5000), CancellationToken);

            await connection.SendTextMessage("Grüß Gott 🔌", CancellationToken);
            Assert.That(await echoed.WaitAsync(Within, CancellationToken), Is.True, "their echo of our TEXT did not come");

            await connection.SendBinaryMessage([ 0x00, 0xff, 0x10, 0xfe ], CancellationToken);
            var binaryEcho = await WithinAsync(binary, "their echo of our BINARY");

            await connection.SendPing([ 0xc0, 0xff, 0xee ], CancellationToken);
            var pongBytes  = await WithinAsync(pong, "their PONG");

            await connection.SendTextMessage("ping-me", CancellationToken);
            var theirPong  = await LoggedAsync(server, "PONG ", CancellationToken);

            await connection.SendTextMessage("ext", CancellationToken);
            Assert.That(await echoed.WaitAsync(Within, CancellationToken), Is.True, "the TEXT after their frame of an extension did not come");

            await client.Close(MessageCloseCode.NormalClosure, "done");
            var theirClose = await LoggedAsync(server, "CLOSE ", CancellationToken);
            var theirHello = await LoggedAsync(server, "HELLO ", CancellationToken);

            Assert.Multiple(() => {
                Assert.That(connection.Subprotocol,       Is.EqualTo("ocpp2.0.1"),                  "the subprotocol their server chose");
                Assert.That(connection.MaxMessageSizeOut, Is.EqualTo(4096UL),                       "their WELCOME's maxMessageSize is not our limit for sending");
                Assert.That(tooLong,                      Is.EqualTo(SentStatus.Error),             "a message above their limit was sent");
                Assert.That(texts,                        Is.EqualTo(new[] { "Grüß Gott 🔌", "after-extension" }), "their echo, then the TEXT after the frame of an extension - and nothing of the 5000 characters");
                Assert.That(binaryEcho,                   Is.EqualTo(new Byte[] { 0x00, 0xff, 0x10, 0xfe }));
                Assert.That(pongBytes,                    Is.EqualTo(new Byte[] { 0xc0, 0xff, 0xee }), "their PONG does not carry our PING's bytes");
                Assert.That(theirPong,                    Is.EqualTo("PONG " + Convert.ToHexStringLower("from-asyncssh"u8)), "we did not answer their PING with its bytes");
                Assert.That(theirClose,                   Is.EqualTo("CLOSE 1000 done"),            "our CLOSE, as they read it");
                Assert.That(theirHello,                   Does.Contain("\"subprotocols\": [\"ocpp2.1\", \"ocpp2.0.1\"]"), "our HELLO, as they read it");
                Assert.That(theirHello,                   Does.Contain("\"maxMessageSize\": 1024"));
                Assert.That(theirHello,                   Does.Contain("\"networkingNodeId\": \"csms01\""));
            });

        }

        #endregion

        #region OurClient_IsRefused_WithTheirRetryAfter

        /// <summary>
        /// A REFUSED with <c>retryAfter</c> reaches our client as what it is: the code, the description and
        /// the time after which it may try again.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_IsRefused_WithTheirRetryAfter(CancellationToken CancellationToken)
        {

            await using var server = await StartTheirServerAsync(new () {
                                                                    ["refuse"] = new Dictionary<String, Object?> {
                                                                                     ["code"]         = "connection-exists",
                                                                                     ["description"]  = "csms01 is connected already",
                                                                                     ["retryAfter"]   = 30
                                                                                 }
                                                                }, CancellationToken);

            await using var client = OurClient(server, 1024, "ocpp2.1");

            var refused = await Assert.ThrowsAsync<SshMessageRefusedException>(async () => await client.ConnectAsync(CancellationToken));

            Assert.Multiple(() => {
                Assert.That(refused!.Code,         Is.EqualTo("connection-exists"));
                Assert.That(refused. Description,  Is.EqualTo("csms01 is connected already"));
                Assert.That(refused. RetryAfter,   Is.EqualTo(TimeSpan.FromSeconds(30)));
            });

        }

        #endregion

        #region OurClient_RefusesASubprotocol_ItDidNotOffer

        /// <summary>
        /// "A client checks that the subprotocol chosen is one it offered": their server chooses one we
        /// never named, and our client does not take the connection.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_RefusesASubprotocol_ItDidNotOffer(CancellationToken CancellationToken)
        {

            await using var server = await StartTheirServerAsync(new () {
                                                                    ["welcome_subprotocol"] = "ocpp1.6"
                                                                }, CancellationToken);

            await using var client = OurClient(server, 1024, "ocpp2.1", "ocpp2.0.1");

            var error = await Assert.ThrowsAsync<SshMessageProtocolException>(async () => await client.ConnectAsync(CancellationToken));

            Assert.That(error!.Message, Does.Contain("ocpp1.6"));

        }

        #endregion

        #region OurClient_AnswersTheirClose

        /// <summary>
        /// Their server ends the connection with CLOSE 1001: our client hears it as the peer's, and answers
        /// with the same code.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_AnswersTheirClose(CancellationToken CancellationToken)
        {

            await using var server = await StartTheirServerAsync(new () { ["subprotocols"] = new[] { "ocpp2.1" } }, CancellationToken);
            await using var client = OurClient(server, 1024, "ocpp2.1");

            var closed = new TaskCompletionSource<SshMessageCloseInfo>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.OnConnectionClosed += (timestamp, sender, connection, close, ct) => { closed.TrySetResult(close); return Task.CompletedTask; };

            var connection = await client.ConnectAsync(CancellationToken);
            await connection.SendTextMessage("close-me", CancellationToken);

            var close      = await WithinAsync(closed, "the end of the connection after their CLOSE");
            var ourAnswer  = await LoggedAsync(server, "CLOSE ", CancellationToken);

            Assert.Multiple(() => {
                Assert.That(close.Code,    Is.EqualTo(MessageCloseCode.GoingAway));
                Assert.That(close.Reason,  Is.EqualTo("going away"));
                Assert.That(close.ByPeer,  Is.True);
                Assert.That(ourAnswer,     Does.StartWith("CLOSE 1001"), "we did not answer their CLOSE with the same code");
            });

        }

        #endregion

        #region OurClient_Closes_With1009_OnAMessageAboveItsLimit

        /// <summary>
        /// Their server sends a TEXT longer than the <c>maxMessageSize</c> our HELLO named: our client ends
        /// the connection with CLOSE 1009, and they read that code.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_Closes_With1009_OnAMessageAboveItsLimit(CancellationToken CancellationToken)
        {

            await using var server = await StartTheirServerAsync(new () { ["subprotocols"] = new[] { "ocpp2.1" } }, CancellationToken);
            await using var client = OurClient(server, 1024, "ocpp2.1");

            var closed = new TaskCompletionSource<SshMessageCloseInfo>(TaskCreationOptions.RunContinuationsAsynchronously);
            client.OnConnectionClosed += (timestamp, sender, connection, close, ct) => { closed.TrySetResult(close); return Task.CompletedTask; };

            var connection = await client.ConnectAsync(CancellationToken);
            await connection.SendTextMessage("big:2000", CancellationToken);

            var close      = await WithinAsync(closed, "the end of the connection after their message above our limit");
            var ourClose   = await LoggedAsync(server, "CLOSE ", CancellationToken);

            Assert.Multiple(() => {
                Assert.That(close.Code,    Is.EqualTo(MessageCloseCode.MessageTooBig));
                Assert.That(close.ByPeer,  Is.False);
                Assert.That(ourClose,      Does.StartWith("CLOSE 1009"), "they did not read our CLOSE 1009");
            });

        }

        #endregion

    }

}
