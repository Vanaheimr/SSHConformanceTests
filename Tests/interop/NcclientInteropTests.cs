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
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// <b>NETCONF</b> (RFC 6241) over SSH (RFC 6242) - the standard subsystem routers, switches and
    /// firewalls are configured through - spoken by <b>ncclient</b>, the Python NETCONF client network
    /// automation runs on, against a <c>netconf</c> subsystem on our server.
    ///
    /// <para>
    /// The subsystem itself is a few dozen lines of this test (<see cref="NetconfServer"/>): what is under
    /// test is not a NETCONF implementation but our subsystem channel carrying an existing standard to an
    /// independent client. NETCONF is a good judge of that because of its framing: base:1.0 ends each
    /// message with <c>]]&gt;]]&gt;</c>, base:1.1 sends it in chunks of announced length, and the peers
    /// agree on one through the <c>&lt;hello&gt;</c>s they exchange as soon as the subsystem opens. Our
    /// server sends a reply of a few hundred kilobytes in chunks of 1, 17, 4096 and 999 bytes, sliced
    /// across SSH packets without regard to where a chunk header or the end marker falls - so a byte lost,
    /// duplicated or reordered anywhere in the channel breaks ncclient's parser or the content it returns.
    /// </para>
    ///
    /// <para>
    /// ncclient runs wherever <see cref="PythonPeers"/> finds it: natively on Windows or Linux, or inside WSL.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.Ncclient")]
    public class NcclientInteropTests
    {

        #region (private) NetconfServer

        /// <summary>
        /// Just enough of a NETCONF server for ncclient to hold a session with: the <c>&lt;hello&gt;</c>s,
        /// both framings, <c>&lt;get-config&gt;</c> answered with one blob, <c>&lt;close-session&gt;</c>,
        /// and an <c>&lt;rpc-error&gt;</c> for every other operation. It records what arrived, and how.
        /// </summary>
        private sealed class NetconfServer(Boolean OfferBase11, Byte[] Blob)
        {

            public const String Base10     = "urn:ietf:params:netconf:base:1.0";
            public const String Base11     = "urn:ietf:params:netconf:base:1.1";
            public const String SessionId  = "4711";

            private static readonly XNamespace netconf      = "urn:ietf:params:xml:ns:netconf:base:1.0";
            private static readonly XNamespace test         = "urn:test:hermod";
            private static readonly Byte[]     endOfMessage = "]]>]]>"u8.ToArray();
            private static readonly Int32[]    chunkSizes   = [ 1, 17, 4096, 999 ];

            /// <summary>The capabilities ncclient announced in its <c>&lt;hello&gt;</c>.</summary>
            public List<String>  ClientCapabilities  { get; } = [];

            /// <summary>The operations ncclient asked for, in order.</summary>
            public List<String>  Operations          { get; } = [];

            /// <summary>How many requests arrived chunked, i.e. in base:1.1 framing.</summary>
            public Int32         ChunkedRequests     { get; private set; }

            /// <summary>What went wrong on our side, if anything did.</summary>
            public Exception?    Failure             { get; private set; }


            public async ValueTask ServeAsync(SshSubsystemContext Context, CancellationToken CancellationToken)
            {

                try
                {

                    var channel = Context.Channel;
                    var reader  = new FrameReader(channel.Input);

                    await SendAsync(channel,
                                    new XElement(netconf + "hello",
                                        new XElement(netconf + "capabilities",
                                            new XElement(netconf + "capability", Base10),
                                            OfferBase11 ? new XElement(netconf + "capability", Base11) : null),
                                        new XElement(netconf + "session-id", SessionId)),
                                    Chunked: false,
                                    CancellationToken);

                    var hello = await reader.ReadEndOfMessageAsync(CancellationToken)
                                    ?? throw new InvalidDataException("The client closed before its <hello>.");

                    ClientCapabilities.AddRange(XElement.Parse(hello.Trim()).Descendants(netconf + "capability").Select(capability => capability.Value.Trim()));

                    // RFC 6242 §4.1: chunked framing once both sides announced base:1.1, end-of-message otherwise.
                    var chunked = OfferBase11 && ClientCapabilities.Contains(Base11);

                    while (true)
                    {

                        var message = chunked
                                          ? await reader.ReadChunkedAsync(CancellationToken)
                                          : await reader.ReadEndOfMessageAsync(CancellationToken);

                        if (message is null)
                            return;

                        if (chunked)
                            ChunkedRequests++;

                        var rpc        = XElement.Parse(message.Trim());
                        var operation  = rpc.Elements().First().Name.LocalName;

                        Operations.Add(operation);

                        // RFC 6241 §4.2: the reply carries every attribute of its <rpc>, message-id included.
                        var reply      = new XElement(netconf + "rpc-reply",
                                             rpc.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration),
                                             operation switch {

                                                 "get-config"     => new XElement(netconf + "data",
                                                                         new XElement(test + "hermod",
                                                                             new XElement(test + "blob", Convert.ToBase64String(Blob)))),

                                                 "close-session"  => new XElement(netconf + "ok"),

                                                 _                => new XElement(netconf + "rpc-error",
                                                                         new XElement(netconf + "error-type",      "protocol"),
                                                                         new XElement(netconf + "error-tag",       "operation-not-supported"),
                                                                         new XElement(netconf + "error-severity",  "error"),
                                                                         new XElement(netconf + "error-message",   $"{operation} is not supported here"))

                                             });

                        await SendAsync(channel, reply, chunked, CancellationToken);

                        if (operation == "close-session")
                            return;

                    }

                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    Failure = exception;
                    throw;
                }

            }

            /// <summary>
            /// Frames a message and sends it in slices of 1500 bytes, wherever chunk headers or the end
            /// marker fall.
            /// </summary>
            private static async ValueTask SendAsync(SshMuxChannel Channel, XElement Message, Boolean Chunked, CancellationToken CancellationToken)
            {

                var body   = Encoding.UTF8.GetBytes(new XDeclaration("1.0", "UTF-8", null) + Message.ToString(SaveOptions.DisableFormatting));
                var framed = new MemoryStream();

                if (Chunked)
                {
                    for (Int32 offset = 0, index = 0; offset < body.Length; index++)
                    {
                        var size = Math.Min(chunkSizes[index % chunkSizes.Length], body.Length - offset);
                        framed.Write(Encoding.ASCII.GetBytes($"\n#{size}\n"));
                        framed.Write(body, offset, size);
                        offset += size;
                    }
                    framed.Write("\n##\n"u8);
                }
                else
                {
                    framed.Write(body);
                    framed.Write(endOfMessage);
                }

                var bytes = framed.ToArray();

                for (var offset = 0; offset < bytes.Length; offset += 1500)
                    await Channel.SendDataAsync(bytes.AsMemory(offset, Math.Min(1500, bytes.Length - offset)), CancellationToken);

            }


            /// <summary>
            /// Reads NETCONF messages off a byte stream, in either framing, strictly by RFC 6242 §4.
            /// </summary>
            private sealed class FrameReader(Stream Input)
            {

                private readonly Byte[] buffer = new Byte[8192];
                private Int32 offset, count;

                private async ValueTask<Int32> ReadByteAsync(CancellationToken CancellationToken)
                {
                    if (offset == count)
                    {
                        count  = await Input.ReadAsync(buffer, CancellationToken);
                        offset = 0;
                        if (count == 0)
                            return -1;
                    }
                    return buffer[offset++];
                }

                private async ValueTask ExpectAsync(Char Expected, CancellationToken CancellationToken)
                {
                    var actual = await ReadByteAsync(CancellationToken);
                    if (actual != Expected)
                        throw new InvalidDataException($"Chunked framing: expected '{Expected}', got {actual}.");
                }

                /// <summary>
                /// A base:1.0 message, up to its <c>]]&gt;]]&gt;</c>; null where the stream ended between messages.
                /// </summary>
                public async ValueTask<String?> ReadEndOfMessageAsync(CancellationToken CancellationToken)
                {

                    var message = new MemoryStream();

                    while (true)
                    {

                        var next = await ReadByteAsync(CancellationToken);

                        if (next < 0)
                            return message.ToArray().All(b => b is (Byte) ' ' or (Byte) '\r' or (Byte) '\n' or (Byte) '\t')
                                       ? null
                                       : throw new InvalidDataException("The stream ended inside a message.");

                        message.WriteByte((Byte) next);

                        if (message.Length >= endOfMessage.Length &&
                            message.GetBuffer().AsSpan((Int32) message.Length - endOfMessage.Length, endOfMessage.Length).SequenceEqual(endOfMessage))
                        {
                            return Encoding.UTF8.GetString(message.GetBuffer(), 0, (Int32) message.Length - endOfMessage.Length);
                        }

                    }

                }

                /// <summary>
                /// A base:1.1 message, chunk by chunk up to its end-of-chunks; null where the stream ended
                /// between messages.
                /// </summary>
                public async ValueTask<String?> ReadChunkedAsync(CancellationToken CancellationToken)
                {

                    var message = new MemoryStream();

                    while (true)
                    {

                        var first = await ReadByteAsync(CancellationToken);

                        if (first < 0 && message.Length == 0)
                            return null;

                        if (first != '\n')
                            throw new InvalidDataException($"Chunked framing: expected a newline, got {first}.");

                        await ExpectAsync('#', CancellationToken);

                        var next = await ReadByteAsync(CancellationToken);

                        if (next == '#')
                        {
                            await ExpectAsync('\n', CancellationToken);
                            return Encoding.UTF8.GetString(message.ToArray());
                        }

                        // chunk-size = [1-9][0-9]*, at most 4294967295
                        if (next is < '1' or > '9')
                            throw new InvalidDataException($"Chunked framing: a chunk size starts with {next}.");

                        UInt64 size = (UInt64) (next - '0');

                        while ((next = await ReadByteAsync(CancellationToken)) != '\n')
                        {
                            if (next is < '0' or > '9' || (size = size * 10 + (UInt64) (next - '0')) > UInt32.MaxValue)
                                throw new InvalidDataException("Chunked framing: a malformed chunk size.");
                        }

                        for (UInt64 index = 0; index < size; index++)
                        {
                            var data = await ReadByteAsync(CancellationToken);
                            if (data < 0)
                                throw new InvalidDataException("The stream ended inside a chunk.");
                            message.WriteByte((Byte) data);
                        }

                    }

                }

            }

        }

        #endregion

        #region (private) harness

        private sealed record Fixture(SshServer      Server,
                                      NetconfServer  Netconf,
                                      String         Host,
                                      Int32          Port,
                                      String         KeyPathWsl,
                                      ISshHostKey    HostKey,
                                      String[]       TempFiles);

        private static async Task<Fixture> StartAsync(Boolean OfferBase11, Byte[] Blob, CancellationToken CancellationToken)
        {

            PythonPeers.SkipIfUnavailable();

            var hostKey  = SshHostKey.GenerateEd25519();
            var userKey  = SshHostKey.GenerateEd25519();
            var keyPath  = Path.Combine(Path.GetTempPath(), "hermod_ncclient_" + Guid.NewGuid().ToString("N"));

            await SshKeyGenerator.WriteKeyPairAsync(userKey, keyPath, "ncclient-interop", CancellationToken);

            var netconf  = new NetconfServer(OfferBase11, Blob);

            var server   = new SshServer(new SshServerOptions {
                               HostKeys       = [ hostKey ],
                               Authenticator  = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                               Subsystems     = (session, name, ct) => ValueTask.FromResult<SshSubsystemHandler?>(name == "netconf" ? netconf.ServeAsync : null)
                           });

            await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Auto), CancellationToken);
            var port = server.LocalEndPoint.Port.ToInt32();

            var host = await PythonPeers.ResolveHostAsync(CancellationToken);
            if (host is null)
            {
                await server.DisposeAsync();
                Assert.Ignore($"WSL cannot reach the test listener on port {port} — check the Windows firewall for the test host process.");
            }

            return new Fixture(server, netconf, host!, port, PythonPeers.ToPeerPath(keyPath), hostKey, [ keyPath, keyPath + ".pub" ]);

        }

        private static async Task StopAsync(Fixture Fixture)
        {
            await Fixture.Server.DisposeAsync();
            foreach (var file in Fixture.TempFiles)
                try { File.Delete(file); } catch { }
        }

        private static String? Text(PeerRunResult Result, String Name)
            => Result.Extra?.TryGetValue(Name, out var value) == true && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

        #endregion


        #region Ncclient_HoldsANetconfSession_OnOurSubsystem

        /// <summary>
        /// A whole NETCONF session, as network automation holds one: ncclient opens the <c>netconf</c>
        /// subsystem, the <c>&lt;hello&gt;</c>s settle the framing - base:1.1's chunks where our server
        /// offers it, base:1.0's end marker where it does not - and then <c>&lt;get-config&gt;</c> brings
        /// back a quarter of a megabyte byte for byte, a <c>&lt;lock&gt;</c> comes back as the
        /// <c>&lt;rpc-error&gt;</c> we sent, and <c>&lt;close-session&gt;</c> ends it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase(true,  TestName = "Ncclient_HoldsANetconfSession_OnOurSubsystem(base 1.1, chunked)")]
        [TestCase(false, TestName = "Ncclient_HoldsANetconfSession_OnOurSubsystem(base 1.0, end-of-message)")]
        public async Task Ncclient_HoldsANetconfSession_OnOurSubsystem(Boolean OfferBase11, CancellationToken CancellationToken)
        {

            var blob    = RandomNumberGenerator.GetBytes(256 * 1024);
            var fixture = await StartAsync(OfferBase11, blob, CancellationToken);

            try
            {

                var result = await PythonPeers.RunDriverAsync(
                                 "ncclient_driver.py",
                                 new Dictionary<String, Object?> {
                                     ["host"]          = fixture.Host,
                                     ["port"]          = fixture.Port,
                                     ["username"]      = "hermoduser",
                                     ["key_path"]      = fixture.KeyPathWsl,
                                     ["host_key_b64"]  = Convert.ToBase64String(fixture.HostKey.PublicKeyBlob),
                                     ["timeout_seconds"] = 60
                                 },
                                 CancellationToken);

                var capabilities = result.Extra?.GetValueOrDefault("server_capabilities") is { ValueKind: JsonValueKind.Array } array
                                       ? array.EnumerateArray().Select(capability => capability.GetString()).ToArray()
                                       : [];

                var lockError    = result.Extra?.GetValueOrDefault("lock_error");

                TestContext.Out.WriteLine($"ncclient {result.PeerVersion}: session {Text(result, "session_id")}, framing {Text(result, "framing")}, " +
                                          $"operations [{String.Join(", ", fixture.Netconf.Operations)}], {fixture.Netconf.ChunkedRequests} requests chunked");

                Assert.Multiple(() => {

                    Assert.That(result.Ok,                                Is.True,                          $"ncclient could not hold the session.\n{result.FailureReport}");
                    Assert.That(fixture.Netconf.Failure,                  Is.Null,                          "our NETCONF subsystem failed");

                    Assert.That(Text(result, "session_id"),               Is.EqualTo(NetconfServer.SessionId), "ncclient read our <hello>");
                    Assert.That(capabilities,                             Does.Contain(NetconfServer.Base10));
                    Assert.That(capabilities.Contains(NetconfServer.Base11), Is.EqualTo(OfferBase11));
                    Assert.That(fixture.Netconf.ClientCapabilities,       Does.Contain(NetconfServer.Base10).And.Contain(NetconfServer.Base11), "we read ncclient's <hello>");

                    Assert.That(fixture.Netconf.Operations,               Is.EqualTo(new[] { "get-config", "lock", "close-session" }));
                    Assert.That(fixture.Netconf.ChunkedRequests,          Is.EqualTo(OfferBase11 ? 3 : 0),  "ncclient framed its requests as the <hello>s settled");

                    Assert.That(Text(result, "config_blob"),              Is.EqualTo(Convert.ToBase64String(blob)), "the reply arrived byte for byte");

                    Assert.That(lockError?.ValueKind,                     Is.EqualTo(JsonValueKind.Object), "our <rpc-error> reached ncclient as an error");
                    if (lockError is { ValueKind: JsonValueKind.Object } error)
                    {
                        Assert.That(error.GetProperty("tag").GetString(),      Is.EqualTo("operation-not-supported"));
                        Assert.That(error.GetProperty("type").GetString(),     Is.EqualTo("protocol"));
                        Assert.That(error.GetProperty("message").GetString(),  Is.EqualTo("lock is not supported here"));
                    }

                });

            }
            finally
            {
                await StopAsync(fixture);
            }

        }

        #endregion

    }

}
