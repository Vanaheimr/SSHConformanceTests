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

using System.Buffers;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Client
{

    /// <summary>
    /// Options for a high-level <see cref="SshClient"/> connection: who to log in as, how to trust the host
    /// key, and which credentials to try. Credentials are <see cref="ISshHostKey"/> signers — a private key,
    /// an agent-backed key (<c>SshAgentKey</c>) or a certificate-bearing key (<c>CertifiedKey</c>).
    /// </summary>
    public sealed record SshClientOptions
    {
        /// <summary>The user to authenticate as.</summary>
        public required String                    Username       { get; init; }

        /// <summary>Host-key trust decision (e.g. from a <c>HostKeyPolicy</c>); null accepts any key (TOFU-off, unsafe).</summary>
        public Func<Byte[], Boolean>?             VerifyHostKey  { get; init; }

        /// <summary>The public-key credentials to try, in order.</summary>
        public IReadOnlyList<ISshHostKey>         Credentials    { get; init; } = [];
    }


    /// <summary>
    /// A high-level SSH client over the connection multiplexer: connect and authenticate once, then run many
    /// operations concurrently on the one connection — <see cref="ExecuteAsync"/> commands and
    /// <see cref="OpenTcpStreamAsync"/> tunnels multiplex freely.
    /// </summary>
    public sealed class SshClient : IAsyncDisposable
    {

        #region Data

        private readonly SshTransport            transport;
        private readonly SshChannelMultiplexer   mux;

        #endregion

        #region Properties

        /// <summary>The underlying multiplexer, for advanced channel operations.</summary>
        public SshChannelMultiplexer Multiplexer => mux;

        #endregion

        #region Constructor(s)

        private SshClient(SshTransport Transport, SshChannelMultiplexer Mux)
        {
            this.transport = Transport;
            this.mux       = Mux;
        }

        #endregion


        #region (static) ConnectAsync(Host, Port, Options, CancellationToken)

        /// <summary>Connect, verify the host key, authenticate with the first working credential and start multiplexing.</summary>
        public static async ValueTask<SshClient> ConnectAsync(String host, UInt16 port, SshClientOptions Options, CancellationToken CancellationToken = default)
        {

            var pipe      = await SshTcp.ConnectAsync(host, IPPort.Parse(port), CancellationToken).ConfigureAwait(false);
            var transport = await SshTransport.ClientHandshakeAsync(pipe, VerifyHostKey: Options.VerifyHostKey, CancellationToken: CancellationToken).ConfigureAwait(false);

            var authenticated = false;
            foreach (var credential in Options.Credentials)
            {
                if (await UserAuthentication.ClientPublicKeyAuthenticateAsync(transport, Options.Username, credential, CancellationToken: CancellationToken).ConfigureAwait(false))
                {
                    authenticated = true;
                    break;
                }
            }

            if (!authenticated)
            {
                transport.Dispose();
                throw new SshAuthenticationException("None of the supplied credentials were accepted.");
            }

            return new SshClient(transport, new SshChannelMultiplexer(transport).Start());

        }

        #endregion

        #region ExecuteAsync(Command, CancellationToken)

        /// <summary>Run a command on the server and capture its stdout/stderr + exit status (log in once, run, capture, log out).</summary>
        public ValueTask<SshCommandResult> ExecuteAsync(String Command, CancellationToken CancellationToken = default)
            => SshSessionChannel.ExecuteAsync(mux, Command, CancellationToken);

        #endregion

        #region OpenTcpStreamAsync(Host, Port, CancellationToken)

        /// <summary>Open a <c>direct-tcpip</c> tunnel to <paramref name="Host"/>:<paramref name="Port"/> through the server as a plain <see cref="Stream"/>.</summary>
        public async ValueTask<Stream> OpenTcpStreamAsync(String Host, UInt16 Port, CancellationToken CancellationToken = default)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteString(Host); w.WriteUInt32(Port); w.WriteString("127.0.0.1"); w.WriteUInt32(0);
            var channel = await mux.OpenChannelAsync("direct-tcpip", abw.WrittenSpan.ToArray(), CancellationToken).ConfigureAwait(false);
            return channel.AsStream();
        }

        #endregion

        #region OpenSftpClientAsync(CancellationToken)

        /// <summary>Open the <c>sftp</c> subsystem over a multiplexed channel and return an SFTP client (runs concurrently with exec/tunnels).</summary>
        public async ValueTask<SftpClient> OpenSftpClientAsync(CancellationToken CancellationToken = default)
        {
            var channel = await mux.OpenChannelAsync("session", CancellationToken: CancellationToken).ConfigureAwait(false);
            if (!await channel.SendRequestAsync("subsystem", true, SshSessionChannel.EncodeString("sftp"), CancellationToken).ConfigureAwait(false))
                throw new SshWireException("The server refused the 'sftp' subsystem.");
            return await SftpClient.OpenAsync(new StreamSftpDuplex(channel.AsStream()), CancellationToken).ConfigureAwait(false);
        }

        #endregion

        #region DisposeAsync()

        /// <summary>Close the connection and stop multiplexing.</summary>
        public async ValueTask DisposeAsync()
        {
            await mux.DisposeAsync().ConfigureAwait(false);
            transport.Dispose();
        }

        #endregion

    }

}
