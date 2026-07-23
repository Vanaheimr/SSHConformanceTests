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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>
    /// Drives the SSH authentication protocol (RFC 4252) over an established <see cref="SshTransport"/>:
    /// the <c>ssh-userauth</c> service request/accept, the <c>publickey</c> method with the query-then-sign
    /// flow, the authentication banner and success/failure handling.
    /// </summary>
    public static class UserAuthentication
    {

        #region Constants

        /// <summary>The authentication service name requested after the transport is up.</summary>
        public const String AuthService        = "ssh-userauth";

        /// <summary>The service a successful authentication grants access to (the connection protocol).</summary>
        public const String ConnectionService  = "ssh-connection";

        /// <summary>The <c>publickey</c> authentication method (RFC 4252 §7).</summary>
        public const String PublicKeyMethod     = "publickey";

        /// <summary>The <c>none</c> method — used only to probe which methods the server will accept.</summary>
        public const String NoneMethod          = "none";

        #endregion


        #region ServerAuthenticateAsync(Transport, Authenticator, Banner = null, MaxAuthTries = 6, CancellationToken = default)

        /// <summary>
        /// Run the server side of authentication: accept the <c>ssh-userauth</c> service, optionally send a
        /// banner, then evaluate <c>publickey</c> requests until one succeeds or the attempt budget is spent.
        /// </summary>
        /// <param name="Transport">The established transport.</param>
        /// <param name="Authenticator">The authentication policy.</param>
        /// <param name="Banner">An optional pre-auth banner (SSH_MSG_USERAUTH_BANNER).</param>
        /// <param name="MaxAuthTries">The maximum number of failed attempts before disconnecting.</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        public static async ValueTask<SshAuthResult> ServerAuthenticateAsync(SshTransport           Transport,
                                                                             ISshUserAuthenticator  Authenticator,
                                                                             String?                Banner             = null,
                                                                             Int32                  MaxAuthTries       = 6,
                                                                             CancellationToken      CancellationToken  = default)
        {

            // 1. Wait for SERVICE_REQUEST("ssh-userauth") — skipping a client-sent EXT_INFO.
            await ExpectServiceRequestAsync(Transport, CancellationToken).ConfigureAwait(false);
            await Transport.SendPacketAsync(BuildServiceAccept(AuthService), CancellationToken).ConfigureAwait(false);

            if (Banner is not null)
                await Transport.SendPacketAsync(BuildBanner(Banner), CancellationToken).ConfigureAwait(false);

            // 2. Process authentication requests.
            var failedAttempts = 0;

            while (true)
            {

                var payload  = await Transport.ReceivePacketAsync(CancellationToken).ConfigureAwait(false);
                var request  = ParseAuthRequest(payload);   // fully parse before any await (ref struct)

                if (request.Method == PublicKeyMethod)
                {

                    var authorized = await Authenticator.AuthorizePublicKeyAsync(
                                             new SshPublicKeyAuthRequest(request.Username, request.Algorithm, request.PublicKeyBlob),
                                             CancellationToken).ConfigureAwait(false);

                    if (!request.HasSignature)
                    {
                        // Query: tell the client whether this key would be acceptable, so it only signs then.
                        if (authorized)
                        {
                            await Transport.SendPacketAsync(BuildPublicKeyOk(request.Algorithm, request.PublicKeyBlob), CancellationToken).ConfigureAwait(false);
                            continue;   // no failed attempt — the client will follow up with a signature
                        }
                    }
                    else
                    {
                        var signedData = BuildPublicKeySignedData(Transport.SessionId, request.Username, request.Algorithm, request.PublicKeyBlob);

                        if (authorized && SshSignature.Verify(request.PublicKeyBlob, signedData, request.Signature))
                        {
                            await Transport.SendPacketAsync(new Byte[] { (Byte) SshMessageNumber.UserAuthSuccess }, CancellationToken).ConfigureAwait(false);
                            return new SshAuthResult(request.Username, PublicKeyMethod);
                        }
                    }

                }

                // Anything else (none, unknown method, unauthorized key, bad signature) is a failure.
                await Transport.SendPacketAsync(BuildFailure(Authenticator.OfferedMethods), CancellationToken).ConfigureAwait(false);

                // "none" and query probes don't burn the budget; a real failed attempt does.
                if (request.Method != NoneMethod)
                {
                    failedAttempts++;
                    if (failedAttempts >= MaxAuthTries)
                        throw new SshAuthenticationException($"Authentication failed after {failedAttempts} attempts.");
                }

            }

        }

        #endregion

        #region ClientPublicKeyAuthenticateAsync(Transport, Username, Key, Algorithm = null, BannerCallback = null, CancellationToken = default)

        /// <summary>
        /// Run the client side of <c>publickey</c> authentication for a single key: request the
        /// <c>ssh-userauth</c> service, query whether the key is acceptable, and only then sign.
        /// </summary>
        /// <param name="Transport">The established transport.</param>
        /// <param name="Username">The login name.</param>
        /// <param name="Key">The signing key (the user's private key).</param>
        /// <param name="Algorithm">
        /// The signature algorithm to use; when null, chosen from the key's algorithms, preferring one the
        /// server advertised via <c>server-sig-algs</c> (so RSA keys use rsa-sha2-256/512, never SHA-1).
        /// </param>
        /// <param name="BannerCallback">An optional callback receiving a server banner (text, language).</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        /// <returns>True on success; false if the server rejected the key.</returns>
        public static async ValueTask<Boolean> ClientPublicKeyAuthenticateAsync(SshTransport             Transport,
                                                                                String                   Username,
                                                                                ISshHostKey              Key,
                                                                                String?                  Algorithm       = null,
                                                                                Action<String, String>?  BannerCallback  = null,
                                                                                CancellationToken        CancellationToken = default)
        {

            // 1. Request the authentication service and wait for its acceptance.
            await Transport.SendPacketAsync(BuildServiceRequest(AuthService), CancellationToken).ConfigureAwait(false);
            await ExpectServiceAcceptAsync(Transport, BannerCallback, CancellationToken).ConfigureAwait(false);

            var algorithm      = Algorithm ?? ChooseAlgorithm(Key, Transport.PeerServerSignatureAlgorithms);
            var publicKeyBlob  = Key.PublicKeyBlob;

            // 2. Query: offer the key without a signature; the server replies PK_OK if it would accept it.
            await Transport.SendPacketAsync(BuildPublicKeyRequest(Username, algorithm, publicKeyBlob, Signature: null), CancellationToken).ConfigureAwait(false);

            var queryReply = await ReadAuthReplyAsync(Transport, BannerCallback, CancellationToken).ConfigureAwait(false);
            if (queryReply == (Byte) SshMessageNumber.UserAuthFailure)
                return false;
            if (queryReply != (Byte) SshMessageNumber.UserAuth60)
                throw new SshWireException($"Expected SSH_MSG_USERAUTH_PK_OK (60), but found message number {queryReply}.");

            // 3. Sign the session-bound request and send it for real.
            var signedData  = BuildPublicKeySignedData(Transport.SessionId, Username, algorithm, publicKeyBlob);
            var signature   = Key.Sign(algorithm, signedData);
            await Transport.SendPacketAsync(BuildPublicKeyRequest(Username, algorithm, publicKeyBlob, signature), CancellationToken).ConfigureAwait(false);

            var reply = await ReadAuthReplyAsync(Transport, BannerCallback, CancellationToken).ConfigureAwait(false);
            return reply == (Byte) SshMessageNumber.UserAuthSuccess;

        }

        #endregion


        #region (private) Flow helpers

        private static async ValueTask ExpectServiceRequestAsync(SshTransport Transport, CancellationToken CancellationToken)
        {
            while (true)
            {

                var payload = await Transport.ReceivePacketAsync(CancellationToken).ConfigureAwait(false);

                if (Transport.TryHandleExtInfo(payload))
                    continue;

                var reader = new SshPacketReader(payload);
                if (reader.ReadByte() != (Byte) SshMessageNumber.ServiceRequest)
                    throw new SshWireException("Expected SSH_MSG_SERVICE_REQUEST (5) after the key exchange.");

                var service = reader.ReadString();
                if (service != AuthService)
                    throw new SshWireException($"The client requested the unsupported service '{service}'.");

                return;

            }
        }

        private static async ValueTask ExpectServiceAcceptAsync(SshTransport Transport, Action<String, String>? BannerCallback, CancellationToken CancellationToken)
        {
            while (true)
            {

                var payload = await Transport.ReceivePacketAsync(CancellationToken).ConfigureAwait(false);

                if (Transport.TryHandleExtInfo(payload))
                    continue;

                var reader  = new SshPacketReader(payload);
                var message = (SshMessageNumber) reader.ReadByte();

                if (message == SshMessageNumber.UserAuthBanner)
                {
                    HandleBanner(ref reader, BannerCallback);
                    continue;
                }

                if (message == SshMessageNumber.ServiceAccept)
                    return;

                throw new SshWireException($"Expected SSH_MSG_SERVICE_ACCEPT (6), but found message number {(Byte) message}.");

            }
        }

        // Read the next authentication reply, transparently surfacing any banner messages.
        private static async ValueTask<Byte> ReadAuthReplyAsync(SshTransport Transport, Action<String, String>? BannerCallback, CancellationToken CancellationToken)
        {
            while (true)
            {

                var payload = await Transport.ReceivePacketAsync(CancellationToken).ConfigureAwait(false);
                var reader  = new SshPacketReader(payload);
                var message = reader.ReadByte();

                if (message == (Byte) SshMessageNumber.UserAuthBanner)
                {
                    HandleBanner(ref reader, BannerCallback);
                    continue;
                }

                return message;

            }
        }

        private static void HandleBanner(ref SshPacketReader Reader, Action<String, String>? BannerCallback)
        {
            var text      = Reader.ReadString();
            var language  = Reader.ReadString();
            BannerCallback?.Invoke(text, language);
        }

        // Prefer a signature algorithm the server advertised (server-sig-algs); otherwise the key's default.
        private static String ChooseAlgorithm(ISshHostKey Key, String[]? ServerSignatureAlgorithms)
        {

            if (ServerSignatureAlgorithms is not null)
                foreach (var candidate in Key.AlgorithmNames)
                    if (Array.IndexOf(ServerSignatureAlgorithms, candidate) >= 0)
                        return candidate;

            return Key.AlgorithmNames[0];

        }

        #endregion

        #region (private) ParseAuthRequest(Payload)

        private readonly record struct AuthRequest(String   Username,
                                                   String   Method,
                                                   Boolean  HasSignature,
                                                   String   Algorithm,
                                                   Byte[]   PublicKeyBlob,
                                                   Byte[]   Signature);

        // Fully parse a USERAUTH_REQUEST synchronously — the ref-struct reader must not cross an await.
        private static AuthRequest ParseAuthRequest(ReadOnlySpan<Byte> Payload)
        {

            var reader = new SshPacketReader(Payload);

            if (reader.ReadByte() != (Byte) SshMessageNumber.UserAuthRequest)
                throw new SshWireException("Expected SSH_MSG_USERAUTH_REQUEST (50) during authentication.");

            var username  = reader.ReadString();
            _             = reader.ReadString();   // service name ("ssh-connection")
            var method    = reader.ReadString();

            if (method != PublicKeyMethod)
                return new AuthRequest(username, method, false, "", [], []);

            var hasSignature   = reader.ReadBoolean();
            var algorithm      = reader.ReadString();
            var publicKeyBlob  = reader.ReadBinaryString();
            var signature      = hasSignature ? reader.ReadBinaryString() : [];

            return new AuthRequest(username, method, hasSignature, algorithm, publicKeyBlob, signature);

        }

        #endregion

        #region (private) Message builders

        private static Byte[] BuildServiceRequest(String Service)
        {
            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);
            writer.WriteByte((Byte) SshMessageNumber.ServiceRequest);
            writer.WriteString(Service);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildServiceAccept(String Service)
        {
            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);
            writer.WriteByte((Byte) SshMessageNumber.ServiceAccept);
            writer.WriteString(Service);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildBanner(String Message)
        {
            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);
            writer.WriteByte((Byte) SshMessageNumber.UserAuthBanner);
            writer.WriteString(Message);
            writer.WriteString("");   // language tag
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildFailure(IReadOnlyList<String> Methods)
        {
            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);
            writer.WriteByte((Byte) SshMessageNumber.UserAuthFailure);
            writer.WriteNameList(Methods);
            writer.WriteBoolean(false);   // partial success
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildPublicKeyOk(String Algorithm, ReadOnlySpan<Byte> PublicKeyBlob)
        {
            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);
            writer.WriteByte((Byte) SshMessageNumber.UserAuth60);   // SSH_MSG_USERAUTH_PK_OK
            writer.WriteString(Algorithm);
            writer.WriteBinaryString(PublicKeyBlob);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildPublicKeyRequest(String Username, String Algorithm, ReadOnlySpan<Byte> PublicKeyBlob, ReadOnlySpan<Byte> Signature)
        {

            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);

            writer.WriteByte((Byte) SshMessageNumber.UserAuthRequest);
            writer.WriteString(Username);
            writer.WriteString(ConnectionService);
            writer.WriteString(PublicKeyMethod);
            writer.WriteBoolean(!Signature.IsEmpty);
            writer.WriteString(Algorithm);
            writer.WriteBinaryString(PublicKeyBlob);

            if (!Signature.IsEmpty)
                writer.WriteBinaryString(Signature);

            return abw.WrittenSpan.ToArray();

        }

        // The data a publickey signature covers (RFC 4252 §7): session id + the request up to the key blob.
        private static Byte[] BuildPublicKeySignedData(ReadOnlySpan<Byte> SessionId, String Username, String Algorithm, ReadOnlySpan<Byte> PublicKeyBlob)
        {

            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);

            writer.WriteBinaryString(SessionId);
            writer.WriteByte((Byte) SshMessageNumber.UserAuthRequest);
            writer.WriteString(Username);
            writer.WriteString(ConnectionService);
            writer.WriteString(PublicKeyMethod);
            writer.WriteBoolean(true);
            writer.WriteString(Algorithm);
            writer.WriteBinaryString(PublicKeyBlob);

            return abw.WrittenSpan.ToArray();

        }

        #endregion

    }


    /// <summary>Thrown when SSH user authentication fails or is exhausted.</summary>
    public sealed class SshAuthenticationException : Exception
    {
        /// <summary>Create a new authentication exception.</summary>
        public SshAuthenticationException(String Message) : base(Message) { }
    }

}
