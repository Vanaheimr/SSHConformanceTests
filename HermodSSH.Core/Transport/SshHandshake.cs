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
using System.IO.Pipelines;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>
    /// Drives the minimal modern SSH transport handshake over an <see cref="IDuplexPipe"/>:
    /// version exchange, KEXINIT negotiation, <c>curve25519-sha256</c> key exchange with an
    /// <c>ssh-ed25519</c> host key, key derivation and NEWKEYS, ending with the AES-256-GCM ciphers in
    /// place. Strict-KEX markers are advertised and the outcome recorded (RFC 4253, RFC 8731, RFC 5647).
    /// </summary>
    public static class SshHandshake
    {

        #region ClientHandshakeAsync(Pipe, LocalIdentification, VerifyHostKey = null, CancellationToken = default)

        /// <summary>
        /// Perform the client side of the handshake.
        /// </summary>
        /// <param name="Pipe">The duplex transport.</param>
        /// <param name="LocalIdentification">Our identification string.</param>
        /// <param name="VerifyHostKey">
        /// An optional callback that receives the server's host-key blob and returns true to accept it.
        /// If null, the host key is accepted (M1 has no persistent trust store yet).
        /// </param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        public static async ValueTask<SshTransportContext> ClientHandshakeAsync(IDuplexPipe               Pipe,
                                                                                SshIdentificationString?  LocalIdentification  = null,
                                                                                Func<Byte[], Boolean>?    VerifyHostKey        = null,
                                                                                CancellationToken         CancellationToken    = default)
        {

            var localId  = LocalIdentification ?? SshIdentificationString.Default;

            // 1. Version exchange.
            await SshVersionExchange.WriteAsync(Pipe.Output, localId, CancellationToken).ConfigureAwait(false);
            var remote   = await SshVersionExchange.ReadAsync(Pipe.Input, CancellationToken).ConfigureAwait(false);
            var vC       = localId.ToWireBytes();
            var vS       = remote.WireBytes;

            // 2. KEXINIT exchange + negotiation.
            var localKexInit = KexInitMessage.CreateLocal(IsServer: false);
            var iC           = localKexInit.Encode();
            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, iC, CancellationToken).ConfigureAwait(false);

            var iS            = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken).ConfigureAwait(false);
            var remoteKexInit = KexInitMessage.Decode(iS);
            var negotiated    = AlgorithmNegotiation.Negotiate(localKexInit, remoteKexInit, WeAreServer: false);
            EnsureSupported(negotiated);

            // 3. ECDH init: send our ephemeral public key.
            var ephemeral = X25519KeyPair.Generate();
            var qC        = ephemeral.PublicKey;
            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, BuildEcdhInit(qC), CancellationToken).ConfigureAwait(false);

            // 4. ECDH reply: host key, server ephemeral, signature.
            var reply = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken).ConfigureAwait(false);
            var (kS, qS, signatureBlob) = ParseEcdhReply(reply);

            // 5. Shared secret, exchange hash, signature verification.
            var rawSecret  = ephemeral.Agree(qS);
            var kMpint     = ExchangeHash.EncodeSharedSecretMPInt(rawSecret);
            var h          = ExchangeHash.ComputeSha256(vC, vS, iC, iS, kS, qC, qS, kMpint);

            var hostPublicKey  = SshEd25519.ParsePublicKeyBlob(kS);
            var signature      = SshEd25519.ParseSignatureBlob(signatureBlob);

            if (!Ed25519KeyPair.Verify(hostPublicKey, h, signature))
                throw new SshWireException("The server's host-key signature over the exchange hash is invalid!");

            if (VerifyHostKey is not null && !VerifyHostKey(kS))
                throw new SshWireException("The server's host key was rejected by the host-key policy.");

            // 6. NEWKEYS + key derivation.
            var sessionId = h;
            await ExchangeNewKeysAsync(Pipe, CancellationToken).ConfigureAwait(false);

            var sendCipher     = MakeAesGcm(kMpint, h, sessionId, Kdf.KeyLetter.EncryptionKeyClientToServer, Kdf.KeyLetter.InitialIVClientToServer);
            var receiveCipher  = MakeAesGcm(kMpint, h, sessionId, Kdf.KeyLetter.EncryptionKeyServerToClient, Kdf.KeyLetter.InitialIVServerToClient);

            return new SshTransportContext(sessionId, h, negotiated, kS, sendCipher, receiveCipher);

        }

        #endregion

        #region ServerHandshakeAsync(Pipe, HostKey, LocalIdentification = null, CancellationToken = default)

        /// <summary>
        /// Perform the server side of the handshake.
        /// </summary>
        /// <param name="Pipe">The duplex transport.</param>
        /// <param name="HostKey">The server's Ed25519 host key.</param>
        /// <param name="LocalIdentification">Our identification string.</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        public static async ValueTask<SshTransportContext> ServerHandshakeAsync(IDuplexPipe               Pipe,
                                                                                Ed25519KeyPair            HostKey,
                                                                                SshIdentificationString?  LocalIdentification  = null,
                                                                                CancellationToken         CancellationToken    = default)
        {

            var localId  = LocalIdentification ?? SshIdentificationString.Default;

            // 1. Version exchange.
            await SshVersionExchange.WriteAsync(Pipe.Output, localId, CancellationToken).ConfigureAwait(false);
            var remote   = await SshVersionExchange.ReadAsync(Pipe.Input, CancellationToken).ConfigureAwait(false);
            var vS       = localId.ToWireBytes();
            var vC       = remote.WireBytes;

            // 2. KEXINIT exchange + negotiation.
            var localKexInit = KexInitMessage.CreateLocal(IsServer: true);
            var iS           = localKexInit.Encode();
            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, iS, CancellationToken).ConfigureAwait(false);

            var iC            = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken).ConfigureAwait(false);
            var remoteKexInit = KexInitMessage.Decode(iC);
            var negotiated    = AlgorithmNegotiation.Negotiate(remoteKexInit, localKexInit, WeAreServer: true);
            EnsureSupported(negotiated);

            // 3. ECDH init: the client's ephemeral public key.
            var initPayload = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken).ConfigureAwait(false);
            var qC          = ParseEcdhInit(initPayload);

            // 4. Compute the shared secret and the exchange hash, then sign it.
            var ephemeral  = X25519KeyPair.Generate();
            var qS         = ephemeral.PublicKey;
            var rawSecret  = ephemeral.Agree(qC);
            var kMpint     = ExchangeHash.EncodeSharedSecretMPInt(rawSecret);

            var kS         = SshEd25519.EncodePublicKeyBlob(HostKey.PublicKey);
            var h          = ExchangeHash.ComputeSha256(vC, vS, iC, iS, kS, qC, qS, kMpint);
            var signature  = SshEd25519.EncodeSignatureBlob(HostKey.Sign(h));

            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, BuildEcdhReply(kS, qS, signature), CancellationToken).ConfigureAwait(false);

            // 5. NEWKEYS + key derivation.
            var sessionId = h;
            await ExchangeNewKeysAsync(Pipe, CancellationToken).ConfigureAwait(false);

            var sendCipher     = MakeAesGcm(kMpint, h, sessionId, Kdf.KeyLetter.EncryptionKeyServerToClient, Kdf.KeyLetter.InitialIVServerToClient);
            var receiveCipher  = MakeAesGcm(kMpint, h, sessionId, Kdf.KeyLetter.EncryptionKeyClientToServer, Kdf.KeyLetter.InitialIVClientToServer);

            return new SshTransportContext(sessionId, h, negotiated, kS, sendCipher, receiveCipher);

        }

        #endregion


        #region (private) EnsureSupported(Negotiated)

        // M1 only implements curve25519-sha256 + ssh-ed25519 + aes256-gcm.
        private static void EnsureSupported(NegotiatedAlgorithms Negotiated)
        {

            if (Negotiated.KeyExchange is not (SshAlgorithmNames.Kex.Curve25519Sha256 or SshAlgorithmNames.Kex.Curve25519Sha256LibSsh))
                throw new SshWireException($"Unsupported key exchange '{Negotiated.KeyExchange}' (M1 supports only curve25519-sha256).");

            if (Negotiated.HostKey != SshAlgorithmNames.HostKey.Ed25519)
                throw new SshWireException($"Unsupported host key '{Negotiated.HostKey}' (M1 supports only ssh-ed25519).");

            if (Negotiated.CipherClientToServer != SshAlgorithmNames.Cipher.Aes256Gcm ||
                Negotiated.CipherServerToClient != SshAlgorithmNames.Cipher.Aes256Gcm)
                throw new SshWireException("Unsupported cipher (M1 supports only aes256-gcm@openssh.com).");

        }

        #endregion

        #region (private) ExchangeNewKeysAsync(Pipe, CancellationToken)

        private static async ValueTask ExchangeNewKeysAsync(IDuplexPipe Pipe, CancellationToken CancellationToken)
        {

            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, [ (Byte) SshMessageNumber.NewKeys ], CancellationToken).ConfigureAwait(false);

            var newKeys = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken).ConfigureAwait(false);

            if (newKeys.Length < 1 || newKeys[0] != (Byte) SshMessageNumber.NewKeys)
                throw new SshWireException("Expected SSH_MSG_NEWKEYS (21) to complete the key exchange!");

        }

        #endregion

        #region (private) MakeAesGcm(SharedSecretMPInt, H, SessionId, KeyLetter, IVLetter)

        private static AesGcmTransportCipher MakeAesGcm(Byte[]  SharedSecretMPInt,
                                                        Byte[]  H,
                                                        Byte[]  SessionId,
                                                        Byte    KeyLetter,
                                                        Byte    IVLetter)
        {

            var key  = Kdf.Derive(SharedSecretMPInt, H, KeyLetter, SessionId, 32);
            var iv   = Kdf.Derive(SharedSecretMPInt, H, IVLetter,  SessionId, AesGcmTransportCipher.NonceLength);

            return new AesGcmTransportCipher(key, iv);

        }

        #endregion

        #region (private) WritePacketAsync(Output, Cipher, Payload, CancellationToken)

        private static async ValueTask WritePacketAsync(PipeWriter          Output,
                                                        SshTransportCipher  Cipher,
                                                        Byte[]              Payload,
                                                        CancellationToken   CancellationToken)
        {
            SshPacketFraming.WritePacket(Output, Cipher, Payload);
            await Output.FlushAsync(CancellationToken).ConfigureAwait(false);
        }

        #endregion

        #region (private) ECDH message builders / parsers

        private static Byte[] BuildEcdhInit(ReadOnlySpan<Byte> Q_C)
        {
            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);
            writer.WriteByte((Byte) SshMessageNumber.KexEcdhInit);
            writer.WriteBinaryString(Q_C);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] ParseEcdhInit(ReadOnlySpan<Byte> Payload)
        {
            var reader  = new SshPacketReader(Payload);
            if (reader.ReadByte() != (Byte) SshMessageNumber.KexEcdhInit)
                throw new SshWireException("Expected SSH_MSG_KEX_ECDH_INIT (30)!");
            return reader.ReadBinaryString();
        }

        private static Byte[] BuildEcdhReply(ReadOnlySpan<Byte> K_S, ReadOnlySpan<Byte> Q_S, ReadOnlySpan<Byte> Signature)
        {
            var abw     = new ArrayBufferWriter<Byte>();
            var writer  = new SshPacketWriter(abw);
            writer.WriteByte((Byte) SshMessageNumber.KexEcdhReply);
            writer.WriteBinaryString(K_S);
            writer.WriteBinaryString(Q_S);
            writer.WriteBinaryString(Signature);
            return abw.WrittenSpan.ToArray();
        }

        private static (Byte[] K_S, Byte[] Q_S, Byte[] Signature) ParseEcdhReply(ReadOnlySpan<Byte> Payload)
        {
            var reader  = new SshPacketReader(Payload);
            if (reader.ReadByte() != (Byte) SshMessageNumber.KexEcdhReply)
                throw new SshWireException("Expected SSH_MSG_KEX_ECDH_REPLY (31)!");
            var kS   = reader.ReadBinaryString();
            var qS   = reader.ReadBinaryString();
            var sig  = reader.ReadBinaryString();
            return (kS, qS, sig);
        }

        #endregion

    }

}
