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
using System.Security.Cryptography;

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
                                                                                String[]?                 Ciphers              = null,
                                                                                String[]?                 Macs                 = null,
                                                                                String[]?                 KeyExchanges         = null,
                                                                                String[]?                 HostKeyAlgorithms    = null,
                                                                                CancellationToken         CancellationToken    = default)
        {

            var localId  = LocalIdentification ?? SshIdentificationString.Default;

            // 1. Version exchange.
            await SshVersionExchange.WriteAsync(Pipe.Output, localId, CancellationToken).ConfigureAwait(false);
            var remote   = await SshVersionExchange.ReadAsync(Pipe.Input, CancellationToken).ConfigureAwait(false);
            var vC       = localId.ToWireBytes();
            var vS       = remote.WireBytes;

            // 2. KEXINIT exchange + negotiation.
            var localKexInit = KexInitMessage.CreateLocal(IsServer: false, Ciphers, Macs, KeyExchanges, HostKeyAlgorithms);
            var iC           = localKexInit.Encode();
            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, iC, CancellationToken).ConfigureAwait(false);

            var iS            = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken: CancellationToken).ConfigureAwait(false);
            var remoteKexInit = KexInitMessage.Decode(iS);
            var negotiated    = AlgorithmNegotiation.Negotiate(localKexInit, remoteKexInit, WeAreServer: false);
            EnsureSupported(negotiated);

            // 3. ECDH init: send our ephemeral public key.
            using var kex = SshKeyExchange.Create(negotiated.KeyExchange);
            var qC        = kex.PublicKey;
            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, BuildEcdhInit(qC), CancellationToken).ConfigureAwait(false);

            // 4. ECDH reply: host key, server ephemeral, signature.
            var reply = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken: CancellationToken).ConfigureAwait(false);
            var (kS, qS, signatureBlob) = ParseEcdhReply(reply);

            // 5. Shared secret, exchange hash, signature verification.
            var rawSecret  = kex.Agree(qS);
            var kMpint     = ExchangeHash.EncodeSharedSecretMPInt(rawSecret);
            var h          = ExchangeHash.Compute(kex.HashAlgorithm, vC, vS, iC, iS, kS, qC, qS, kMpint);

            if (!SshSignature.Verify(kS, h, signatureBlob))
                throw new SshWireException("The server's host-key signature over the exchange hash is invalid!");

            if (VerifyHostKey is not null && !VerifyHostKey(kS))
                throw new SshWireException("The server's host key was rejected by the host-key policy.");

            // 6. NEWKEYS + key derivation.
            var sessionId = h;
            await ExchangeNewKeysAsync(Pipe, CancellationToken).ConfigureAwait(false);

            var derive = MakeDeriver(kex.HashAlgorithm, kMpint, h, sessionId);
            var (sendCipher,    sendMac)    = BuildDirection(negotiated.CipherClientToServer, negotiated.MacClientToServer, derive, Kdf.KeyLetter.EncryptionKeyClientToServer, Kdf.KeyLetter.InitialIVClientToServer, Kdf.KeyLetter.IntegrityKeyClientToServer);
            var (receiveCipher, receiveMac) = BuildDirection(negotiated.CipherServerToClient, negotiated.MacServerToClient, derive, Kdf.KeyLetter.EncryptionKeyServerToClient, Kdf.KeyLetter.InitialIVServerToClient, Kdf.KeyLetter.IntegrityKeyServerToClient);

            return new SshTransportContext(sessionId, h, negotiated, kS, sendCipher, receiveCipher, sendMac, receiveMac);

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
                                                                                ISshHostKey               HostKey,
                                                                                SshIdentificationString?  LocalIdentification  = null,
                                                                                String[]?                 Ciphers              = null,
                                                                                String[]?                 Macs                 = null,
                                                                                String[]?                 KeyExchanges         = null,
                                                                                CancellationToken         CancellationToken    = default)
        {

            var localId  = LocalIdentification ?? SshIdentificationString.Default;

            // 1. Version exchange.
            await SshVersionExchange.WriteAsync(Pipe.Output, localId, CancellationToken).ConfigureAwait(false);
            var remote   = await SshVersionExchange.ReadAsync(Pipe.Input, CancellationToken).ConfigureAwait(false);
            var vS       = localId.ToWireBytes();
            var vC       = remote.WireBytes;

            // 2. KEXINIT exchange + negotiation. The server offers only its host key's algorithms.
            var localKexInit = KexInitMessage.CreateLocal(IsServer: true, Ciphers, Macs, KeyExchanges, [.. HostKey.AlgorithmNames]);
            var iS           = localKexInit.Encode();
            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, iS, CancellationToken).ConfigureAwait(false);

            var iC            = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken: CancellationToken).ConfigureAwait(false);
            var remoteKexInit = KexInitMessage.Decode(iC);
            var negotiated    = AlgorithmNegotiation.Negotiate(remoteKexInit, localKexInit, WeAreServer: true);
            EnsureSupported(negotiated);

            // 3. ECDH init: the client's ephemeral public key.
            var initPayload = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken: CancellationToken).ConfigureAwait(false);
            var qC          = ParseEcdhInit(initPayload);

            // 4. Compute the shared secret and the exchange hash, then sign it.
            using var kex  = SshKeyExchange.Create(negotiated.KeyExchange);
            var qS         = kex.PublicKey;
            var rawSecret  = kex.Agree(qC);
            var kMpint     = ExchangeHash.EncodeSharedSecretMPInt(rawSecret);

            var kS         = HostKey.PublicKeyBlob;
            var h          = ExchangeHash.Compute(kex.HashAlgorithm, vC, vS, iC, iS, kS, qC, qS, kMpint);
            var signature  = HostKey.Sign(negotiated.HostKey, h);

            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, BuildEcdhReply(kS, qS, signature), CancellationToken).ConfigureAwait(false);

            // 5. NEWKEYS + key derivation.
            var sessionId = h;
            await ExchangeNewKeysAsync(Pipe, CancellationToken).ConfigureAwait(false);

            var derive = MakeDeriver(kex.HashAlgorithm, kMpint, h, sessionId);
            var (sendCipher,    sendMac)    = BuildDirection(negotiated.CipherServerToClient, negotiated.MacServerToClient, derive, Kdf.KeyLetter.EncryptionKeyServerToClient, Kdf.KeyLetter.InitialIVServerToClient, Kdf.KeyLetter.IntegrityKeyServerToClient);
            var (receiveCipher, receiveMac) = BuildDirection(negotiated.CipherClientToServer, negotiated.MacClientToServer, derive, Kdf.KeyLetter.EncryptionKeyClientToServer, Kdf.KeyLetter.InitialIVClientToServer, Kdf.KeyLetter.IntegrityKeyClientToServer);

            return new SshTransportContext(sessionId, h, negotiated, kS, sendCipher, receiveCipher, sendMac, receiveMac);

        }

        #endregion


        #region (private) EnsureSupported(Negotiated)

        // Current support: curve25519-sha256 + ssh-ed25519 + (aes*-gcm | aes*-ctr with an -etm MAC).
        private static void EnsureSupported(NegotiatedAlgorithms Negotiated)
        {

            if (Negotiated.KeyExchange is not (SshAlgorithmNames.Kex.Curve25519Sha256       or
                                               SshAlgorithmNames.Kex.Curve25519Sha256LibSsh or
                                               SshAlgorithmNames.Kex.EcdhNistP256            or
                                               SshAlgorithmNames.Kex.EcdhNistP384            or
                                               SshAlgorithmNames.Kex.EcdhNistP521))
                throw new SshWireException($"Unsupported key exchange '{Negotiated.KeyExchange}' (supported: curve25519-sha256, ecdh-sha2-nistp256/384/521).");

            if (Negotiated.HostKey is not (SshAlgorithmNames.HostKey.Ed25519       or
                                           SshAlgorithmNames.HostKey.EcdsaNistP256 or
                                           SshAlgorithmNames.HostKey.EcdsaNistP384 or
                                           SshAlgorithmNames.HostKey.EcdsaNistP521 or
                                           SshAlgorithmNames.HostKey.RsaSha2_256   or
                                           SshAlgorithmNames.HostKey.RsaSha2_512))
                throw new SshWireException($"Unsupported host key '{Negotiated.HostKey}' (supported: ssh-ed25519, ecdsa-sha2-nistp256/384/521, rsa-sha2-256/512).");

            EnsureCipherSupported(Negotiated.CipherClientToServer, Negotiated.MacClientToServer);
            EnsureCipherSupported(Negotiated.CipherServerToClient, Negotiated.MacServerToClient);

        }

        private static void EnsureCipherSupported(String Cipher, String Mac)
        {

            var isGcm = Cipher is SshAlgorithmNames.Cipher.Aes256Gcm or SshAlgorithmNames.Cipher.Aes128Gcm;
            var isCtr = Cipher is SshAlgorithmNames.Cipher.Aes256Ctr or SshAlgorithmNames.Cipher.Aes192Ctr or SshAlgorithmNames.Cipher.Aes128Ctr;

            if (!isGcm && !isCtr)
                throw new SshWireException($"Unsupported cipher '{Cipher}' (supported: aes*-gcm@openssh.com, aes*-ctr).");

            if (isCtr && Mac is not (SshAlgorithmNames.Mac.HmacSha2_256Etm or SshAlgorithmNames.Mac.HmacSha2_512Etm))
                throw new SshWireException($"The CTR cipher '{Cipher}' requires an encrypt-then-MAC ('{Mac}' is not supported yet).");

        }

        #endregion

        #region (private) ExchangeNewKeysAsync(Pipe, CancellationToken)

        private static async ValueTask ExchangeNewKeysAsync(IDuplexPipe Pipe, CancellationToken CancellationToken)
        {

            await WritePacketAsync(Pipe.Output, NullTransportCipher.Instance, [ (Byte) SshMessageNumber.NewKeys ], CancellationToken).ConfigureAwait(false);

            var newKeys = await SshPacketFraming.ReadPacketAsync(Pipe.Input, NullTransportCipher.Instance, CancellationToken: CancellationToken).ConfigureAwait(false);

            if (newKeys.Length < 1 || newKeys[0] != (Byte) SshMessageNumber.NewKeys)
                throw new SshWireException("Expected SSH_MSG_NEWKEYS (21) to complete the key exchange!");

        }

        #endregion

        #region (private) MakeDeriver / BuildDirection / BuildMac

        // A closure that derives 'length' key bytes for a given key-derivation letter (RFC 4253 §7.2).
        private static Func<Byte, Int32, Byte[]> MakeDeriver(HashAlgorithmName HashAlgorithm, Byte[] SharedSecretMPInt, Byte[] H, Byte[] SessionId)
            => (letter, length) => Kdf.Derive(HashAlgorithm, SharedSecretMPInt, H, letter, SessionId, length);

        // Build the cipher (and, for CTR, the encrypt-then-MAC) for one direction from the negotiated names.
        private static (SshTransportCipher Cipher, ISshMac? Mac) BuildDirection(String                    CipherName,
                                                                                String                    MacName,
                                                                                Func<Byte, Int32, Byte[]> Derive,
                                                                                Byte                      KeyLetter,
                                                                                Byte                      IVLetter,
                                                                                Byte                      MacLetter)

            => CipherName switch {
                   SshAlgorithmNames.Cipher.Aes256Gcm => (new AesGcmTransportCipher(Derive(KeyLetter, 32), Derive(IVLetter, AesGcmTransportCipher.NonceLength)), null),
                   SshAlgorithmNames.Cipher.Aes128Gcm => (new AesGcmTransportCipher(Derive(KeyLetter, 16), Derive(IVLetter, AesGcmTransportCipher.NonceLength)), null),
                   SshAlgorithmNames.Cipher.Aes256Ctr => (new AesCtrTransportCipher(Derive(KeyLetter, 32), Derive(IVLetter, AesCtrTransportCipher.CounterLength)), BuildMac(MacName, Derive, MacLetter)),
                   SshAlgorithmNames.Cipher.Aes192Ctr => (new AesCtrTransportCipher(Derive(KeyLetter, 24), Derive(IVLetter, AesCtrTransportCipher.CounterLength)), BuildMac(MacName, Derive, MacLetter)),
                   SshAlgorithmNames.Cipher.Aes128Ctr => (new AesCtrTransportCipher(Derive(KeyLetter, 16), Derive(IVLetter, AesCtrTransportCipher.CounterLength)), BuildMac(MacName, Derive, MacLetter)),
                   _                                  => throw new SshWireException($"Unsupported cipher '{CipherName}'.")
               };

        private static ISshMac BuildMac(String MacName, Func<Byte, Int32, Byte[]> Derive, Byte MacLetter)
            => MacName switch {
                   SshAlgorithmNames.Mac.HmacSha2_256Etm => HmacSha2Mac.Sha256(Derive(MacLetter, 32)),
                   SshAlgorithmNames.Mac.HmacSha2_512Etm => HmacSha2Mac.Sha512(Derive(MacLetter, 64)),
                   _                                     => throw new SshWireException($"Unsupported MAC '{MacName}'.")
               };

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
