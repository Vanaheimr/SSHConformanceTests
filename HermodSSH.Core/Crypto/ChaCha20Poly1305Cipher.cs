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
using System.Buffers.Binary;
using System.Security.Cryptography;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>
    /// The <c>chacha20-poly1305@openssh.com</c> AEAD cipher (OpenSSH <c>PROTOCOL.chacha20poly1305</c>).
    /// Unlike RFC 8439, this is OpenSSH's own construction: 64 bytes of key material split into two
    /// 32-byte ChaCha20 keys — <c>K_main</c> (payload + Poly1305 key) and <c>K_header</c> (the 4-byte
    /// packet length). The nonce is the packet sequence number; the length field is encrypted separately
    /// (so it can be decrypted before the rest) and both the encrypted length and payload are
    /// Poly1305-authenticated. The BouncyCastle primitives arrive via the Hermod/Styx submodules.
    /// </summary>
    /// <remarks>
    /// The binary packet framing special-cases this cipher (via <see cref="EncryptPacketInto"/>,
    /// <see cref="DecryptLength"/> and <see cref="DecryptAndVerify"/>) because the length field is
    /// encrypted, unlike the AEAD/CTR ciphers where it is plaintext.
    /// </remarks>
    public sealed class ChaCha20Poly1305Cipher : SshTransportCipher
    {

        #region Data

        /// <summary>The required key length in bytes (two 32-byte ChaCha20 keys).</summary>
        public const Int32  KeyLength   = 64;

        /// <summary>The Poly1305 tag length in bytes.</summary>
        public const Int32  TagLen      = 16;

        private readonly KeyParameter  mainKey;     // key[0..32]  — payload + Poly1305 key
        private readonly KeyParameter  headerKey;   // key[32..64] — the 4-byte packet length

        #endregion

        #region Properties

        public override Int32    BlockSize                          => 8;
        public override Int32    TagLength                          => TagLen;
        public override Boolean  LengthIncludedInPaddingAlignment   => false;

        #endregion

        #region Constructor(s)

        /// <summary>Create a ChaCha20-Poly1305 cipher for one direction from 64 bytes of key material.</summary>
        public ChaCha20Poly1305Cipher(ReadOnlySpan<Byte> Key)
        {

            if (Key.Length != KeyLength)
                throw new ArgumentException($"A chacha20-poly1305@openssh.com key must be {KeyLength} bytes!", nameof(Key));

            this.mainKey    = new KeyParameter(Key[..32].ToArray());
            this.headerKey  = new KeyParameter(Key[32..].ToArray());

        }

        #endregion


        #region (private) Nonce(SequenceNumber) / ChaCha(...)

        // The nonce is the 64-bit big-endian sequence number.
        private static Byte[] Nonce(UInt32 SequenceNumber)
        {
            var nonce = new Byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(nonce, SequenceNumber);
            return nonce;
        }

        private static ChaChaEngine ChaCha(KeyParameter Key, Byte[] Nonce)
        {
            var engine = new ChaChaEngine();   // ChaCha20 (20 rounds), 8-byte nonce
            engine.Init(true, new ParametersWithIV(Key, Nonce));
            return engine;
        }

        // Derive the Poly1305 one-time key: the first 32 bytes of the main keystream at block counter 0.
        // Processing the whole 64-byte block-0 also advances the engine to block counter 1 for the payload.
        private static Byte[] DerivePoly1305Key(ChaChaEngine MainEngine)
        {
            var block = new Byte[64];
            MainEngine.ProcessBytes(block, 0, 64, block, 0);
            var polyKey = new Byte[32];
            Array.Copy(block, polyKey, 32);
            return polyKey;
        }

        private static Byte[] Poly1305Tag(Byte[] PolyKey, ReadOnlySpan<Byte> EncryptedLength, ReadOnlySpan<Byte> Ciphertext)
        {
            var poly = new Poly1305();
            poly.Init(new KeyParameter(PolyKey));
            poly.BlockUpdate(EncryptedLength);
            poly.BlockUpdate(Ciphertext);
            var tag = new Byte[TagLen];
            poly.DoFinal(tag, 0);
            return tag;
        }

        #endregion


        #region EncryptPacketInto(SequenceNumber, Payload, Output)

        /// <summary>
        /// Frame and encrypt one packet: writes the encrypted length (4), the encrypted
        /// <c>padding_length || payload || padding</c>, and the 16-byte Poly1305 tag.
        /// </summary>
        public void EncryptPacketInto(UInt32 SequenceNumber, ReadOnlySpan<Byte> Payload, IBufferWriter<Byte> Output)
        {

            // Padding: align (padding_length || payload || padding) to the 8-byte block, at least 4 bytes.
            var paddingLength  = 8 - ((1 + Payload.Length) % 8);
            if (paddingLength < 4)
                paddingLength += 8;
            var packetLength   = 1 + Payload.Length + paddingLength;

            var nonce          = Nonce(SequenceNumber);

            var plaintext = ArrayPool<Byte>.Shared.Rent(packetLength);
            try
            {

                plaintext[0] = (Byte) paddingLength;
                Payload.CopyTo(plaintext.AsSpan(1));
                RandomNumberGenerator.Fill(plaintext.AsSpan(1 + Payload.Length, paddingLength));

                var output = Output.GetSpan(4 + packetLength + TagLen);

                // Encrypted length (header key).
                Span<Byte> lengthBytes = stackalloc Byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(lengthBytes, (UInt32) packetLength);
                var headerEngine  = ChaCha(headerKey, nonce);
                var encryptedLen  = new Byte[4];
                headerEngine.ProcessBytes(lengthBytes.ToArray(), 0, 4, encryptedLen, 0);
                encryptedLen.CopyTo(output);

                // Poly1305 key + encrypted payload (main key, counter 0 then 1).
                var mainEngine  = ChaCha(mainKey, nonce);
                var polyKey     = DerivePoly1305Key(mainEngine);
                var ciphertext  = new Byte[packetLength];
                mainEngine.ProcessBytes(plaintext, 0, packetLength, ciphertext, 0);
                ciphertext.CopyTo(output.Slice(4, packetLength));

                // Poly1305 tag over the encrypted length and the ciphertext.
                var tag = Poly1305Tag(polyKey, output[..4], ciphertext);
                tag.CopyTo(output.Slice(4 + packetLength, TagLen));

                Output.Advance(4 + packetLength + TagLen);

            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, packetLength));
                ArrayPool<Byte>.Shared.Return(plaintext);
            }

        }

        #endregion

        #region DecryptLength(SequenceNumber, EncryptedLength)

        /// <summary>Decrypt the 4-byte packet length field (header key) so the caller can read the rest.</summary>
        public UInt32 DecryptLength(UInt32 SequenceNumber, ReadOnlySpan<Byte> EncryptedLength)
        {
            var headerEngine  = ChaCha(headerKey, Nonce(SequenceNumber));
            var lengthBytes   = new Byte[4];
            headerEngine.ProcessBytes(EncryptedLength.ToArray(), 0, 4, lengthBytes, 0);
            return BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);
        }

        #endregion

        #region DecryptAndVerify(SequenceNumber, EncryptedLength, CiphertextAndTag)

        /// <summary>
        /// Verify the Poly1305 tag and decrypt the payload block, returning
        /// <c>padding_length || payload || padding</c> (the caller strips the padding).
        /// </summary>
        public Byte[] DecryptAndVerify(UInt32 SequenceNumber, ReadOnlySpan<Byte> EncryptedLength, ReadOnlySpan<Byte> CiphertextAndTag)
        {

            var packetLength  = CiphertextAndTag.Length - TagLen;
            var ciphertext    = CiphertextAndTag[..packetLength];
            var receivedTag   = CiphertextAndTag[packetLength..];

            var mainEngine    = ChaCha(mainKey, Nonce(SequenceNumber));
            var polyKey       = DerivePoly1305Key(mainEngine);

            var expectedTag   = Poly1305Tag(polyKey, EncryptedLength, ciphertext);
            if (!CryptographicOperations.FixedTimeEquals(expectedTag, receivedTag))
                throw new SshWireException("SSH chacha20-poly1305 authentication failed (bad Poly1305 tag)!");

            var plaintext = new Byte[packetLength];
            mainEngine.ProcessBytes(ciphertext.ToArray(), 0, packetLength, plaintext, 0);
            return plaintext;

        }

        #endregion


        #region (unused) Encrypt / Decrypt

        // This cipher is handled directly by the packet framing (the length field is encrypted, so the
        // generic length-plaintext path does not apply); these members are never called.
        public override void Encrypt(ReadOnlySpan<Byte> LengthBytes, ReadOnlySpan<Byte> Plaintext, Span<Byte> Output)
            => throw new NotSupportedException("chacha20-poly1305 is framed directly by SshPacketFraming.");

        public override Boolean Decrypt(ReadOnlySpan<Byte> LengthBytes, ReadOnlySpan<Byte> Input, Span<Byte> Plaintext)
            => throw new NotSupportedException("chacha20-poly1305 is framed directly by SshPacketFraming.");

        #endregion

    }

}
