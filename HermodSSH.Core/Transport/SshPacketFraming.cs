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
using System.Buffers.Binary;
using System.Security.Cryptography;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>
    /// Frames and de-frames SSH binary packets (RFC 4253, section 6) over
    /// <see cref="System.IO.Pipelines"/>, delegating encryption/decryption to an
    /// <see cref="SshTransportCipher"/>. Handles the padding computation and defensive length checks.
    /// </summary>
    public static class SshPacketFraming
    {

        #region Data

        /// <summary>The largest accepted packet_length, bounding a peer's allocation demand.</summary>
        public const Int32 MaxPacketLength = 256 * 1024;

        /// <summary>The smallest sensible packet_length (1 padding_length byte + minimum 4 padding + margin).</summary>
        public const Int32 MinPacketLength = 8;

        #endregion


        #region ComputePaddingLength(PayloadLength, BlockSize, LengthIncludedInAlignment)

        /// <summary>
        /// Compute the padding length so the aligned region is a whole number of blocks, with at least
        /// 4 bytes of padding (RFC 4253, section 6).
        /// </summary>
        public static Byte ComputePaddingLength(Int32    PayloadLength,
                                                Int32    BlockSize,
                                                Boolean  LengthIncludedInAlignment)
        {

            var block     = Math.Max(BlockSize, 8);
            var unpadded  = (LengthIncludedInAlignment ? 4 : 0) + 1 + PayloadLength;
            var padding   = block - (unpadded % block);

            if (padding < 4)
                padding += block;

            return (Byte) padding;

        }

        #endregion

        #region WritePacket(Output, Cipher, Payload)

        /// <summary>
        /// Frame and encrypt one packet with the given payload, writing it to <paramref name="Output"/>
        /// (the caller flushes).
        /// </summary>
        /// <param name="Output">The destination buffer writer (e.g. a <see cref="PipeWriter"/>).</param>
        /// <param name="Cipher">The send cipher for the current direction.</param>
        /// <param name="Payload">The packet payload (the message).</param>
        public static void WritePacket(IBufferWriter<Byte>  Output,
                                       SshTransportCipher   Cipher,
                                       ReadOnlySpan<Byte>   Payload)
        {

            var paddingLength  = ComputePaddingLength(Payload.Length, Cipher.BlockSize, Cipher.LengthIncludedInPaddingAlignment);
            var packetLength   = 1 + Payload.Length + paddingLength;

            // Assemble the plaintext block: padding_length || payload || random padding.
            var plaintext = ArrayPool<Byte>.Shared.Rent(packetLength);
            try
            {

                plaintext[0] = paddingLength;
                Payload.CopyTo(plaintext.AsSpan(1));
                RandomNumberGenerator.Fill(plaintext.AsSpan(1 + Payload.Length, paddingLength));

                var output = Output.GetSpan(4 + packetLength + Cipher.TagLength);

                BinaryPrimitives.WriteUInt32BigEndian(output, (UInt32) packetLength);

                Cipher.Encrypt(
                    output[..4],
                    plaintext.AsSpan(0, packetLength),
                    output.Slice(4, packetLength + Cipher.TagLength)
                );

                Output.Advance(4 + packetLength + Cipher.TagLength);

            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext.AsSpan(0, packetLength));
                ArrayPool<Byte>.Shared.Return(plaintext);
            }

        }

        #endregion

        #region ReadPacketAsync(Input, Cipher, CancellationToken = default)

        /// <summary>
        /// Read, decrypt and authenticate one packet, returning its payload.
        /// </summary>
        /// <param name="Input">The source pipe reader.</param>
        /// <param name="Cipher">The receive cipher for the current direction.</param>
        /// <param name="CancellationToken">An optional cancellation token.</param>
        public static async ValueTask<Byte[]> ReadPacketAsync(PipeReader          Input,
                                                              SshTransportCipher  Cipher,
                                                              CancellationToken   CancellationToken = default)
        {

            // 1. The 4-byte packet_length is always plaintext for the M1 ciphers (none, aes-gcm).
            var lengthBytes   = await ReadExactAsync(Input, 4, CancellationToken).ConfigureAwait(false);
            var packetLength  = BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);

            if (packetLength < MinPacketLength || packetLength > MaxPacketLength)
                throw new SshWireException($"Illegal SSH packet_length {packetLength} (must be {MinPacketLength}..{MaxPacketLength})!");

            if (!Cipher.LengthIncludedInPaddingAlignment && packetLength % (UInt32) Cipher.BlockSize != 0)
                throw new SshWireException($"SSH packet_length {packetLength} is not a multiple of the {Cipher.BlockSize}-byte block size!");

            // 2. The encrypted region (packet_length bytes) plus the authentication tag.
            var body       = await ReadExactAsync(Input, (Int32) packetLength + Cipher.TagLength, CancellationToken).ConfigureAwait(false);

            var plaintext  = new Byte[packetLength];

            if (!Cipher.Decrypt(lengthBytes, body, plaintext))
                throw new SshWireException("SSH packet authentication failed (bad MAC/tag)!");

            var paddingLength = plaintext[0];
            var payloadLength = (Int32) packetLength - paddingLength - 1;

            if (paddingLength < 4 || payloadLength < 0)
                throw new SshWireException($"Illegal SSH padding_length {paddingLength} for packet_length {packetLength}!");

            return plaintext[1..(1 + payloadLength)];

        }

        #endregion


        #region (private) ReadExactAsync(Input, Count, CancellationToken)

        private static async ValueTask<Byte[]> ReadExactAsync(PipeReader         Input,
                                                              Int32              Count,
                                                              CancellationToken  CancellationToken)
        {

            while (true)
            {

                var result  = await Input.ReadAsync(CancellationToken).ConfigureAwait(false);
                var buffer  = result.Buffer;

                if (buffer.Length >= Count)
                {
                    var slice  = buffer.Slice(0, Count);
                    var bytes  = slice.ToArray();
                    Input.AdvanceTo(buffer.GetPosition(Count));
                    return bytes;
                }

                Input.AdvanceTo(buffer.Start, buffer.End);

                if (result.IsCompleted)
                    throw new SshWireException("The connection was closed in the middle of an SSH packet!");

            }

        }

        #endregion

    }

}
