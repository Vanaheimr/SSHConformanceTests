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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>
    /// The <c>aes256-ctr</c> / <c>aes192-ctr</c> / <c>aes128-ctr</c> stream cipher (RFC 4344), built on
    /// the BCL AES-ECB transform: each 16-byte counter block is AES-encrypted to produce keystream that
    /// is XORed with the data. Not authenticating on its own — always paired with a separate
    /// <see cref="ISshMac"/> in encrypt-then-MAC mode.
    /// </summary>
    /// <remarks>
    /// Directional and stateful: the 128-bit counter (seeded from the KDF IV) advances by one per block.
    /// </remarks>
    public sealed class AesCtrTransportCipher : SshTransportCipher
    {

        #region Data

        /// <summary>The AES block / counter size in bytes.</summary>
        public const Int32  CounterLength = 16;

        private readonly Aes     aes;
        private readonly Byte[]  counter;
        private readonly Byte[]  keystream;
        private          Int32   keystreamPosition;

        #endregion

        #region Properties

        public override Int32    BlockSize                          => 16;
        public override Int32    TagLength                          => 0;
        // Encrypt-then-MAC: the packet_length is sent in the clear, so it is excluded from the alignment.
        public override Boolean  LengthIncludedInPaddingAlignment   => false;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create an AES-CTR cipher for one direction.
        /// </summary>
        /// <param name="Key">The 16-, 24- or 32-byte AES key (from the KDF).</param>
        /// <param name="InitialCounter">The 16-byte initial counter / IV (from the KDF).</param>
        public AesCtrTransportCipher(ReadOnlySpan<Byte>  Key,
                                     ReadOnlySpan<Byte>  InitialCounter)
        {

            if (Key.Length is not 16 and not 24 and not 32)
                throw new ArgumentException("An AES key must be 16, 24 or 32 bytes!", nameof(Key));

            if (InitialCounter.Length != CounterLength)
                throw new ArgumentException($"An AES-CTR counter must be {CounterLength} bytes!", nameof(InitialCounter));

            this.aes                = Aes.Create();
            this.aes.Mode           = CipherMode.ECB;
            this.aes.Padding        = PaddingMode.None;
            this.aes.Key            = Key.ToArray();

            this.counter            = InitialCounter.ToArray();
            this.keystream          = new Byte[CounterLength];
            this.keystreamPosition  = CounterLength;   // force a fresh keystream block on first use

        }

        #endregion


        #region Encrypt / Decrypt (CTR is symmetric)

        public override void Encrypt(ReadOnlySpan<Byte>  LengthBytes,
                                     ReadOnlySpan<Byte>  Plaintext,
                                     Span<Byte>          Output)

            => Process(Plaintext, Output);

        public override Boolean Decrypt(ReadOnlySpan<Byte>  LengthBytes,
                                        ReadOnlySpan<Byte>  Input,
                                        Span<Byte>          Plaintext)
        {
            Process(Input, Plaintext);
            return true;   // authentication is done by the paired MAC, not here
        }

        #endregion

        #region (private) Process(Input, Output)

        private void Process(ReadOnlySpan<Byte> Input, Span<Byte> Output)
        {

            for (var i = 0; i < Input.Length; i++)
            {

                if (keystreamPosition == CounterLength)
                {
                    aes.EncryptEcb(counter, keystream, PaddingMode.None);
                    IncrementCounter();
                    keystreamPosition = 0;
                }

                Output[i] = (Byte) (Input[i] ^ keystream[keystreamPosition++]);

            }

        }

        #endregion

        #region (private) IncrementCounter()

        // Increment the 128-bit big-endian counter by one.
        private void IncrementCounter()
        {
            for (var i = CounterLength - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
            }
        }

        #endregion

        #region Dispose()

        public override void Dispose()
        {
            aes.Dispose();
            CryptographicOperations.ZeroMemory(counter);
            CryptographicOperations.ZeroMemory(keystream);
            base.Dispose();
        }

        #endregion

    }

}
