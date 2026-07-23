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

using System.Numerics;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Unit tests for the classic finite-field Diffie-Hellman key exchange
    /// (diffie-hellman-group14-sha256 / group16-sha512, RFC 3526 MODP groups).
    /// </summary>
    [TestFixture]
    public class DiffieHellmanKeyExchangeTests
    {

        #region BothSides_DeriveTheSameSharedSecret

        [TestCase(SshAlgorithmNames.Kex.DhGroup14Sha256)]
        [TestCase(SshAlgorithmNames.Kex.DhGroup16Sha512)]
        public void BothSides_DeriveTheSameSharedSecret(String Kex)
        {

            using var alice = SshKeyExchange.Create(Kex);
            using var bob   = SshKeyExchange.Create(Kex);

            // e and f exchanged; each derives K from the other's public value.
            var aliceSecret = alice.Agree(bob.PublicKey);
            var bobSecret   = bob.Agree(alice.PublicKey);

            Assert.That(aliceSecret, Is.EqualTo(bobSecret));
            Assert.That(aliceSecret, Is.Not.Empty);

        }

        #endregion

        #region PublicValue_IsAPositiveMPIntBelowThePrime

        [TestCase(SshAlgorithmNames.Kex.DhGroup14Sha256)]
        [TestCase(SshAlgorithmNames.Kex.DhGroup16Sha512)]
        public void PublicValue_IsAPositiveMPIntBelowThePrime(String Kex)
        {

            using var kex = SshKeyExchange.Create(Kex);

            // The mpint content bytes must decode (unsigned) to a value in the open interval (1, p-1).
            var e     = new BigInteger(kex.PublicKey, isUnsigned: true, isBigEndian: true);
            var prime = Kex == SshAlgorithmNames.Kex.DhGroup14Sha256
                            ? DiffieHellmanKeyExchange.Group14Prime
                            : DiffieHellmanKeyExchange.Group16Prime;

            Assert.Multiple(() => {
                Assert.That(e > BigInteger.One,       Is.True, "e must be > 1.");
                Assert.That(e < prime - BigInteger.One, Is.True, "e must be < p-1.");
                // Signed big-endian encoding of a positive number never has its top bit set.
                Assert.That((kex.PublicKey[0] & 0x80), Is.Zero, "The mpint content must encode a positive value.");
            });

        }

        #endregion

        #region Agree_RejectsDegeneratePeerValues

        [Test]
        public void Agree_RejectsDegeneratePeerValues()
        {

            using var kex = SshKeyExchange.Create(SshAlgorithmNames.Kex.DhGroup14Sha256);

            var p        = DiffieHellmanKeyExchange.Group14Prime;
            var one      = new Byte[] { 0x01 };
            var pMinus1  = (p - BigInteger.One).ToByteArray(isUnsigned: true, isBigEndian: true);
            var pValue   = p.ToByteArray(isUnsigned: true, isBigEndian: true);

            Assert.Multiple(() => {
                Assert.That(() => kex.Agree(Array.Empty<Byte>()), Throws.TypeOf<SshWireException>());  // 0
                Assert.That(() => kex.Agree(one),                 Throws.TypeOf<SshWireException>());  // 1
                Assert.That(() => kex.Agree(pMinus1),             Throws.TypeOf<SshWireException>());  // p-1
                Assert.That(() => kex.Agree(pValue),              Throws.TypeOf<SshWireException>());  // p
            });

        }

        #endregion

        #region Group_PrimesMatchRfc3526BitLengths

        [Test]
        public void Group_PrimesMatchRfc3526BitLengths()
        {
            Assert.Multiple(() => {
                Assert.That(DiffieHellmanKeyExchange.Group14Prime.GetBitLength(), Is.EqualTo(2048));
                Assert.That(DiffieHellmanKeyExchange.Group16Prime.GetBitLength(), Is.EqualTo(4096));
                Assert.That(DiffieHellmanKeyExchange.Group14Prime.Sign, Is.EqualTo(1));
                Assert.That(DiffieHellmanKeyExchange.Group16Prime.Sign, Is.EqualTo(1));
            });
        }

        #endregion

    }

}
