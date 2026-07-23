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
    /// One ephemeral key-exchange instance for an ECDH-style method: it generates a fresh ephemeral
    /// key pair, exposes the public value Q to send to the peer, and computes the raw shared secret
    /// from the peer's Q. The associated hash (SHA-256/384/512) is used both for the exchange hash and
    /// for the key derivation.
    /// </summary>
    public abstract class SshKeyExchange : IDisposable
    {

        /// <summary>The wire name of the key exchange method.</summary>
        public abstract String             Name           { get; }

        /// <summary>The hash used for the exchange hash H and the key derivation.</summary>
        public abstract HashAlgorithmName  HashAlgorithm  { get; }

        /// <summary>Our ephemeral public value Q (Q_C on the client, Q_S on the server).</summary>
        public abstract Byte[]             PublicKey      { get; }

        /// <summary>
        /// Compute the raw shared secret from the peer's public value. The result is interpreted as an
        /// unsigned big-endian integer and encoded as an SSH mpint by the caller.
        /// </summary>
        public abstract Byte[] Agree(ReadOnlySpan<Byte> PeerPublicKey);


        /// <summary>
        /// Create a fresh ephemeral key exchange for the given negotiated method name.
        /// </summary>
        public static SshKeyExchange Create(String Name)

            => Name switch {
                   SshAlgorithmNames.Kex.Curve25519Sha256       or
                   SshAlgorithmNames.Kex.Curve25519Sha256LibSsh => new Curve25519KeyExchange(),
                   SshAlgorithmNames.Kex.EcdhNistP256           => new NistEcdhKeyExchange(ECCurve.NamedCurves.nistP256, HashAlgorithmName.SHA256, SshAlgorithmNames.Kex.EcdhNistP256),
                   SshAlgorithmNames.Kex.EcdhNistP384           => new NistEcdhKeyExchange(ECCurve.NamedCurves.nistP384, HashAlgorithmName.SHA384, SshAlgorithmNames.Kex.EcdhNistP384),
                   SshAlgorithmNames.Kex.EcdhNistP521           => new NistEcdhKeyExchange(ECCurve.NamedCurves.nistP521, HashAlgorithmName.SHA512, SshAlgorithmNames.Kex.EcdhNistP521),
                   _                                            => throw new SshWireException($"Unsupported key exchange '{Name}'.")
               };


        /// <summary>Release any key material.</summary>
        public virtual void Dispose()
            => GC.SuppressFinalize(this);

    }


    /// <summary>
    /// The <c>curve25519-sha256</c> key exchange (RFC 8731): X25519 with SHA-256.
    /// </summary>
    public sealed class Curve25519KeyExchange : SshKeyExchange
    {

        private readonly X25519KeyPair keyPair = X25519KeyPair.Generate();

        public override String             Name           => SshAlgorithmNames.Kex.Curve25519Sha256;
        public override HashAlgorithmName  HashAlgorithm  => HashAlgorithmName.SHA256;
        public override Byte[]             PublicKey      => keyPair.PublicKey;

        public override Byte[] Agree(ReadOnlySpan<Byte> PeerPublicKey)
            => keyPair.Agree(PeerPublicKey);

    }


    /// <summary>
    /// The <c>ecdh-sha2-nistp256/384/521</c> key exchanges (RFC 5656): ECDH over a NIST prime curve,
    /// with the public value sent as an uncompressed EC point (0x04 || X || Y) and the shared secret
    /// being the X coordinate of the shared point.
    /// </summary>
    public sealed class NistEcdhKeyExchange : SshKeyExchange
    {

        #region Data

        private readonly ECDiffieHellman  ecdh;
        private readonly ECCurve          curve;
        private readonly Int32            fieldSize;
        private readonly Byte[]           publicKey;

        #endregion

        #region Properties

        public override String             Name           { get; }
        public override HashAlgorithmName  HashAlgorithm  { get; }
        public override Byte[]             PublicKey      => publicKey;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create a fresh ECDH key exchange over the given NIST curve.
        /// </summary>
        public NistEcdhKeyExchange(ECCurve Curve, HashAlgorithmName HashAlgorithm, String Name)
        {

            this.curve          = Curve;
            this.Name           = Name;
            this.HashAlgorithm  = HashAlgorithm;
            this.ecdh           = ECDiffieHellman.Create(Curve);

            var parameters      = ecdh.PublicKey.ExportParameters();
            this.fieldSize      = parameters.Q.X!.Length;

            // Uncompressed EC point: 0x04 || X || Y (both field-size big-endian).
            this.publicKey      = new Byte[1 + (2 * fieldSize)];
            this.publicKey[0]   = 0x04;
            parameters.Q.X!.CopyTo(publicKey, 1);
            parameters.Q.Y!.CopyTo(publicKey, 1 + fieldSize);

        }

        #endregion


        #region Agree(PeerPublicKey)

        public override Byte[] Agree(ReadOnlySpan<Byte> PeerPublicKey)
        {

            if (PeerPublicKey.Length != 1 + (2 * fieldSize) || PeerPublicKey[0] != 0x04)
                throw new SshWireException($"Invalid EC public point for {Name} (expected an uncompressed 0x04 point of {1 + 2 * fieldSize} bytes).");

            var peerParameters = new ECParameters {
                                     Curve = curve,
                                     Q     = new ECPoint {
                                                 X = PeerPublicKey.Slice(1,             fieldSize).ToArray(),
                                                 Y = PeerPublicKey.Slice(1 + fieldSize, fieldSize).ToArray()
                                             }
                                 };

            // Validates the point is on the curve; then derive the raw shared X coordinate.
            using var peerKey = ECDiffieHellman.Create(peerParameters);
            return ecdh.DeriveRawSecretAgreement(peerKey.PublicKey);

        }

        #endregion

        #region Dispose()

        public override void Dispose()
        {
            ecdh.Dispose();
            base.Dispose();
        }

        #endregion

    }

}
