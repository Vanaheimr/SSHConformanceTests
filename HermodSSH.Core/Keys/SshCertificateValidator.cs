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

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>The outcome of validating a certificate against a trust store.</summary>
    public sealed record SshCertificateValidation(Boolean IsValid, String? Reason)
    {
        /// <summary>A successful validation.</summary>
        public static readonly SshCertificateValidation Ok = new (true, null);
        /// <summary>A failed validation with a reason (for the audit log, never the wire).</summary>
        public static SshCertificateValidation Fail(String Reason) => new (false, Reason);
    }


    /// <summary>
    /// The set of certificate authorities a verifier trusts, plus a simple revocation list (serials, key
    /// ids and subject keys). The CA-trust equivalent of OpenSSH <c>TrustedUserCAKeys</c> / <c>@cert-authority</c>.
    /// </summary>
    public sealed class SshCertificateAuthorityTrust
    {

        private readonly List<Byte[]>     caKeys          = [];
        private readonly HashSet<UInt64>  revokedSerials  = [];
        private readonly HashSet<String>  revokedKeyIds   = [];
        private readonly List<Byte[]>     revokedKeys     = [];

        /// <summary>Trust a CA public key (its wire blob).</summary>
        public SshCertificateAuthorityTrust TrustCA(Byte[] CaPublicKeyBlob) { caKeys.Add(CaPublicKeyBlob); return this; }

        /// <summary>Trust a CA signing key.</summary>
        public SshCertificateAuthorityTrust TrustCA(ISshHostKey CaKey) => TrustCA(CaKey.PublicKeyBlob);

        /// <summary>Revoke a certificate by serial number.</summary>
        public SshCertificateAuthorityTrust RevokeSerial(UInt64 Serial) { revokedSerials.Add(Serial); return this; }

        /// <summary>Revoke all certificates with a given key id.</summary>
        public SshCertificateAuthorityTrust RevokeKeyId(String KeyId) { revokedKeyIds.Add(KeyId); return this; }

        /// <summary>Revoke a specific subject public key (its wire blob).</summary>
        public SshCertificateAuthorityTrust RevokeKey(Byte[] SubjectPublicKeyBlob) { revokedKeys.Add(SubjectPublicKeyBlob); return this; }

        /// <summary>Whether the given CA key blob is trusted.</summary>
        public Boolean IsCaTrusted(Byte[] CaPublicKeyBlob)
            => caKeys.Any(k => k.AsSpan().SequenceEqual(CaPublicKeyBlob));

        /// <summary>Whether the certificate is on the revocation list (by serial, key id or subject key).</summary>
        public Boolean IsRevoked(SshCertificate Certificate)
            => revokedSerials.Contains(Certificate.Serial) ||
               revokedKeyIds.Contains(Certificate.KeyId)   ||
               revokedKeys.Any(k => k.AsSpan().SequenceEqual(Certificate.SubjectPublicKey));

    }


    /// <summary>
    /// Validates OpenSSH certificates following the mandatory check order (PLAN.md §6): type, CA trust,
    /// CA signature, validity window, principals, critical options and revocation. The subject's own
    /// signature over the authentication/exchange data is verified separately (by the auth or transport layer).
    /// </summary>
    public static class SshCertificateValidator
    {

        /// <summary>
        /// Critical options we both recognise <b>and enforce</b>; anything else must cause rejection
        /// (PROTOCOL.certkeys: "critical options … must be understood, or the certificate is refused").
        ///
        /// <para>
        /// This set is deliberately <b>empty</b>. "Understood" has to mean enforced: listing an option
        /// here without acting on it would turn a CA's restriction into a silent no-op — a certificate
        /// issued as <c>force-command="/usr/bin/backup-only"</c> would be accepted and the holder would
        /// then run any command at all, which is worse than refusing the certificate outright. Until
        /// <c>force-command</c> and <c>source-address</c> are actually applied to the session, a
        /// certificate carrying them is rejected. Add a name here only together with its enforcement.
        /// </para>
        /// </summary>
        private static readonly HashSet<String> KnownCriticalOptions =
            new (StringComparer.Ordinal);


        #region Validate(Certificate, ExpectedType, Principal, Trust, Now)

        /// <summary>Validate a certificate for a principal against the trust store at a given instant.</summary>
        public static SshCertificateValidation Validate(SshCertificate                Certificate,
                                                        SshCertType                   ExpectedType,
                                                        String                        Principal,
                                                        SshCertificateAuthorityTrust  Trust,
                                                        DateTimeOffset                Now)
        {

            // 2. Type must match (a host cert must not authenticate a user, and vice versa).
            if (Certificate.Type != ExpectedType)
                return SshCertificateValidation.Fail($"certificate type {Certificate.Type} does not match expected {ExpectedType}");

            // 3. The CA key must be trusted and must not itself be a certificate.
            if (CaIsCertificate(Certificate.SignatureKey))
                return SshCertificateValidation.Fail("the CA key is itself a certificate");

            if (!Trust.IsCaTrusted(Certificate.SignatureKey))
                return SshCertificateValidation.Fail("the signing CA is not trusted");

            // 4. The CA signature over the certificate must be valid.
            if (!Certificate.VerifyCaSignature())
                return SshCertificateValidation.Fail("the CA signature is invalid");

            // 5. The validity window must contain now.
            if (Now < Certificate.ValidAfter)
                return SshCertificateValidation.Fail("the certificate is not yet valid");
            if (Now >= Certificate.ValidBefore)
                return SshCertificateValidation.Fail("the certificate has expired");

            // 6. The principal must be listed (an empty principal list means "valid for all").
            if (Certificate.Principals.Count > 0 && !Certificate.Principals.Contains(Principal, StringComparer.Ordinal))
                return SshCertificateValidation.Fail($"'{Principal}' is not a valid principal for this certificate");

            // 7. Every critical option must be understood.
            foreach (var option in Certificate.CriticalOptions)
                if (!KnownCriticalOptions.Contains(option.Key))
                    return SshCertificateValidation.Fail($"unknown critical option '{option.Key}'");

            // 8. The certificate must not be revoked.
            if (Trust.IsRevoked(Certificate))
                return SshCertificateValidation.Fail("the certificate has been revoked");

            return SshCertificateValidation.Ok;

        }

        #endregion

        #region (private) CaIsCertificate(SignatureKey)

        private static Boolean CaIsCertificate(Byte[] SignatureKey)
        {
            try
            {
                var reader = new SshPacketReader(SignatureKey);
                return SshCertificate.IsCertificateAlgorithm(reader.ReadString());
            }
            catch
            {
                return true;   // unreadable ⇒ treat as invalid CA
            }
        }

        #endregion

    }

}
