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

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Certificates issued by our mini-CA for the interop peers, valid for an hour either side of now,
    /// and the OpenSSH text forms the peers read them in.
    /// </summary>
    internal static class InteropCertificates
    {

        /// <summary>
        /// A user certificate for <paramref name="Key"/>, signed by <paramref name="CA"/>, with OpenSSH's
        /// default extensions (the builder's default for a user certificate).
        /// </summary>
        public static CertifiedKey User(ISshHostKey Key, ISshHostKey CA, params String[] Principals)
            => new (Key, Builder(SshCertType.User, "issued-by-hermod-for-a-user", Principals).Sign(Key.PublicKeyBlob, CA));

        /// <summary>
        /// A host certificate for <paramref name="Key"/>, signed by <paramref name="CA"/>.
        /// </summary>
        public static CertifiedKey Host(ISshHostKey Key, ISshHostKey CA, params String[] Principals)
            => new (Key, Builder(SshCertType.Host, "issued-by-hermod-for-a-host", Principals).Sign(Key.PublicKeyBlob, CA));

        /// <summary>
        /// The certificate as OpenSSH writes it to <c>*-cert.pub</c>: algorithm, base64 blob, comment.
        /// </summary>
        public static String CertificateLine(CertifiedKey Certified)
            => $"{Certified.AlgorithmNames[0]} {Convert.ToBase64String(Certified.PublicKeyBlob)} issued-by-hermod";

        /// <summary>
        /// A public key as OpenSSH writes it: algorithm and base64 blob.
        /// </summary>
        public static String PublicKeyLine(ISshHostKey Key)
            => $"{Key.AlgorithmNames[0]} {Convert.ToBase64String(Key.PublicKeyBlob)}";

        private static OpenSshCertificateBuilder Builder(SshCertType Type, String KeyId, String[] Principals)
            => new () {
                   Serial       = 1,
                   Type         = Type,
                   KeyId        = KeyId,
                   Principals   = Principals,
                   ValidAfter   = TimeProvider.System.GetUtcNow().AddHours(-1),
                   ValidBefore  = TimeProvider.System.GetUtcNow().AddHours(1)
               };

    }

}
