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

    /// <summary>
    /// A public-key authentication request the server evaluates before verifying the signature: the login
    /// name, the offered signature algorithm and the SSH public-key blob (RFC 4252 §7).
    /// </summary>
    public sealed record SshPublicKeyAuthRequest(String  Username,
                                                 String  Algorithm,
                                                 Byte[]  PublicKeyBlob);


    /// <summary>The outcome of a successful user authentication.</summary>
    public sealed record SshAuthResult(String Username, String Method);


    /// <summary>
    /// The server-side authentication policy (RFC 4252): which methods are offered, and whether a given
    /// public key is acceptable for a user. Signature verification itself is done by the auth driver — an
    /// authenticator only decides <i>authorization</i> (is this key allowed for this account?).
    /// </summary>
    public interface ISshUserAuthenticator
    {

        /// <summary>The authentication methods offered to clients (RFC 4252 names), e.g. <c>publickey</c>.</summary>
        IReadOnlyList<String> OfferedMethods { get; }

        /// <summary>
        /// Whether the given public key is authorized for the user. Called first for the client's
        /// "query" (no signature) and again once the signature has been verified.
        /// </summary>
        ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest  Request,
                                                   CancellationToken        CancellationToken = default);

    }


    /// <summary>
    /// A minimal delegate-backed <see cref="ISshUserAuthenticator"/> for public-key authentication.
    /// </summary>
    public sealed class SshUserAuthenticator : ISshUserAuthenticator
    {

        #region Data

        private readonly Func<SshPublicKeyAuthRequest, CancellationToken, ValueTask<Boolean>> authorizePublicKey;

        #endregion

        #region Properties

        public IReadOnlyList<String> OfferedMethods { get; }

        #endregion

        #region Constructor(s)

        /// <summary>Create an authenticator from a public-key authorization callback.</summary>
        public SshUserAuthenticator(Func<SshPublicKeyAuthRequest, CancellationToken, ValueTask<Boolean>>  AuthorizePublicKey,
                                    IReadOnlyList<String>?                                                 OfferedMethods = null)
        {
            this.authorizePublicKey  = AuthorizePublicKey;
            this.OfferedMethods      = OfferedMethods ?? [ "publickey" ];
        }

        #endregion


        #region (static) ForAuthorizedKeys(AuthorizedKeyBlobs)

        /// <summary>
        /// An authenticator that accepts any user presenting one of the given public-key blobs (an
        /// in-memory <c>authorized_keys</c> equivalent, ignoring the login name).
        /// </summary>
        public static SshUserAuthenticator ForAuthorizedKeys(params Byte[][] AuthorizedKeyBlobs)
        {

            var authorized = AuthorizedKeyBlobs.ToArray();

            return new SshUserAuthenticator((request, _) =>
                ValueTask.FromResult(authorized.Any(blob => blob.AsSpan().SequenceEqual(request.PublicKeyBlob))));

        }

        #endregion

        #region AuthorizePublicKeyAsync(Request, CancellationToken)

        public ValueTask<Boolean> AuthorizePublicKeyAsync(SshPublicKeyAuthRequest  Request,
                                                          CancellationToken        CancellationToken = default)

            => authorizePublicKey(Request, CancellationToken);

        #endregion

    }

}
