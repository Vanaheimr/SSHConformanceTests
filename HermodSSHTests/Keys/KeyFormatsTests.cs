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

using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// M4 key formats: fingerprints, the authorized_keys/.pub and RFC 4716 public formats, and the
    /// openssh-key-v1 private format — round-tripped in-process (interop with ssh-keygen is separate).
    /// </summary>
    [TestFixture]
    public class KeyFormatsTests
    {

        private static readonly String[] KeyTypes =
            [ "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp521", "ssh-rsa" ];


        #region Fingerprint_Formats

        [Test]
        public void Fingerprint_Formats()
        {

            var key   = SshHostKey.GenerateEd25519();
            var sha   = SshFingerprint.Sha256(key.PublicKeyBlob);
            var md5   = SshFingerprint.Md5(key.PublicKeyBlob);

            Assert.Multiple(() => {
                Assert.That(sha, Does.StartWith("SHA256:"));
                Assert.That(sha, Does.Not.EndWith("="));                       // unpadded
                Assert.That(md5, Does.StartWith("MD5:"));
                Assert.That(SshFingerprint.Matches(key.PublicKeyBlob, sha), Is.True);
                Assert.That(SshFingerprint.Matches(key.PublicKeyBlob, md5), Is.True);
                Assert.That(SshFingerprint.Matches(key.PublicKeyBlob, "SHA256:AAAA"), Is.False);
            });

        }

        #endregion

        #region PublicKey_AuthorizedKeyLine_RoundTrip

        [TestCaseSource(nameof(KeyTypes))]
        public void PublicKey_AuthorizedKeyLine_RoundTrip(String KeyType)
        {

            var key   = SshKeyGenerator.Generate(KeyType);
            var pub   = SshPublicKey.FromHostKey(key, "user@host");

            var line    = pub.ToAuthorizedKeyLine();
            var parsed  = SshPublicKey.Parse(line);

            Assert.Multiple(() => {
                Assert.That(parsed.Blob,       Is.EqualTo(key.PublicKeyBlob));
                Assert.That(parsed.Comment,    Is.EqualTo("user@host"));
                Assert.That(parsed.Algorithm,  Is.EqualTo(pub.Algorithm));
            });

        }

        #endregion

        #region PublicKey_Rfc4716_RoundTrip

        [TestCaseSource(nameof(KeyTypes))]
        public void PublicKey_Rfc4716_RoundTrip(String KeyType)
        {

            var key   = SshKeyGenerator.Generate(KeyType);
            var pub   = SshPublicKey.FromHostKey(key, "an rfc4716 comment");

            var parsed = SshPublicKey.ParseRfc4716(pub.ToRfc4716());

            Assert.Multiple(() => {
                Assert.That(parsed.Blob,    Is.EqualTo(key.PublicKeyBlob));
                Assert.That(parsed.Comment, Is.EqualTo("an rfc4716 comment"));
            });

        }

        #endregion

        #region OpenSshPrivateKey_RoundTrip_SignsCorrectly

        [TestCaseSource(nameof(KeyTypes))]
        public void OpenSshPrivateKey_RoundTrip_SignsCorrectly(String KeyType)
        {

            var key  = SshKeyGenerator.Generate(KeyType);
            var pem  = OpenSshPrivateKey.Format(key, "round-trip");

            Assert.That(pem, Does.StartWith("-----BEGIN OPENSSH PRIVATE KEY-----"));

            var loaded = OpenSshPrivateKey.Parse(pem);

            // The reconstructed key must have the same public blob and produce a valid signature.
            var data       = RandomNumberGenerator.GetBytes(96);
            var algorithm  = loaded.Key.AlgorithmNames[0];
            var signature  = loaded.Key.Sign(algorithm, data);

            Assert.Multiple(() => {
                Assert.That(loaded.Key.PublicKeyBlob, Is.EqualTo(key.PublicKeyBlob));
                Assert.That(loaded.Comment,           Is.EqualTo("round-trip"));
                Assert.That(SshSignature.Verify(loaded.Key.PublicKeyBlob, data, signature), Is.True);
            });

        }

        #endregion

        #region WriteKeyPairAsync_LocksDownThePrivateKey

        /// <summary>
        /// The private key we write must be readable by its owner only — OpenSSH refuses a key that
        /// anybody else can read, which is what broke <c>ssh-keygen -y</c> on our written keys. The
        /// public <c>.pub</c> file, by contrast, stays freely readable.
        /// </summary>
        [Test]
        [CancelAfter(15000)]
        public async Task WriteKeyPairAsync_LocksDownThePrivateKey(CancellationToken CancellationToken)
        {

            var key  = SshHostKey.GenerateEd25519();
            var path = Path.Combine(Path.GetTempPath(), "hermod_perm_" + Guid.NewGuid().ToString("N"));

            try
            {

                await SshKeyGenerator.WriteKeyPairAsync(key, path, "perm-test", CancellationToken);

                if (OperatingSystem.IsWindows())
                {
                    var security = new FileInfo(path).GetAccessControl();
                    var rules    = security.GetAccessRules(true, true, typeof(SecurityIdentifier));
                    var owner    = WindowsIdentity.GetCurrent().User!;

                    Assert.Multiple(() => {
                        Assert.That(security.AreAccessRulesProtected, Is.True,
                                    "the private key's DACL must not inherit permissions");
                        Assert.That(rules.Cast<FileSystemAccessRule>().Select(r => r.IdentityReference),
                                    Is.All.EqualTo(owner),
                                    "only the current user may appear in the private key's DACL");
                    });
                }
                else
                {
                    const UnixFileMode groupAndOther =
                        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

                    Assert.That(File.GetUnixFileMode(path) & groupAndOther, Is.EqualTo((UnixFileMode) 0),
                                "the private key must carry no group/other permission bits (mode 0600)");
                }

            }
            finally
            {
                try { File.Delete(path);          } catch { }
                try { File.Delete(path + ".pub"); } catch { }
            }

        }

        #endregion

    }

}
