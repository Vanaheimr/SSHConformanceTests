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

using System.Diagnostics;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Interoperability tests for the private-key formats against the real <c>ssh-keygen</c>: we load
    /// keys it generates (unencrypted and bcrypt-encrypted, validating <see cref="BcryptPbkdf"/>), and it
    /// reads the openssh-key-v1 keys we write.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshKeyFormatInteropTests
    {

        #region (static) helpers

        private static String? FindSshKeygen()
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { "ssh-keygen", "ssh-keygen.exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }

            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh-keygen.exe");
            return File.Exists(system) ? system : null;
        }

        private static String? FindOnPath(String Tool)
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { Tool, Tool + ".exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }
            return null;
        }

        private static async Task<Int32> RunAsync(String Exe, CancellationToken CancellationToken, params String[] Args)
        {
            var startInfo = new ProcessStartInfo(Exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in Args) startInfo.ArgumentList.Add(a);
            using var process = Process.Start(startInfo)!;
            await process.WaitForExitAsync(CancellationToken);
            return process.ExitCode;
        }

        private static async Task<(String StdOut, String StdErr, Int32 ExitCode)> RunCaptureAsync(String Exe, CancellationToken CancellationToken, params String[] Args)
        {
            var startInfo = new ProcessStartInfo(Exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in Args) startInfo.ArgumentList.Add(a);
            using var process = Process.Start(startInfo)!;
            var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken);
            var stderr = process.StandardError. ReadToEndAsync(CancellationToken);
            await process.WaitForExitAsync(CancellationToken);
            return (await stdout, await stderr, process.ExitCode);
        }

        #endregion


        #region WeLoad_SshKeygenKeys_Unencrypted

        [Test]
        [CancelAfter(30000)]
        [TestCase("ed25519")]
        [TestCase("ecdsa")]
        [TestCase("rsa")]
        public async Task WeLoad_SshKeygenKeys_Unencrypted(String KeyType, CancellationToken CancellationToken)
        {

            var keygen = FindSshKeygen();
            if (keygen is null)
                Assert.Ignore("No 'ssh-keygen' found.");

            var path = Path.Combine(Path.GetTempPath(), "hermod_key_" + Guid.NewGuid().ToString("N"));

            try
            {

                if (await RunAsync(keygen!, CancellationToken, "-t", KeyType, "-f", path, "-N", "", "-q", "-C", "unenc") != 0)
                    Assert.Ignore($"ssh-keygen could not generate a {KeyType} key.");

                var loaded      = SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(path, CancellationToken));
                var publicLine  = await File.ReadAllTextAsync(path + ".pub", CancellationToken);
                var expected    = SshPublicKey.Parse(publicLine);

                // The public key we reconstruct from the private key must match ssh-keygen's .pub, and a
                // signature by the loaded key must verify against that same public key.
                var data      = RandomNumberGenerator.GetBytes(64);
                var signature = loaded.Key.Sign(loaded.Key.AlgorithmNames[0], data);

                Assert.Multiple(() => {
                    Assert.That(loaded.Key.PublicKeyBlob, Is.EqualTo(expected.Blob), "reconstructed public key must match ssh-keygen's .pub");
                    Assert.That(SshSignature.Verify(expected.Blob, data, signature), Is.True, "loaded private key must sign verifiably");
                });

            }
            finally
            {
                try { File.Delete(path);          } catch { }
                try { File.Delete(path + ".pub"); } catch { }
            }

        }

        #endregion

        #region WeLoad_SshKeygenKeys_BcryptEncrypted

        [Test]
        [CancelAfter(30000)]
        [TestCase("ed25519")]
        [TestCase("rsa")]
        public async Task WeLoad_SshKeygenKeys_BcryptEncrypted(String KeyType, CancellationToken CancellationToken)
        {

            var keygen = FindSshKeygen();
            if (keygen is null)
                Assert.Ignore("No 'ssh-keygen' found.");

            const String passphrase = "correct horse battery staple";
            var path = Path.Combine(Path.GetTempPath(), "hermod_enckey_" + Guid.NewGuid().ToString("N"));

            try
            {

                // A low KDF round count keeps the test fast while still exercising bcrypt_pbkdf.
                if (await RunAsync(keygen!, CancellationToken, "-t", KeyType, "-f", path, "-N", passphrase, "-a", "8", "-q", "-C", "enc") != 0)
                    Assert.Ignore($"ssh-keygen could not generate an encrypted {KeyType} key.");

                var loaded   = SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(path, CancellationToken), passphrase);
                var expected = SshPublicKey.Parse(await File.ReadAllTextAsync(path + ".pub", CancellationToken));

                var data      = RandomNumberGenerator.GetBytes(64);
                var signature = loaded.Key.Sign(loaded.Key.AlgorithmNames[0], data);

                Assert.Multiple(() => {
                    Assert.That(loaded.Key.PublicKeyBlob, Is.EqualTo(expected.Blob), "bcrypt_pbkdf must decrypt to the right key");
                    Assert.That(SshSignature.Verify(expected.Blob, data, signature), Is.True);
                });

            }
            finally
            {
                try { File.Delete(path);          } catch { }
                try { File.Delete(path + ".pub"); } catch { }
            }

        }

        #endregion

        #region WeLoad_SshKeygenKeys_InEveryCipher

        /// <summary>
        /// <c>ssh-keygen -Z</c> encrypts a key with each cipher it offers, and we read every one of them
        /// to the key its <c>.pub</c> names - all but <c>3des-cbc</c>, which is refused with the command
        /// that re-encrypts the key.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        [TestCase("aes128-ctr")]
        [TestCase("aes192-ctr")]
        [TestCase("aes256-ctr")]
        [TestCase("aes128-cbc")]
        [TestCase("aes192-cbc")]
        [TestCase("aes256-cbc")]
        [TestCase("aes128-gcm@openssh.com")]
        [TestCase("aes256-gcm@openssh.com")]
        [TestCase("chacha20-poly1305@openssh.com")]
        [TestCase("3des-cbc")]
        public async Task WeLoad_SshKeygenKeys_InEveryCipher(String Cipher, CancellationToken CancellationToken)
        {

            var keygen = FindSshKeygen();
            if (keygen is null)
                Assert.Ignore("No 'ssh-keygen' found.");

            const String passphrase = "correct horse battery staple";
            var path = Path.Combine(Path.GetTempPath(), "hermod_cipherkey_" + Guid.NewGuid().ToString("N"));

            try
            {

                if (await RunAsync(keygen!, CancellationToken, "-t", "ed25519", "-f", path, "-N", passphrase, "-Z", Cipher, "-a", "8", "-q", "-C", "cipher") != 0)
                    Assert.Ignore($"This ssh-keygen does not write keys with '{Cipher}'.");

                var text = await File.ReadAllTextAsync(path, CancellationToken);

                if (Cipher == "3des-cbc")
                {
                    var refused = Assert.Throws<SshWireException>(() => SshKeyGenerator.LoadPrivateKey(text, passphrase));
                    Assert.That(refused!.Message, Does.Contain("ssh-keygen -p -Z"));
                    return;
                }

                var loaded   = SshKeyGenerator.LoadPrivateKey(text, passphrase);
                var expected = SshPublicKey.Parse(await File.ReadAllTextAsync(path + ".pub", CancellationToken));

                var data      = RandomNumberGenerator.GetBytes(64);
                var signature = loaded.Key.Sign(loaded.Key.AlgorithmNames[0], data);

                Assert.Multiple(() => {
                    Assert.That(loaded.Key.PublicKeyBlob, Is.EqualTo(expected.Blob), $"'{Cipher}' must decrypt to the key ssh-keygen wrote");
                    Assert.That(SshSignature.Verify(expected.Blob, data, signature), Is.True);
                    Assert.Throws<SshAuthenticationException>(() => SshKeyGenerator.LoadPrivateKey(text, "wrong passphrase"));
                });

            }
            finally
            {
                try { File.Delete(path);          } catch { }
                try { File.Delete(path + ".pub"); } catch { }
            }

        }

        #endregion

        #region WeLoad_OpenSslEd25519Pkcs8Keys

        /// <summary>
        /// <c>openssl genpkey -algorithm ed25519</c> writes PKCS#8, which the BCL does not read for Ed25519;
        /// we load it, plain and passphrase-encrypted, to the key <c>openssl pkey -pubout</c> names.
        /// </summary>
        [Test]
        [CancelAfter(30000)]
        [TestCase(false)]
        [TestCase(true)]
        public async Task WeLoad_OpenSslEd25519Pkcs8Keys(Boolean Encrypted, CancellationToken CancellationToken)
        {

            var openssl = FindOnPath("openssl");
            if (openssl is null)
                Assert.Ignore("No 'openssl' found.");

            const String passphrase = "correct horse battery staple";
            var plain    = Path.Combine(Path.GetTempPath(), "hermod_pkcs8_" + Guid.NewGuid().ToString("N") + ".pem");
            var sealedUp = plain + ".enc";

            try
            {

                if (await RunAsync(openssl!, CancellationToken, "genpkey", "-algorithm", "ed25519", "-out", plain) != 0)
                    Assert.Ignore("This openssl does not generate Ed25519 keys.");

                if (Encrypted && await RunAsync(openssl!, CancellationToken, "pkcs8", "-topk8", "-in", plain, "-out", sealedUp, "-v2", "aes-256-cbc", "-passout", "pass:" + passphrase) != 0)
                    Assert.Fail("openssl could not encrypt the key.");

                var (publicDer, _, exitCode) = await RunCaptureAsync(openssl!, CancellationToken, "pkey", "-in", plain, "-pubout");
                Assert.That(exitCode, Is.Zero);

                // The SubjectPublicKeyInfo of an Ed25519 key ends in the 32 raw bytes of the key.
                var spki     = Convert.FromBase64String(String.Concat(publicDer.Split('\n').Where(line => !line.StartsWith("-----")).Select(line => line.Trim())));
                var expected = SshEd25519.EncodePublicKeyBlob(spki.AsSpan(spki.Length - 32));

                var loaded   = SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(Encrypted ? sealedUp : plain, CancellationToken),
                                                              Encrypted ? passphrase : null);

                // The fixture is OpenSSH's by name, the peer here is OpenSSL.
                TestContext.Out.WriteLine("INTEROP-MATRIX: peer=OpenSSL feature=Key formats (openssh-key-v1, PEM)");

                Assert.That(loaded.Key.PublicKeyBlob, Is.EqualTo(expected), "the key openssl generated");

            }
            finally
            {
                try { File.Delete(plain);    } catch { }
                try { File.Delete(sealedUp); } catch { }
            }

        }

        #endregion

        #region SshKeygenReads_OurOpenSshPrivateKey

        [Test]
        [CancelAfter(30000)]
        [TestCase("ssh-ed25519")]
        [TestCase("ecdsa-sha2-nistp256")]
        [TestCase("ssh-rsa")]
        public async Task SshKeygenReads_OurOpenSshPrivateKey(String KeyType, CancellationToken CancellationToken)
        {

            var keygen = FindSshKeygen();
            if (keygen is null)
                Assert.Ignore("No 'ssh-keygen' found.");

            var key   = SshKeyGenerator.Generate(KeyType);
            var path  = Path.Combine(Path.GetTempPath(), "hermod_ourkey_" + Guid.NewGuid().ToString("N"));

            try
            {

                await SshKeyGenerator.WriteKeyPairAsync(key, path, "written-by-hermod", CancellationToken);

                // ssh-keygen -y derives the public key from OUR private key — proof it can read our format.
                var result        = await RunCaptureAsync(keygen!, CancellationToken, "-y", "-f", path);
                var derivedPublic = result.StdOut.Trim();
                var expected      = SshPublicKey.FromHostKey(key).ToAuthorizedKeyLine();

                Assert.That(derivedPublic.StartsWith(expected, StringComparison.Ordinal), Is.True,
                            $"ssh-keygen -y should reproduce our public key.\n  ours: {expected}\n  ssh-keygen: {derivedPublic}\n  exit code: {result.ExitCode}\n  stderr: {result.StdErr.Trim()}");

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
