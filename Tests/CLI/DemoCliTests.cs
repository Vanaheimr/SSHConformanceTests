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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.CLI;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// M10: the demo CLI's offline verbs (keygen / scan / ca) wire the library correctly.
    /// </summary>
    [TestFixture]
    public class DemoCliTests
    {

        private String dir = "";

        [SetUp]
        public void MakeDir()
        {
            dir = Path.Combine(Path.GetTempPath(), "hermod_cli_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
        }

        [TearDown]
        public void CleanDir()
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }


        #region Keygen_Scan_Ca_Pipeline

        [Test]
        [CancelAfter(20000)]
        public async Task Keygen_Scan_Ca_Pipeline(CancellationToken CancellationToken)
        {

            var userKey = Path.Combine(dir, "user");
            var caKey   = Path.Combine(dir, "ca");

            // keygen writes the private key + a .pub, and returns success.
            var kg1 = await Commands.KeygenAsync(["keygen", "-t", "ed25519", "-f", userKey, "-C", "achim@test"], CancellationToken);
            var kg2 = await Commands.KeygenAsync(["keygen", "-t", "ecdsa-sha2-nistp256", "-f", caKey], CancellationToken);

            Assert.Multiple(() => {
                Assert.That(kg1, Is.EqualTo(0));
                Assert.That(kg2, Is.EqualTo(0));
                Assert.That(File.Exists(userKey),          Is.True);
                Assert.That(File.Exists(userKey + ".pub"), Is.True);
            });

            // scan succeeds on the generated public key.
            var scan = await Commands.ScanAsync(["scan", "-f", userKey + ".pub", "-n", "dev.fleet."], CancellationToken);
            Assert.That(scan, Is.EqualTo(0));

            // ca signs the user key with the CA key and writes a *-cert.pub whose blob is a real certificate.
            var ca = await Commands.CaAsync(["ca", "--ca", caKey, "-s", userKey + ".pub", "-I", "achim@2026", "-n", "achim,admin", "-z", "42"], CancellationToken);
            var certFile = userKey + "-cert.pub";

            Assert.Multiple(() => {
                Assert.That(ca, Is.EqualTo(0));
                Assert.That(File.Exists(certFile), Is.True);
            });

            // The emitted certificate parses back and carries what the CLI put in it.
            var line = (await File.ReadAllTextAsync(certFile, CancellationToken)).Split(' ');
            var cert = SshCertificate.Parse(Convert.FromBase64String(line[1]));

            Assert.Multiple(() => {
                Assert.That(cert.Serial,     Is.EqualTo(42UL));
                Assert.That(cert.KeyId,      Is.EqualTo("achim@2026"));
                Assert.That(cert.Principals, Is.EqualTo(new[] { "achim", "admin" }));
            });

        }

        #endregion

    }

}
