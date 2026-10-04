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
using System.Text.RegularExpressions;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Interoperability tests for OpenSSH certificates against <c>ssh-keygen</c>: we validate a certificate
    /// it signs (as a CA), and it reads a certificate our mini-CA issues.
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    public class OpenSshCertificateInteropTests
    {

        private static String? FindSshKeygen()
        {
            foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
                foreach (var name in new[] { "ssh-keygen", "ssh-keygen.exe" })
                    try { var c = Path.Combine(dir.Trim(), name); if (File.Exists(c)) return c; } catch { }
            var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", "ssh-keygen.exe");
            return File.Exists(system) ? system : null;
        }

        private static async Task<(Int32 ExitCode, String StdOut, String StdErr)> RunAsync(String Exe, CancellationToken CancellationToken, params String[] Args)
        {
            var startInfo = new ProcessStartInfo(Exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in Args) startInfo.ArgumentList.Add(a);
            using var process = Process.Start(startInfo)!;
            var stdout = await process.StandardOutput.ReadToEndAsync(CancellationToken);
            var stderr = await process.StandardError.ReadToEndAsync(CancellationToken);
            await process.WaitForExitAsync(CancellationToken);
            return (process.ExitCode, stdout, stderr);
        }


        #region WeValidate_SshKeygenSignedCertificate

        [Test]
        [CancelAfter(30000)]
        public async Task WeValidate_SshKeygenSignedCertificate(CancellationToken CancellationToken)
        {

            var keygen = FindSshKeygen();
            if (keygen is null)
                Assert.Ignore("No 'ssh-keygen' found.");

            var dir   = Directory.CreateTempSubdirectory("hermod_cert_");
            var ca    = Path.Combine(dir.FullName, "ca");
            var user  = Path.Combine(dir.FullName, "user");

            try
            {

                if ((await RunAsync(keygen!, CancellationToken, "-t", "ed25519", "-f", ca,   "-N", "", "-q", "-C", "ca")).ExitCode   != 0 ||
                    (await RunAsync(keygen!, CancellationToken, "-t", "ed25519", "-f", user, "-N", "", "-q", "-C", "user")).ExitCode != 0)
                    Assert.Ignore("ssh-keygen could not generate keys.");

                // ssh-keygen as a CA: sign the user key with id, principals, serial and a validity window.
                var sign = await RunAsync(keygen!, CancellationToken,
                                          "-s", ca, "-I", "hermod-test-id", "-n", "achim,ops", "-z", "777",
                                          "-V", "-1h:+52w", user + ".pub");
                if (sign.ExitCode != 0)
                    Assert.Ignore($"ssh-keygen -s failed: {sign.StdErr}");

                var certLine = await File.ReadAllTextAsync(user + "-cert.pub", CancellationToken);
                var caLine   = await File.ReadAllTextAsync(ca + ".pub", CancellationToken);

                var cert  = SshCertificate.Parse(SshPublicKey.Parse(certLine).Blob);
                var caKey = SshPublicKey.Parse(caLine);
                var trust = new SshCertificateAuthorityTrust().TrustCA(caKey.Blob);

                var result = SshCertificateValidator.Validate(cert, SshCertType.User, "achim", trust, DateTimeOffset.UtcNow);

                Assert.Multiple(() => {
                    Assert.That(cert.KeyId,       Is.EqualTo("hermod-test-id"));
                    Assert.That(cert.Serial,      Is.EqualTo(777));
                    Assert.That(cert.Principals,  Does.Contain("achim").And.Contains("ops"));
                    Assert.That(cert.VerifyCaSignature(), Is.True, "we must verify ssh-keygen's CA signature");
                    Assert.That(result.IsValid,   Is.True, "ssh-keygen's certificate must pass our validation");
                    Assert.That(SshCertificateValidator.Validate(cert, SshCertType.User, "eve", trust, DateTimeOffset.UtcNow).IsValid, Is.False);
                });

            }
            finally
            {
                try { dir.Delete(recursive: true); } catch { }
            }

        }

        #endregion

        #region SshKeygenReads_OurCertificate

        [Test]
        [CancelAfter(30000)]
        public async Task SshKeygenReads_OurCertificate(CancellationToken CancellationToken)
        {

            var keygen = FindSshKeygen();
            if (keygen is null)
                Assert.Ignore("No 'ssh-keygen' found.");

            var dir  = Directory.CreateTempSubdirectory("hermod_ourcert_");
            var path = Path.Combine(dir.FullName, "id-cert.pub");

            try
            {

                var caKey    = SshHostKey.GenerateEd25519();
                var userKey  = SshHostKey.GenerateEd25519();

                var cert = new OpenSshCertificateBuilder
                {
                    Serial      = 4242,
                    Type        = SshCertType.User,
                    KeyId       = "issued-by-hermod",
                    Principals  = [ "achim", "admin" ],
                    ValidAfter  = DateTimeOffset.UtcNow.AddHours(-1),
                    ValidBefore = DateTimeOffset.UtcNow.AddDays(30)
                }.Sign(userKey.PublicKeyBlob, caKey);

                var line = cert.CertAlgorithm + " " + Convert.ToBase64String(cert.Blob) + " hermod\n";
                await File.WriteAllTextAsync(path, line, CancellationToken);

                // ssh-keygen -L prints certificate details — proof it can parse and verify our structure.
                var view = await RunAsync(keygen!, CancellationToken, "-L", "-f", path);

                Assert.Multiple(() => {
                    Assert.That(view.ExitCode, Is.EqualTo(0), $"ssh-keygen -L failed: {view.StdErr}");
                    Assert.That(view.StdOut,   Does.Contain("issued-by-hermod"));
                    Assert.That(view.StdOut,   Does.Contain("Serial: 4242"));
                    Assert.That(view.StdOut,   Does.Contain("achim"));
                });

            }
            finally
            {
                try { dir.Delete(recursive: true); } catch { }
            }

        }

        #endregion


        #region OpenSsh_EmptyCertPrincipals_MatchNothingFrom_10_3

        /// <summary>
        /// A real OpenSSH accepts a user certificate with an empty principals list up to 10.2 and
        /// refuses it from 10.3 on — the change our own validator was altered to match.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Peer against peer: their <c>ssh-keygen</c> issues the certificates, their <c>sshd</c> judges
        /// them, their <c>ssh</c> presents them. Nothing of ours takes part, and that is the point — it
        /// establishes the reference behaviour instead of asserting our implementation against itself.
        /// </para>
        /// <para>
        /// The path matters, and finding it cost a probe. Over <c>TrustedUserCAKeys</c> even 10.0p2
        /// refuses an empty list, logging "Certificate lacks principal list", because there the
        /// principal is the only thing binding the certificate to a login name. The wildcard lived in
        /// <c>authorized_keys</c> behind a <c>cert-authority</c> marker, where the file already binds
        /// the key to the user — and that is the case 10.3 changed, under "Potentially incompatible
        /// changes".
        /// </para>
        /// <para>
        /// So this asserts the version-appropriate truth rather than skipping below 10.3: accepted
        /// before, refused from 10.3 on. It therefore runs on every leg — Debian 13 ships 10.0p2 and
        /// exercises the old branch, the nightly's upstream leg builds the newest release and exercises
        /// the new one — and if a distribution ever backports the change, this says so instead of
        /// staying quiet. The named-principal control runs at every version: without it a refusal could
        /// come from any setup mistake rather than from the principals field.
        /// </para>
        /// </remarks>
        [Test]
        [CancelAfter(180000)]
        public async Task OpenSsh_EmptyCertPrincipals_MatchNothingFrom_10_3(CancellationToken CancellationToken)
        {

            WslInterop.SkipIfUnavailable();

            var (_, _, versionText) = await WslInterop.RunAsync([ "-e", "ssh", "-V" ], CancellationToken);
            var match               = Regex.Match(versionText, "OpenSSH_([0-9]+)[.]([0-9]+)");

            if (!match.Success)
                Assert.Ignore($"Could not read an OpenSSH version from '{versionText.Trim()}'.");

            var version = new Version(Int32.Parse(match.Groups[1].Value), Int32.Parse(match.Groups[2].Value));
            var refuses = version >= new Version(10, 3);

            // Deliberately not an interpolated string: the script picks its own directory and echoes it
            // back, so the braces of the printf group stay literal and nothing has to be escaped.
            const String setup =
                "d=$(mktemp -d /tmp/hermod-certprin-XXXXXX) && cd $d" +
                " && ssh-keygen -q -t ed25519 -f hostkey -N '' -C h" +
                " && ssh-keygen -q -t ed25519 -f ca -N '' -C ca" +
                " && ssh-keygen -q -t ed25519 -f named -N '' -C n" +
                " && ssh-keygen -q -t ed25519 -f empty -N '' -C e" +
                " && ssh-keygen -q -s ca -I named-cert -n $(id -un) named.pub" +
                " && ssh-keygen -q -s ca -I empty-cert empty.pub" +
                " && { printf 'cert-authority '; cat ca.pub; } > ak" +
                " && chmod 600 named empty hostkey ak" +
                " && echo $d";

            var (setupExit, setupOut, setupErr) = await WslInterop.RunAsync([ "-e", "bash", "-c", setup ], CancellationToken);

            if (setupExit != 0)
                Assert.Ignore($"Could not prepare the certificate workspace: {setupErr.Trim()}");

            // ssh-keygen -q says nothing, so the only thing on stdout is the directory.
            var dir = setupOut.Trim();

            var daemon = await WslInterop.StartServerAsync(
                             port =>
                                 $"$(mkdir -p /run/sshd 2>/dev/null; command -v sshd || echo /usr/sbin/sshd) -D -e -p {port}" +
                                 $" -h {dir}/hostkey -o AuthorizedKeysFile={dir}/ak" +
                                 " -o StrictModes=no -o UsePAM=no -o PidFile=none -o PermitRootLogin=yes" +
                                 " -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no" +
                                 " -o ListenAddress=127.0.0.1",
                             CancellationToken);

            try
            {

                async Task<(Int32 ExitCode, String StdOut)> PresentAsync(String Name)
                {
                    var (exitCode, stdOut, _) = await WslInterop.RunAsync(
                        [ "-e", "bash", "-c",
                          $"ssh -q -i {dir}/{Name} -o CertificateFile={dir}/{Name}-cert.pub" +
                          " -o IdentitiesOnly=yes -o StrictHostKeyChecking=no" +
                          " -o UserKnownHostsFile=/dev/null -o BatchMode=yes" +
                          $" -p {daemon.Port} $(id -un)@127.0.0.1 echo MARKER" ],
                        CancellationToken);
                    return (exitCode, stdOut);
                }

                var named = await PresentAsync("named");
                var empty = await PresentAsync("empty");

                TestContext.Out.WriteLine($"OpenSSH {version} via cert-authority: named principal -> exit {named.ExitCode}, " +
                                          $"empty principals -> exit {empty.ExitCode} (expected {(refuses ? "refusal" : "acceptance")})");

                Assert.Multiple(() => {

                    // The control, true at every version: it shows the harness works, and leaves the
                    // principals field as the only variable between the two runs.
                    Assert.That(named.ExitCode, Is.EqualTo(0),
                                "a certificate naming this user must authenticate — if this fails the setup is at fault, not the principals rule");
                    Assert.That(named.StdOut,   Does.Contain("MARKER"),
                                "the named certificate must actually reach a shell");

                    if (refuses)
                        Assert.That(empty.ExitCode, Is.Not.EqualTo(0),
                                    $"OpenSSH {version} is 10.3 or newer, so an empty principals list must match nothing");
                    else
                        Assert.That(empty.ExitCode, Is.EqualTo(0),
                                    $"OpenSSH {version} predates 10.3, where an empty principals list still matched every principal — " +
                                    "a refusal here means the distribution backported the change and this baseline moved");

                });

            }
            finally
            {
                await daemon.DisposeAsync();
                try { await WslInterop.RunAsync([ "-e", "rm", "-rf", dir ], CancellationToken.None); } catch { }
            }

        }

        #endregion

    }

}
