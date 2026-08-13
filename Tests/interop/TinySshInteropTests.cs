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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Interoperability against <b>TinySSH</b> — the most minimal SSH server in existence, and the sharpest
    /// test of our <b>client</b>'s narrow path.
    ///
    /// <para>
    /// TinySSH implements one host-key type (<c>ssh-ed25519</c>), one cipher
    /// (<c>chacha20-poly1305@openssh.com</c>) and two key exchanges (<c>sntrup761x25519-sha512@openssh.com</c>
    /// and <c>curve25519-sha256</c>) — no RSA, no CBC, no compression, no port forwarding, not even dynamic
    /// memory. There is nothing to fall back to: either our first-choice modern algorithms are exactly right
    /// or nothing connects at all. It is also the only peer here that makes our client speak the
    /// post-quantum hybrid, rather than answering one.
    /// </para>
    ///
    /// <para>
    /// These tests stop at the transport. TinySSH authorises strictly against <c>~/.ssh/authorized_keys</c>
    /// of the account it runs as, with no option to point it elsewhere (unlike Dropbear's <c>-D</c>), and a
    /// test has no business writing a usable key into a developer's real account. The transport is where
    /// TinySSH's value lies anyway: the key exchange, the host key and the cipher.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.TinySSH")]
    public class TinySshInteropTests
    {

        #region (private) harness

        private sealed record Fixture(String WslRoot, String KeyDirectory, Byte[] HostKeyBlob);

        /// <summary>
        /// Create a TinySSH key directory and read back the host key it generated, which is what our client
        /// then has to recognise.
        /// </summary>
        private static async Task<Fixture> PrepareAsync(CancellationToken CancellationToken)
        {

            WslInterop.SkipIfUnavailable();

            var (present, _, _) = await WslInterop.RunAsync(["-e", "bash", "-c", "command -v tinysshd tinysshd-makekey tinysshd-printkey >/dev/null"], CancellationToken);
            if (present != 0)
                Assert.Ignore("TinySSH is not installed inside WSL — run interop/setup-wsl.sh.");

            var home    = await WslInterop.HomeAsync(CancellationToken);
            var wslRoot = $"{home}/.hermod-interop/tinyssh_{Guid.NewGuid():N}";
            var keyDir  = $"{wslRoot}/keys";

            // tinysshd-makekey insists on creating the directory itself.
            var (exitCode, _, stderr) = await WslInterop.RunAsync([
                                            "-e", "bash", "-c",
                                            $"mkdir -p {wslRoot} && chmod 700 {wslRoot} && tinysshd-makekey {keyDir}"
                                        ], CancellationToken);

            if (exitCode != 0)
                Assert.Ignore($"tinysshd-makekey failed: {stderr}");

            // Through a shell: the TinySSH tools live in /usr/sbin, which is on bash's PATH but not on the
            // bare one `wsl -e` execs with.
            var (printExit, publicKeyText, printError) = await WslInterop.RunAsync([
                                                             "-e", "bash", "-c", $"tinysshd-printkey {keyDir}"
                                                         ], CancellationToken);

            if (printExit != 0)
                Assert.Ignore($"tinysshd-printkey failed: {printError}");

            var line = publicKeyText.Split('\n').FirstOrDefault(l => l.StartsWith("ssh-ed25519", StringComparison.Ordinal))
                           ?? throw new InvalidOperationException($"tinysshd-printkey printed no ed25519 key:\n{publicKeyText}");

            return new Fixture(wslRoot, keyDir, Convert.FromBase64String(line.Split(' ')[1]));

        }

        private static async Task CleanupAsync(Fixture Fixture)
        {
            try { await WslInterop.RunAsync(["-e", "rm", "-rf", Fixture.WslRoot], CancellationToken.None); } catch { }
        }

        /// <summary>
        /// TinySSH speaks over stdin/stdout in the inetd tradition, so socat gives it a listening socket.
        /// Bound to loopback inside WSL, which Windows reaches through WSL2's localhost forwarding.
        /// </summary>
        private static Task<WslServer> StartAsync(Fixture Fixture, CancellationToken CancellationToken)
            => WslInterop.StartServerAsync(
                   port =>
                       $"socat TCP-LISTEN:{port},reuseaddr,fork,bind=127.0.0.1 EXEC:'/usr/sbin/tinysshd -v {Fixture.KeyDirectory}'",
                   CancellationToken);

        #endregion


        #region OurClient_CompletesTransport_WithTinySshServer

        /// <summary>
        /// Our client against TinySSH, one key exchange at a time — including the post-quantum hybrid, which
        /// this is the first test to make our <i>client</i> drive rather than answer.
        ///
        /// <para>
        /// Completing the handshake is the assertion: our client verifies TinySSH's host-key signature over
        /// the exchange hash, so a completed handshake means both sides derived the same secret and the same
        /// H. The negotiated cipher is checked too, since TinySSH offers exactly one and nothing else could
        /// have been chosen by accident.
        /// </para>
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        [TestCase("sntrup761x25519-sha512@openssh.com")]
        [TestCase("curve25519-sha256")]
        public async Task OurClient_CompletesTransport_WithTinySshServer(String KeyExchange, CancellationToken CancellationToken)
        {

            var fixture = await PrepareAsync(CancellationToken);

            await using var tinyssh = await StartAsync(fixture, CancellationToken);

            try
            {

                var pipe = await SshTcp.ConnectAsync(new IPSocket(IPv4Address.Localhost, IPPort.Parse(tinyssh.Port)), CancellationToken);

                using var transport = await SshTransport.ClientHandshakeAsync(
                                          pipe,
                                          VerifyHostKey: blob => blob.AsSpan().SequenceEqual(fixture.HostKeyBlob),
                                          KeyExchanges:  [ KeyExchange ],
                                          CancellationToken: CancellationToken);

                var algorithms = transport.Algorithms;

                TestContext.Out.WriteLine($"TinySSH agreed on {algorithms.KeyExchange} / {algorithms.CipherServerToClient} / {algorithms.HostKey}");

                Assert.Multiple(() => {

                    Assert.That(algorithms.KeyExchange, Is.EqualTo(KeyExchange),
                                $"our client must complete {KeyExchange} with TinySSH.\n{tinyssh.Output}");

                    Assert.That(algorithms.HostKey, Is.EqualTo("ssh-ed25519"),
                                "TinySSH offers exactly one host-key type");

                    Assert.That(algorithms.CipherServerToClient, Is.EqualTo("chacha20-poly1305@openssh.com"),
                                "TinySSH offers exactly one cipher, so this is the only possible outcome");

                    Assert.That(algorithms.StrictKex, Is.True,
                                "TinySSH has supported strict KEX since 20240101, so the Terrapin countermeasure must be in force");

                });

                await pipe.Output.CompleteAsync();
                await pipe.Input. CompleteAsync();

            }
            finally
            {
                await CleanupAsync(fixture);
            }

        }

        #endregion

        #region OurClient_RejectsAWrongTinySshHostKey

        /// <summary>
        /// The same handshake with the wrong key pinned: our client must fail closed against a real
        /// third-party server, and it must fail during the key exchange rather than after it.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_RejectsAWrongTinySshHostKey(CancellationToken CancellationToken)
        {

            var fixture      = await PrepareAsync(CancellationToken);
            var somebodyElse = SshHostKey.GenerateEd25519();

            await using var tinyssh = await StartAsync(fixture, CancellationToken);

            try
            {

                var pipe = await SshTcp.ConnectAsync(new IPSocket(IPv4Address.Localhost, IPPort.Parse(tinyssh.Port)), CancellationToken);

                Assert.That(async () => await SshTransport.ClientHandshakeAsync(
                                            pipe,
                                            VerifyHostKey: blob => blob.AsSpan().SequenceEqual(somebodyElse.PublicKeyBlob),
                                            CancellationToken: CancellationToken),
                            Throws.TypeOf<SshWireException>().With.Message.Contains("rejected"),
                            "our client must refuse a host key that is not the one it pinned");

            }
            finally
            {
                await CleanupAsync(fixture);
            }

        }

        #endregion

    }

}
