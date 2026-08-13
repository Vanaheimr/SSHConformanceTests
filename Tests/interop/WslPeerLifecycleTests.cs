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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// The harness testing itself: a peer server must be gone once its test disposed it.
    ///
    /// <para>
    /// This is not housekeeping. Every other interop fixture starts a real SSH daemon, and for a long
    /// time none of them managed to stop one — the daemons piled up on the developer's machine, still
    /// listening, still holding the ports that later runs then failed to bind. The mechanism that reaps
    /// them is only exercised on the way out of a test, where nothing looks at it, so nothing noticed.
    /// This test looks.
    /// </para>
    ///
    /// <para>
    /// It uses <c>sshd</c> deliberately, rather than something cheaper to start. The reaping is easy to
    /// get subtly wrong precisely because OpenSSH rewrites its own command line, and a peer that is
    /// identified by what it looks like — rather than by the identity it recorded before it started —
    /// passes with any other daemon and fails with this one.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    public class WslPeerLifecycleTests
    {

        #region DisposingAPeerServer_ReapsTheDaemonInsideLinux

        [Test]
        [CancelAfter(120000)]
        public async Task DisposingAPeerServer_ReapsTheDaemonInsideLinux(CancellationToken CancellationToken)
        {

            WslInterop.SkipIfUnavailable();

            var identifier = Guid.NewGuid().ToString("N");
            var home       = await WslInterop.HomeAsync(CancellationToken);
            var wslRoot    = $"{home}/.hermod-interop/lifecycle_{identifier}";

            var (prepared, _, prepareError) = await WslInterop.RunAsync([
                                                  "-e", "bash", "-c",
                                                  $"mkdir -p {wslRoot} && chmod 700 {wslRoot} && " +
                                                  $"ssh-keygen -t ed25519 -f {wslRoot}/hostkey -N '' -q && " +
                                                  $": > {wslRoot}/authorized_keys && chmod 600 {wslRoot}/authorized_keys"
                                              ], CancellationToken);

            if (prepared != 0)
                Assert.Ignore($"Could not prepare the sshd workspace: {prepareError}");

            var port = FreePort();

            try
            {

                var server = await WslInterop.StartServerAsync(
                                 $"$(command -v sshd || echo /usr/sbin/sshd) -D -e -p {port} " +
                                 $"-h {wslRoot}/hostkey " +
                                 $"-o AuthorizedKeysFile={wslRoot}/authorized_keys " +
                                 $"-o StrictModes=no -o UsePAM=no -o PidFile=none " +
                                 $"-o ListenAddress=127.0.0.1",
                                 port,
                                 CancellationToken);

                // What the peer recorded about itself is the whole basis of reaping it, so read it back
                // before disposing: if this is wrong, the failure below is about the wrong thing.
                var (_, recorded, _) = await WslInterop.RunAsync([
                                           "-e", "bash", "-c",
                                           $"cat \"$HOME/.hermod-interop/run\"/*/*.pid 2>/dev/null | tr '\\n' ' '"
                                       ], CancellationToken);

                TestContext.Out.WriteLine($"the peer recorded: [{recorded.Trim()}]");

                Assert.That(recorded.Trim(), Does.Match(@"^\d+\s+\d+$"),
                            "the peer must record its PID and start time — both, or disposal cannot identify it");

                await server.DisposeAsync();

                var (_, listening, _) = await WslInterop.RunAsync([
                                            "-e", "bash", "-c",
                                            $"ps -eo pid=,args= | grep -F '{wslRoot}' | grep -v grep | tr '\\n' ';'"
                                        ], CancellationToken);

                Assert.That(listening.Trim(), Is.Empty,
                            $"disposal must leave no daemon of this test running inside Linux, but found: {listening.Trim()}");

            }
            finally
            {
                // Two direct execs rather than one shell line: 'pkill -f <path>' inside 'bash -c' matches
                // the very shell running it, because the path is in that shell's own command line — so the
                // shell dies before it reaches anything after the semicolon. pkill never matches itself.
                try { await WslInterop.RunAsync(["-e", "pkill", "-f", wslRoot], CancellationToken.None); } catch { }
                try { await WslInterop.RunAsync(["-e", "rm", "-rf", wslRoot],   CancellationToken.None); } catch { }
            }

        }

        #endregion

        #region (private) FreePort()

        private static Int32 FreePort()
        {
            using var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            probe.Start();
            var port = ((System.Net.IPEndPoint) probe.LocalEndpoint).Port;
            probe.Stop();
            return port;
        }

        #endregion

    }

}
