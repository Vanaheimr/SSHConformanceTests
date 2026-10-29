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

using System.Text.Json;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Our client logging in to an <b>AsyncSSH server</b> with what is not a key: a password, and the
    /// answers to keyboard-interactive prompts.
    ///
    /// <para>
    /// The other server peers can not check this without touching an account: <c>sshd</c> and Dropbear
    /// check a password against the system's, so a test would need a Linux user with a known password.
    /// AsyncSSH asks a callback instead (<c>interop/python/asyncssh_server.py</c>), and logs every
    /// request it judges - which is how these tests see what our client said, not just that it got in.
    /// </para>
    /// </summary>
    [TestFixture]
    [Category("Interop")]
    [Category("Interop.WSL")]
    [Category("Interop.AsyncSSH")]
    public class AsyncSshServerInteropTests
    {

        private const String Marker = "ASYNCSSH_SERVER_INTEROP_OK";


        #region (private) harness

        private sealed record Peer(WslServer Server, Byte[] HostKeyBlob, String WindowsRoot) : IAsyncDisposable
        {

            public UInt16 Port
                => (UInt16) Server.Port;

            public async ValueTask DisposeAsync()
            {
                await Server.DisposeAsync();
                try { Directory.Delete(WindowsRoot, recursive: true); } catch { }
            }

        }

        /// <summary>
        /// Start the AsyncSSH server with the given configuration (see the script's header for the keys),
        /// and read back the host key it generated.
        /// </summary>
        private static async Task<Peer> StartAsync(Dictionary<String, Object?> Configuration, CancellationToken CancellationToken)
        {

            WslInterop.SkipIfUnavailable();

            var windowsRoot = Path.Combine(Path.GetTempPath(), "hermod_asyncssh_server_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(windowsRoot);

            var hostKeyPath = Path.Combine(windowsRoot, "hostkey.pub");
            var configPath  = Path.Combine(windowsRoot, "config.json");

            Configuration["host_key_path"] = WslInterop.ToWslPath(hostKeyPath);
            Configuration["marker"]        = Marker;

            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(Configuration), CancellationToken);

            var server = await WslInterop.StartServerAsync(
                             port => WslInterop.PythonPeerCommand("asyncssh_server.py", port.ToString(), WslInterop.ToWslPath(configPath)),
                             CancellationToken);

            // Written before the server listens, so a port that answers means a key on disk.
            var hostKeyBlob = Convert.FromBase64String((await File.ReadAllTextAsync(hostKeyPath, CancellationToken)).Split(' ')[1]);

            return new Peer(server, hostKeyBlob, windowsRoot);

        }

        /// <summary>
        /// What the server logged of the authentication, in order ("begin", then "password", …).
        /// </summary>
        private static String[] Requests(Peer Peer)

            => Peer.Server.Output
                   .Split('\n')
                   .Select (line => line.Trim())
                   .Where  (line => line.StartsWith("AUTH ", StringComparison.Ordinal))
                   .Select (line => line.Split(' ')[1])
                   .ToArray();

        #endregion


        #region OurClient_AuthenticatesWithAPassword_OnAsyncSshServer

        [Test]
        [CancelAfter(60000)]
        public async Task OurClient_AuthenticatesWithAPassword_OnAsyncSshServer(CancellationToken CancellationToken)
        {

            await using var peer = await StartAsync(new () {
                                                       ["username"] = "hermoduser",
                                                       ["password"] = "s3cr3t"
                                                   }, CancellationToken);

            await using (var client = await SshClient.ConnectAsync("127.0.0.1", peer.Port, new SshClientOptions {
                                                                       Username       = "hermoduser",
                                                                       VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(peer.HostKeyBlob),
                                                                       Password       = "s3cr3t"
                                                                   }, CancellationToken))
            {

                var result = await client.ExecuteAsync("whoami", CancellationToken);

                Assert.Multiple(() => {
                    Assert.That(result.StandardOutput.Trim(), Is.EqualTo($"{Marker} whoami password"), $"AsyncSSH let us in with the password.\n{peer.Server.Output}");
                    Assert.That(result.ExitCode,              Is.EqualTo(0));
                });

            }

            Assert.That(Requests(peer), Is.EqualTo(new[] { "begin", "password" }), $"the password, once.\n{peer.Server.Output}");

        }

        #endregion

        #region OurClient_AWrongPassword_IsAnAuthenticationError_OnAsyncSshServer

        [Test]
        [CancelAfter(60000)]
        public async Task OurClient_AWrongPassword_IsAnAuthenticationError_OnAsyncSshServer(CancellationToken CancellationToken)
        {

            await using var peer = await StartAsync(new () {
                                                       ["username"] = "hermoduser",
                                                       ["password"] = "s3cr3t"
                                                   }, CancellationToken);

            Assert.That(async () => await SshClient.ConnectAsync("127.0.0.1", peer.Port, new SshClientOptions {
                                              Username       = "hermoduser",
                                              VerifyHostKey  = blob => blob.AsSpan().SequenceEqual(peer.HostKeyBlob),
                                              Password       = "wrong"
                                          }, CancellationToken),
                        Throws.InstanceOf<SshAuthenticationException>(),
                        peer.Server.Output);

        }

        #endregion

        #region OurClient_AuthenticatesWithKeyboardInteractive_OnAsyncSshServer

        /// <summary>
        /// Two prompts, the shape of a PAM stack asking for a password and then a code: our client hands
        /// both to the application as AsyncSSH sent them, and returns the answers in order.
        /// </summary>
        [Test]
        [CancelAfter(60000)]
        public async Task OurClient_AuthenticatesWithKeyboardInteractive_OnAsyncSshServer(CancellationToken CancellationToken)
        {

            await using var peer = await StartAsync(new () {
                                                       ["username"] = "hermoduser",
                                                       ["kbdint"]   = new Dictionary<String, Object> {
                                                                          ["name"]        = "login",
                                                                          ["instruction"] = "Two questions.",
                                                                          ["prompts"]     = new Object[] { new Object[] { "Password: ", false }, new Object[] { "Code: ", true } },
                                                                          ["answers"]     = new[] { "s3cr3t", "424242" }
                                                                      }
                                                   }, CancellationToken);

            SshKeyboardInteractiveChallenge? asked = null;

            await using (var client = await SshClient.ConnectAsync("127.0.0.1", peer.Port, new SshClientOptions {
                                                                       Username             = "hermoduser",
                                                                       VerifyHostKey        = blob => blob.AsSpan().SequenceEqual(peer.HostKeyBlob),
                                                                       KeyboardInteractive  = (challenge, _) => {
                                                                                                  asked = challenge;
                                                                                                  return ValueTask.FromResult(new[] { "s3cr3t", "424242" });
                                                                                              }
                                                                   }, CancellationToken))
            {

                var result = await client.ExecuteAsync("whoami", CancellationToken);
                Assert.That(result.StandardOutput.Trim(), Is.EqualTo($"{Marker} whoami keyboard-interactive"), $"AsyncSSH let us in on the answers.\n{peer.Server.Output}");

            }

            Assert.Multiple(() => {
                Assert.That(asked,                                       Is.Not.Null);
                Assert.That(asked!.Name,                                 Is.EqualTo("login"));
                Assert.That(asked.Instruction,                           Is.EqualTo("Two questions."));
                Assert.That(asked.Prompts.Select(prompt => prompt.Text), Is.EqualTo(new[] { "Password: ", "Code: " }));
                Assert.That(asked.Prompts.Select(prompt => prompt.Echo), Is.EqualTo(new[] { false, true }));
            });

        }

        #endregion

    }

}
