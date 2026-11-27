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

using System.Text;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// Hermod's own time-based one-time password - every parameter of its configuration, not bound to the
    /// session - between our implementation and an unmodified OpenSSH that the SSHTOTPTool
    /// (<c>hermod-ssh-totp</c>) teaches it: <c>sshd</c> checks the token through <c>pam_exec</c>, <c>ssh</c>
    /// sends it through <c>SSH_ASKPASS</c>. Three directions:
    /// <list type="bullet">
    ///   <item>the real <c>ssh</c>, with the tool as its askpass, signs in to our server, whose second
    ///         factor is <see cref="HermodTotpKeyboardInteractive"/>;</item>
    ///   <item>our client answers the keyboard-interactive prompt of a real <c>sshd</c> whose PAM stack is
    ///         the tool;</item>
    ///   <item>the real <c>ssh</c> and the real <c>sshd</c>, both with the tool and neither with us - what
    ///         the tool is for.</item>
    /// </list>
    /// </summary>
    /// <remarks>
    /// <para>
    /// An <c>sshd</c> asks PAM under the service name <c>sshd</c> whatever it is started as (checked against
    /// 10.0p2, <c>SshdAuthPath</c> included), so the two cases with a real <c>sshd</c> rewrite
    /// <c>/etc/pam.d/sshd</c> for as long as they run - which they do only where that harms nobody: as root,
    /// on Linux, in a container (the CI's Debian leg), or where <c>HERMOD_INTEROP_PAM=1</c> says this machine
    /// may have it rewritten. Everywhere else they skip and say why. Other fixtures' <c>sshd</c>s run with
    /// <c>UsePAM no</c> and are untouched by it.
    /// </para>
    /// <para>
    /// OpenSSH 9.8 and later punish an address for failed sign-ins (<c>PerSourcePenalties</c>), and the
    /// refusals here are deliberate: the <c>sshd</c> of this fixture has the penalties off, or the next
    /// sign-in from 127.0.0.1 would be dropped before it began. An older <c>sshd</c>, as the nightly's 8.9
    /// and 9.6 lanes run, has no such keyword and would not start with it, so it is set only where
    /// <c>sshd -t</c> takes it.
    /// </para>
    /// </remarks>
    [TestFixture]
    [NonParallelizable]
    [Category("Interop")]
    [Category("Interop.OpenSSH")]
    [Category("Interop.TOTP")]
    public class OpenSshTotpInteropTests
    {

        #region Data

        private const String Marker = "HERMOD-TOTP-LOGIN-OK";

        /// <summary>
        /// A configuration that leaves no parameter at its default, so that each of them has to reach
        /// the other end: 10 characters of a 31-character alphabet, HMAC-SHA384, 20-second slots.
        /// </summary>
        private static TOTPConfig NewConfig()
            => new (RandomNumberGenerator.GetString("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 32),
                    TimeSpan.FromSeconds(20),
                    10,
                    "abcdefghjkmnpqrstuvwxyz23456789",
                    TOTPHashAlgorithm.SHA384);

        #endregion


        #region (private) the tool, ssh and the workspace

        /// <summary>
        /// The tool as a program to start: the apphost on Windows; on Linux a script that starts it with
        /// this very dotnet, because pam_exec hands the program a bare environment in which an apphost might
        /// not find the runtime.
        /// </summary>
        private static String ToolCommand(String Workspace)
        {

            if (OperatingSystem.IsWindows())
            {
                var exe = Path.Combine(AppContext.BaseDirectory, "hermod-ssh-totp.exe");
                if (!File.Exists(exe))
                    Assert.Ignore($"The tool's apphost is not next to the tests: {exe}");
                return exe;
            }

            var dll    = Path.Combine(AppContext.BaseDirectory, "hermod-ssh-totp.dll");
            var dotnet = FindDotnet() ?? throw new IgnoreException("No dotnet host found to start the tool with.");
            var script = Path.Combine(Workspace, "hermod-ssh-totp");

            File.WriteAllText(script, $"#!/bin/sh\nexec '{dotnet}' '{dll}' \"$@\"\n");
            File.SetUnixFileMode(script, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                         UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                                         UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
            return script;

        }

        private static String? FindDotnet()
        {

            if (Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") is { Length: > 0 } host && File.Exists(host))
                return host;

            if (Environment.ProcessPath is { } process && Path.GetFileNameWithoutExtension(process) == "dotnet")
                return process;

            return FindOnPath("dotnet");

        }

        private static String? FindOnPath(String Tool)
        {

            foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
            {
                foreach (var name in new[] { Tool, Tool + ".exe" })
                {
                    try
                    {
                        var candidate = Path.Combine(directory.Trim(), name);
                        if (File.Exists(candidate))
                            return candidate;
                    }
                    catch { /* a malformed PATH entry */ }
                }
            }

            if (OperatingSystem.IsWindows())
            {
                var system = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OpenSSH", Tool + ".exe");
                return File.Exists(system) ? system : null;
            }

            // Debian keeps sshd in /usr/sbin, which a non-root PATH does not have.
            foreach (var directory in new[] { "/usr/sbin", "/usr/local/sbin", "/sbin" })
                if (File.Exists(Path.Combine(directory, Tool)))
                    return Path.Combine(directory, Tool);

            return null;

        }

        private static String NewWorkspace()
        {

            var directory = Path.Combine(Path.GetTempPath(), "hermod_totp_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            // sshd as root opens what is under it, and walks up to it.
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                                                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                                                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

            return directory;

        }

        /// <summary>
        /// Write a configuration as the tool reads it: owner-only, or it refuses the file.
        /// </summary>
        private static String WriteConfig(String Path, TOTPConfig Config)
        {

            File.WriteAllText(Path, Config.ToJSON().ToString(), new UTF8Encoding(false));

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            return Path;

        }

        /// <summary>
        /// Start the real ssh with the tool as its askpass, signing in as the given user with the given key
        /// and the token of the given configuration.
        /// </summary>
        private static async Task<(Int32 ExitCode, String StandardOutput, String StandardError)> RunSshAsync(String             Ssh,
                                                                                                           String             Tool,
                                                                                                           String             ConfigPath,
                                                                                                           String             KeyPath,
                                                                                                           String             User,
                                                                                                           Int32              Port,
                                                                                                           String             Workspace,
                                                                                                           CancellationToken  CancellationToken,
                                                                                                           params String[]    ExtraOptions)
        {

            var emptyConfig = Path.Combine(Workspace, "ssh_config_" + Guid.NewGuid().ToString("N"));
            File.WriteAllText(emptyConfig, "");

            var start = new ProcessStartInfo(Ssh) {
                            RedirectStandardInput   = true,
                            RedirectStandardOutput  = true,
                            RedirectStandardError   = true,
                            UseShellExecute         = false,
                            CreateNoWindow          = true
                        };

            foreach (var argument in new[] {
                                         "-F", emptyConfig,
                                         "-p", Port.ToString(),
                                         "-i", KeyPath,
                                         "-o", "IdentitiesOnly=yes",
                                         "-o", "StrictHostKeyChecking=no",
                                         "-o", $"UserKnownHostsFile={Path.Combine(Workspace, "known_hosts")}",
                                         "-o", "PreferredAuthentications=publickey,keyboard-interactive",
                                         "-o", "PasswordAuthentication=no",
                                         // BatchMode would turn keyboard-interactive off - and with it the token.
                                         "-o", "BatchMode=no",
                                         "-o", "NumberOfPasswordPrompts=1",
                                         "-o", "ConnectTimeout=10",
                                         "-v"
                                     }.Concat(ExtraOptions).Concat([ $"{User}@127.0.0.1", $"echo {Marker}" ]))
                start.ArgumentList.Add(argument);

            // ssh starts the askpass program with the prompt as its only argument; everything else the tool
            // needs comes from the environment ssh passes on.
            start.Environment["SSH_ASKPASS"]                = Tool;
            start.Environment["SSH_ASKPASS_REQUIRE"]        = "force";
            start.Environment["DISPLAY"]                    = "hermod-totp-interop:0";
            start.Environment["HERMOD_SSH_TOTP_CONFIG"]     = ConfigPath;

            using var process = Process.Start(start)!;
            process.StandardInput.Close();

            var output = process.StandardOutput.ReadToEndAsync(CancellationToken);
            var error  = process.StandardError. ReadToEndAsync(CancellationToken);

            try
            {
                await process.WaitForExitAsync(CancellationToken);
            }
            finally
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            }

            return (process.ExitCode, await output, await error);

        }

        #endregion

        #region (private) an sshd whose PAM stack is the tool

        /// <summary>
        /// Why a real sshd with the tool in its PAM stack cannot run here, or null when it can.
        /// </summary>
        private static String? WhyNoPamSshd()
        {

            if (!OperatingSystem.IsLinux())
                return "sshd with the tool in its PAM stack runs on Linux only (the CI's Debian leg; locally a debian:13 container): " +
                       "it rewrites /etc/pam.d/sshd, which over the WSL bridge would be the developer's own.";

            if (!Environment.IsPrivilegedProcess)
                return "sshd with the tool in its PAM stack needs root: it rewrites /etc/pam.d/sshd for as long as it runs.";

            if (!File.Exists("/.dockerenv") && !File.Exists("/run/.containerenv") && Environment.GetEnvironmentVariable("HERMOD_INTEROP_PAM") != "1")
                return "Not in a container: /etc/pam.d/sshd is only rewritten in one, or where HERMOD_INTEROP_PAM=1 says this machine may have it rewritten.";

            if (FindOnPath("sshd") is null)
                return "No sshd found.";

            if (!File.Exists("/etc/pam.d/sshd"))
                return "No /etc/pam.d/sshd: is openssh-server installed with PAM?";

            return null;

        }

        private sealed class PamSshd : IAsyncDisposable
        {

            public required Process      Process      { get; init; }
            public required Int32        Port         { get; init; }
            public required String       User         { get; init; }
            public required ISshHostKey  UserKey      { get; init; }
            public required String       UserKeyPath  { get; init; }
            public required Byte[]       HostKeyBlob  { get; init; }
            public required String       PamLog       { get; init; }
            public required String       PamBackup    { get; init; }
            public required StringBuilder Log         { get; init; }

            public String PamLogText
                => File.Exists(PamLog) ? File.ReadAllText(PamLog) : "(pam_exec logged nothing)";

            public String Logs
            {
                get
                {
                    lock (Log)
                        return $"sshd:\n{Log}\npam_exec:\n{PamLogText}";
                }
            }

            /// <summary>
            /// Run the given part of a test; whatever it throws besides NUnit's own outcomes comes back as
            /// a failure that carries both logs - which a connection sshd closed says nothing about.
            /// </summary>
            public async Task ExplainingFailures(Func<Task> Body)
            {
                try
                {
                    await Body();
                }
                catch (Exception e) when (e is not ResultStateException)
                {
                    throw new AssertionException($"{e.GetType().Name}: {e.Message}\n{Logs}", e);
                }
            }

            public async ValueTask DisposeAsync()
            {

                try { if (!Process.HasExited) Process.Kill(entireProcessTree: true); } catch { }
                try { await Process.WaitForExitAsync(); } catch { }
                Process.Dispose();

                File.Copy(PamBackup, "/etc/pam.d/sshd", overwrite: true);

            }

        }

        /// <summary>
        /// Start an sshd that takes the user's key and then the token of the user's configuration file
        /// (%u.json in the workspace) through pam_exec and the tool.
        /// </summary>
        private static async Task<PamSshd> StartPamSshdAsync(String Workspace, String Tool, CancellationToken CancellationToken)
        {

            if (WhyNoPamSshd() is String why)
                Assert.Ignore(why);

            var user        = Environment.UserName;
            var userKey     = SshHostKey.GenerateEd25519();
            var userKeyPath = Path.Combine(Workspace, "user_ed25519");
            await SshKeyGenerator.WriteKeyPairAsync(userKey, userKeyPath, "hermod-totp-interop", CancellationToken);
            File.Copy(userKeyPath + ".pub", Path.Combine(Workspace, "authorized_keys"));

            var hostKey     = SshHostKey.GenerateEd25519();
            var hostKeyPath = Path.Combine(Workspace, "host_ed25519");
            await SshKeyGenerator.WriteKeyPairAsync(hostKey, hostKeyPath, "hermod-totp-interop-host", CancellationToken);

            // The tool's line, as the README puts it; %u is the tool's own token, filled from PAM_USER. Written
            // with LF whatever this source file came with: Linux-PAM 1.4 (Ubuntu 22.04) takes a CR at the end of
            // "@include common-account" for part of the file name and fails pam_start, where 1.7 forgives it.
            var pamLog      = Path.Combine(Workspace, "pam_exec.log");
            var pamBackup   = Path.Combine(Workspace, "pam.d-sshd.orig");
            File.Copy("/etc/pam.d/sshd", pamBackup);
            File.WriteAllText("/etc/pam.d/sshd",
                              $"""
                              # Written by OpenSshTotpInteropTests for as long as it runs; the original is {pamBackup}.
                              auth     required  pam_exec.so expose_authtok quiet log={pamLog} {Tool} verify --config {Workspace}/%u.json
                              auth     optional  pam_permit.so
                              @include common-account
                              @include common-session

                              """.ReplaceLineEndings("\n"));

            var port        = FreePort();
            var config      = Path.Combine(Workspace, "sshd_config");
            var sshd        = FindOnPath("sshd")!;
            var settings    = $"""
                               Port {port}
                               ListenAddress 127.0.0.1
                               HostKey {hostKeyPath}
                               PidFile {Workspace}/sshd.pid
                               AuthorizedKeysFile {Workspace}/authorized_keys
                               StrictModes no
                               PermitRootLogin yes
                               UsePAM yes
                               KbdInteractiveAuthentication yes
                               PasswordAuthentication no
                               AuthenticationMethods publickey,keyboard-interactive:pam
                               PrintMotd no
                               LogLevel VERBOSE

                               """.ReplaceLineEndings("\n");

            // Run as root, sshd refuses even "sshd -t" without its privilege-separation directory.
            Directory.CreateDirectory("/run/sshd");

            // The penalties came with 9.8; an older sshd takes the keyword for a mistake and does not start
            // ("Bad configuration option: PerSourcePenalties"), and has no penalties to switch off anyway.
            // Asked of the sshd itself rather than inferred from a version, as the nightly's source builds
            // and distribution packages need not agree on what a version number means.
            File.WriteAllText(config, settings + "PerSourcePenalties no\n");

            if (!await SshdAcceptsAsync(sshd, config, CancellationToken))
                File.WriteAllText(config, settings);

            var start = new ProcessStartInfo(sshd) {
                            RedirectStandardError  = true,
                            RedirectStandardOutput = true,
                            UseShellExecute        = false
                        };
            foreach (var argument in new[] { "-D", "-e", "-f", config })
                start.ArgumentList.Add(argument);

            var log     = new StringBuilder();
            var process = Process.Start(start)!;
            process.ErrorDataReceived  += (_, e) => { if (e.Data is not null) lock (log) log.AppendLine(e.Data); };
            process.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (log) log.AppendLine(e.Data); };
            process.BeginErrorReadLine();
            process.BeginOutputReadLine();

            var daemon  = new PamSshd {
                              Process      = process,
                              Port         = port,
                              User         = user,
                              UserKey      = userKey,
                              UserKeyPath  = userKeyPath,
                              HostKeyBlob  = hostKey.PublicKeyBlob,
                              PamLog       = pamLog,
                              PamBackup    = pamBackup,
                              Log          = log
                          };

            for (var attempt = 0; attempt < 100; attempt++)
            {

                if (process.HasExited)
                {
                    await daemon.DisposeAsync();
                    Assert.Fail($"sshd did not start:\n{log}");
                }

                try
                {
                    using var probe = new TcpClient();
                    await probe.ConnectAsync("127.0.0.1", port, CancellationToken);
                    return daemon;
                }
                catch (SocketException)
                {
                    await Task.Delay(100, CancellationToken);
                }

            }

            await daemon.DisposeAsync();
            Assert.Fail($"sshd did not listen on {port}:\n{log}");
            return null!;

        }

        /// <summary>
        /// Whether the given sshd takes the given configuration file (<c>sshd -t</c>).
        /// </summary>
        private static async Task<Boolean> SshdAcceptsAsync(String Sshd, String Config, CancellationToken CancellationToken)
        {

            var start = new ProcessStartInfo(Sshd) {
                            RedirectStandardError  = true,
                            RedirectStandardOutput = true,
                            UseShellExecute        = false
                        };

            foreach (var argument in new[] { "-t", "-f", Config })
                start.ArgumentList.Add(argument);

            using var process = Process.Start(start)!;
            var output = process.StandardOutput.ReadToEndAsync(CancellationToken);
            var error  = process.StandardError. ReadToEndAsync(CancellationToken);
            await process.WaitForExitAsync(CancellationToken);

            if (process.ExitCode != 0)
                TestContext.Out.WriteLine($"sshd -t refused {Config}: {(await error).Trim()} {(await output).Trim()}");

            return process.ExitCode == 0;

        }

        private static Int32 FreePort()
        {
            using var listener = SshTcpListener.Start(new IPSocket(IPv4Address.Localhost, IPPort.Auto));
            return listener.LocalEndPoint.Port.ToInt32();
        }

        #endregion


        #region RealSshClient_WithTheToolAsAskpass_SignsInToOurServer

        /// <summary>
        /// The real ssh signs in to our server - publickey, then the token over keyboard-interactive - with
        /// the token the tool writes for our server's prompt; the token of another secret gets nowhere.
        /// </summary>
        [TestCase(true,  TestName = "RealSshClient_WithTheToolAsAskpass_SignsInToOurServer(the right secret)")]
        [TestCase(false, TestName = "RealSshClient_WithTheToolAsAskpass_SignsInToOurServer(another secret)")]
        [CancelAfter(60000)]
        public async Task RealSshClient_WithTheToolAsAskpass_SignsInToOurServer(Boolean RightSecret, CancellationToken CancellationToken)
        {

            var ssh       = FindOnPath("ssh");
            if (ssh is null)
                Assert.Ignore("No 'ssh' found.");

            var workspace = NewWorkspace();

            try
            {

                var tool        = ToolCommand(workspace);
                var config      = NewConfig();
                var clientPath  = WriteConfig(Path.Combine(workspace, "client.json"), RightSecret ? config : NewConfig());

                var userKey     = SshHostKey.GenerateEd25519();
                var keyPath     = Path.Combine(workspace, "user_ed25519");
                await SshKeyGenerator.WriteKeyPairAsync(userKey, keyPath, "hermod-totp-interop", CancellationToken);


                var authenticator = new SshAuthenticationPolicy()
                                        .WithPublicKey((request, _) => ValueTask.FromResult(request.PublicKeyBlob.AsSpan().SequenceEqual(userKey.PublicKeyBlob)))
                                        .WithSecondFactor(user => new HermodTotpKeyboardInteractive(config));

                using var listener = SshTcpListener.Start(new IPSocket(IPv4Address.Localhost, IPPort.Auto));
                var port           = listener.LocalEndPoint.Port.ToInt32();
                var hostKey        = SshHostKey.GenerateEd25519();

                var serverTask = Task.Run(async () => {
                    var pipe = await listener.AcceptAsync(CancellationToken);
                    using var transport = await SshTransport.ServerHandshakeAsync(pipe, hostKey, CancellationToken: CancellationToken);
                    return await UserAuthentication.ServerAuthenticateAsync(transport, authenticator, CancellationToken: CancellationToken);
                }, CancellationToken);

                var sshTask    = RunSshAsync(ssh!, tool, clientPath, keyPath, "alice", port, workspace, CancellationToken);

                if (RightSecret)
                {

                    // Our server returns once both factors are in - the proof; ssh then waits for a session
                    // nobody here serves, and is stopped.
                    var result = await serverTask.WaitAsync(TimeSpan.FromSeconds(30), CancellationToken);

                    Assert.Multiple(() => {
                        Assert.That(result.Username, Is.EqualTo(User_Id.Parse("alice")));
                        Assert.That(result.Method,   Is.EqualTo("keyboard-interactive"), "the token completed the chain publickey,keyboard-interactive");
                    });

                }
                else
                {

                    var (exitCode, _, stderr) = await sshTask;

                    Assert.That(exitCode, Is.Not.Zero, $"ssh with the token of another secret got in:\n{stderr}");
                    Assert.That(async () => await serverTask.WaitAsync(TimeSpan.FromSeconds(30), CancellationToken), Throws.Exception,
                                "our server let nobody in");

                }

            }
            finally
            {
                try { Directory.Delete(workspace, recursive: true); } catch { }
            }

        }

        #endregion

        #region OurClient_AnswersTheToken_ToRealSshdWithTheToolInItsPamStack

        /// <summary>
        /// Our client signs in to a real sshd: its key, then - asked by PAM, through pam_exec, with pam_exec's
        /// own prompt "Password: " - the token of the configuration the tool checks it against. The token of
        /// another secret is refused.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task OurClient_AnswersTheToken_ToRealSshdWithTheToolInItsPamStack(CancellationToken CancellationToken)
        {

            if (WhyNoPamSshd() is String why)
                Assert.Ignore(why);

            var workspace = NewWorkspace();

            try
            {

                var tool          = ToolCommand(workspace);
                var config        = NewConfig();

                await using var daemon = await StartPamSshdAsync(workspace, tool, CancellationToken);
                WriteConfig(Path.Combine(workspace, daemon.User + ".json"), config);

                var prompts       = new List<String>();

                SSHClientOptions OptionsWith(TOTPConfig Config)
                    => new () {
                           Username             = User_Id.Parse(daemon.User),
                           Credentials          = [ daemon.UserKey ],
                           VerifyHostKey        = blob => blob.AsSpan().SequenceEqual(daemon.HostKeyBlob),
                           KeyboardInteractive  = (challenge, cancellationToken) => {
                                                      prompts.AddRange(challenge.Prompts.Select(prompt => prompt.Text));
                                                      return HermodTotpKeyboardInteractive.Answer(Config)(challenge, cancellationToken);
                                                  }
                       };

                await daemon.ExplainingFailures(async () => {

                    await using (var client = await SSHClient.Connect("127.0.0.1", IPPort.Parse(daemon.Port.ToString()), OptionsWith(config), CancellationToken))
                    {

                        var result = await client.Execute($"echo {Marker}", CancellationToken);

                        Assert.Multiple(() => {
                            Assert.That(result.StandardOutput, Does.Contain(Marker), $"signed in, and a command ran.\n{daemon.Logs}");
                            Assert.That(prompts,               Has.Some.Contains("Password"), "pam_exec's prompt reached our client");
                            Assert.That(daemon.PamLogText,     Does.Contain($"accepted for {daemon.User}"), "the tool checked the token");
                        });

                    }

                    Assert.That(async () => await SSHClient.Connect("127.0.0.1", IPPort.Parse(daemon.Port.ToString()), OptionsWith(NewConfig()), CancellationToken),
                                Throws.InstanceOf<SshAuthenticationException>(),
                                $"the token of another secret.\n{daemon.Logs}");

                    Assert.That(daemon.PamLogText, Does.Contain($"refused for {daemon.User}"), "and the tool said so");

                });

            }
            finally
            {
                try { Directory.Delete(workspace, recursive: true); } catch { }
            }

        }

        #endregion

        #region RealSshClient_AndRealSshd_BothWithTheTool

        /// <summary>
        /// Neither end is ours: the real ssh with the tool as its askpass signs in to the real sshd with the
        /// tool in its PAM stack - publickey and the token, both ends reading the same configuration. The
        /// token of another secret is refused, and so is the key alone.
        /// </summary>
        [Test]
        [CancelAfter(120000)]
        public async Task RealSshClient_AndRealSshd_BothWithTheTool(CancellationToken CancellationToken)
        {

            if (WhyNoPamSshd() is String why)
                Assert.Ignore(why);

            var ssh = FindOnPath("ssh");
            if (ssh is null)
                Assert.Ignore("No 'ssh' found.");

            var workspace = NewWorkspace();

            try
            {

                var tool          = ToolCommand(workspace);
                var config        = NewConfig();

                await using var daemon = await StartPamSshdAsync(workspace, tool, CancellationToken);
                WriteConfig(Path.Combine(workspace, daemon.User + ".json"), config);

                // The client's copy, found the way the README suggests: by host and user, from OpenSSH's own
                // "(user@host) " in front of the prompt.
                Directory.CreateDirectory(Path.Combine(workspace, "client", "127.0.0.1"));
                WriteConfig(Path.Combine(workspace, "client", "127.0.0.1", daemon.User + ".json"), config);
                WriteConfig(Path.Combine(workspace, "other.json"), NewConfig());

                var clientPath = Path.Combine(workspace, "client", "%h", "%u.json");

                var signedIn   = await RunSshAsync(ssh!, tool, clientPath,                            daemon.UserKeyPath, daemon.User, daemon.Port, workspace, CancellationToken);
                var otherKey   = await RunSshAsync(ssh!, tool, Path.Combine(workspace, "other.json"), daemon.UserKeyPath, daemon.User, daemon.Port, workspace, CancellationToken);
                var keyAlone   = await RunSshAsync(ssh!, tool, clientPath,                            daemon.UserKeyPath, daemon.User, daemon.Port, workspace, CancellationToken,
                                                   "-o", "KbdInteractiveAuthentication=no");

                Assert.Multiple(() => {
                    Assert.That(signedIn.StandardOutput, Does.Contain(Marker),     $"ssh and sshd, both with the tool.\nssh:\n{signedIn.StandardError}\n{daemon.Logs}");
                    Assert.That(otherKey.StandardOutput, Does.Not.Contain(Marker), "the token of another secret");
                    Assert.That(otherKey.ExitCode,       Is.Not.Zero);
                    Assert.That(keyAlone.StandardOutput, Does.Not.Contain(Marker), "the key alone");
                    Assert.That(keyAlone.ExitCode,       Is.Not.Zero);
                });

            }
            finally
            {
                try { Directory.Delete(workspace, recursive: true); } catch { }
            }

        }

        #endregion

    }

}
