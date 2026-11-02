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

using System.Net.Sockets;
using System.Text;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.CLI
{

    /// <summary>
    /// The implementations of the <c>hermod-ssh</c> verbs, each wiring the library features.
    /// </summary>
    public static class Commands
    {

        #region keygen

        /// <summary>
        /// Generate a key pair and write it (private + <c>.pub</c>), then print its fingerprint.
        /// </summary>
        public static async Task<Int32> KeygenAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var type    = Opt(Arguments, "-t", "--type")    ?? "ed25519";
            var path    = Opt(Arguments, "-f", "--file");
            var comment = Opt(Arguments, "-C", "--comment") ?? $"{Environment.UserName}@{Environment.MachineName}";

            if (path is null)
                return Usage("keygen -t <ed25519|ecdsa-sha2-nistp256|ssh-rsa> -f <path> [-C <comment>]");

            var key = SshKeyGenerator.Generate(type);
            await SshKeyGenerator.WriteKeyPairAsync(key, path, comment, CancellationToken);

            Console.WriteLine($"Wrote {path} and {path}.pub");
            Console.WriteLine($"  {key.AlgorithmNames[0]}  {SshFingerprint.Sha256(key.PublicKeyBlob)}  {comment}");
            return 0;

        }

        #endregion

        #region scan

        /// <summary>
        /// Print a public key's fingerprints and its SSHFP DNS records (the <c>ssh-keygen -r</c> view).
        /// </summary>
        public static async Task<Int32> ScanAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var file = Opt(Arguments, "-f", "--file");
            var name = Opt(Arguments, "-n", "--name") ?? "host.example.";

            if (file is null)
                return Usage("scan -f <public-key-file> [-n <hostname>]");

            var line = (await File.ReadAllTextAsync(file, CancellationToken)).Trim();
            if (!SshPublicKey.TryParse(line, out var pub) || pub is null)
                return Fail($"Not a public key file: {file}");

            Console.WriteLine($"Fingerprints:");
            Console.WriteLine($"  {pub.Sha256Fingerprint}");
            Console.WriteLine($"  {pub.Md5Fingerprint}");
            Console.WriteLine($"SSHFP records:");
            foreach (var record in SshfpRecord.FromBlob(pub.Blob))
                Console.WriteLine($"  {record.ToZoneLine(name)}");
            return 0;

        }

        #endregion

        #region ca

        /// <summary>
        /// Issue an OpenSSH certificate: sign a subject public key with a CA key (mini-CA).
        /// </summary>
        public static async Task<Int32> CaAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var caFile      = Opt(Arguments, "--ca");
            var subjectFile = Opt(Arguments, "-s", "--sign");
            var keyId       = Opt(Arguments, "-I", "--identity") ?? "hermod-ca";
            var principals  = (Opt(Arguments, "-n", "--principals") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var isHost      = Has(Arguments, "--host");
            var serial      = UInt64.TryParse(Opt(Arguments, "-z", "--serial"), out var z) ? z : 0UL;
            var validDays   = Int32.TryParse(Opt(Arguments, "-V", "--valid-days"), out var d) ? d : 3650;

            if (caFile is null || subjectFile is null)
                return Usage("ca --ca <ca-key> -s <subject.pub> [-I <key-id>] [-n <principals>] [--host] [-z <serial>] [-V <days>]");

            var caKey    = SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(caFile, CancellationToken)).Key;
            var subject  = SshPublicKey.Parse((await File.ReadAllTextAsync(subjectFile, CancellationToken)).Trim());

            var builder = new OpenSshCertificateBuilder {
                Serial       = serial,
                Type         = isHost ? SshCertType.Host : SshCertType.User,
                KeyId        = keyId,
                Principals   = principals,
                ValidAfter   = DateTimeOffset.UtcNow,
                ValidBefore  = DateTimeOffset.UtcNow.AddDays(validDays)
            };
            if (!isHost)
                foreach (var ext in OpenSshCertificateBuilder.DefaultUserExtensions)
                    builder.Extensions.Add(ext);

            var cert    = builder.Sign(subject.Blob, caKey);
            var outFile = subjectFile.Replace(".pub", "") + "-cert.pub";
            await File.WriteAllTextAsync(outFile, $"{cert.CertAlgorithm} {Convert.ToBase64String(cert.Blob)} {keyId}\n", CancellationToken);

            Console.WriteLine($"Signed {(isHost ? "host" : "user")} certificate → {outFile}");
            Console.WriteLine($"  serial {serial}, key-id \"{keyId}\", principals [{String.Join(", ", principals)}]");
            Console.WriteLine($"  valid  {builder.ValidAfter:u} … {builder.ValidBefore:u}");
            return 0;

        }

        #endregion

        #region exec

        /// <summary>
        /// Log in with a key, run a command, capture stdout/stderr + exit code, log out (over the façade).
        /// </summary>
        public static async Task<Int32> ExecAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var rest = Positional(Arguments);
            if (Opt(Arguments, "-i", "--identity") is null || rest.Count < 2)
                return Usage("exec -i <key> [-p <port>] [-J <jump hosts>] <user@host> <command...>");

            await using var client = await ConnectClientAsync(Arguments, rest[0], CancellationToken);

            var result = await client.ExecuteAsync(String.Join(' ', rest.Skip(1)), CancellationToken);
            Console.Out.Write(result.StandardOutput);
            Console.Error.Write(result.StandardError);
            return result.ExitCode;

        }

        #endregion

        #region connect

        /// <summary>
        /// Open a session and stream it interactively: local stdin → remote, remote stdout/stderr → local.
        /// </summary>
        public static async Task<Int32> ConnectAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var rest = Positional(Arguments);
            if (Opt(Arguments, "-i", "--identity") is null || rest.Count < 1)
                return Usage("connect -i <key> [-p <port>] [-J <jump hosts>] <user@host> [command...]");

            await using var client  = await ConnectClientAsync(Arguments, rest[0], CancellationToken);
            var command             = String.Join(' ', rest.Skip(1));

            var channel = await client.Multiplexer.OpenChannelAsync("session", CancellationToken: CancellationToken);
            await channel.SendRequestAsync(command.Length > 0 ? "exec" : "shell", true,
                                           command.Length > 0 ? SshSessionChannel.EncodeString(command) : [],
                                           CancellationToken);

            // Pump remote → local (stdout + stderr) and local → remote (stdin) until the channel ends.
            var toOut = channel.Input.CopyToAsync(Console.OpenStandardOutput(), CancellationToken);
            var toErr = channel.Error.CopyToAsync(Console.OpenStandardError(), CancellationToken);
            var toIn  = Task.Run(async () =>
            {
                try { await Console.OpenStandardInput().CopyToAsync(channel.AsStream(), CancellationToken); } catch { }
                try { await channel.SendEofAsync(CancellationToken); } catch { }
            }, CancellationToken);

            var exit = 0;
            SshChannelRequest? request;
            while ((request = await channel.ReadRequestAsync(CancellationToken)) is not null)
                if (request.Value.Type == "exit-status")
                    exit = (Int32) ReadUInt32(request.Value.Data);

            await Task.WhenAll(toOut, toErr);
            _ = toIn;
            return exit;

        }

        #endregion

        #region sftp

        /// <summary>
        /// Transfer files over a multiplexed SFTP subsystem: <c>ls</c> / <c>get</c> / <c>put</c>.
        /// </summary>
        public static async Task<Int32> SftpAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var rest = Positional(Arguments);
            if (Opt(Arguments, "-i", "--identity") is null || rest.Count < 2)
                return Usage("sftp -i <key> [-p <port>] [-J <jump hosts>] <user@host> <ls <path> | get <remote> <local> | put <local> <remote>>");

            await using var client = await ConnectClientAsync(Arguments, rest[0], CancellationToken);
            var sftp               = await client.OpenSftpClientAsync(CancellationToken);
            var op                 = rest[1].ToLowerInvariant();

            try
            {
                switch (op)
                {
                    case "ls":
                        foreach (var entry in await sftp.ListDirectoryAsync(rest.ElementAtOrDefault(2) ?? "/", CancellationToken))
                            Console.WriteLine($"  {(entry.Attributes.IsDirectory ? "d" : "-")} {entry.Attributes.Size,12}  {entry.Name}");
                        return 0;

                    case "get" when rest.Count >= 4:
                        await File.WriteAllBytesAsync(rest[3], await sftp.DownloadAsync(rest[2], CancellationToken), CancellationToken);
                        Console.WriteLine($"Downloaded {rest[2]} → {rest[3]}");
                        return 0;

                    case "put" when rest.Count >= 4:
                        await sftp.UploadAsync(rest[3], await File.ReadAllBytesAsync(rest[2], CancellationToken), CancellationToken);
                        Console.WriteLine($"Uploaded {rest[2]} → {rest[3]}");
                        return 0;

                    default:
                        return Usage("sftp … <ls <path> | get <remote> <local> | put <local> <remote>>");
                }
            }
            finally { await sftp.DisposeAsync(); }

        }

        #endregion

        #region forward

        /// <summary>
        /// Port forwarding, either way: <c>-L</c> listens here and tunnels each connection through the server
        /// (<c>ssh -L</c>); <c>-R</c> has the server listen and tunnels each connection back to here
        /// (<c>ssh -R</c>). Port 0 lets the OS, or the server, choose the port.
        /// </summary>
        public static async Task<Int32> ForwardAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            const String usage = "forward -i <key> [-p <port>] [-J <jump hosts>] <-L|-R> [<bind>:]<port>:<host>:<hostport> <user@host>";

            var rest   = Positional(Arguments);
            var local  = Opt(Arguments, "-L", "--local");
            var remote = Opt(Arguments, "-R", "--remote");

            if (Opt(Arguments, "-i", "--identity") is null || rest.Count < 1 || (local is null) == (remote is null))
                return Usage(usage);

            if (!TryParseForward(local ?? remote!, out var bind, out var port, out var host, out var hostPort))
                return Usage(usage);

            // -L binds here, so its bind address is ours to resolve; -R hands its own to the server as typed.
            IIPAddress? bindAddress = null;
            if (local is not null && bind is not null)
            {

                bindAddress = bind switch {
                    "" or "*"    => IPv6Address.Any,
                    "localhost"  => IPv4Address.Localhost,
                    _            => IPAddress.TryParse(bind, out var parsed) ? parsed : null
                };

                if (bindAddress is null)
                    return Fail($"-L binds an IP address, 'localhost' or '*', not '{bind}'");

            }

            await using var client = await ConnectClientAsync(Arguments, rest[0], CancellationToken);

            if (local is not null)
            {
                await using var forward = client.StartLocalForward(new IPSocket(bindAddress ?? IPv4Address.Localhost, IPPort.Parse(port)), host, hostPort);
                Console.WriteLine($"Forwarding {forward.LocalEndPoint} → {host}:{hostPort} (through {rest[0]}) — Ctrl+C to stop");
                await WaitForCtrlCAsync(CancellationToken);
            }
            else
            {
                await using var forward = await client.RequestRemoteForwardAsync(bind ?? "localhost", port, host, hostPort, CancellationToken);
                Console.WriteLine($"Forwarding {forward.BindHost}:{forward.BoundPort} on {rest[0]} → {host}:{hostPort} (here) — Ctrl+C to stop");
                await WaitForCtrlCAsync(CancellationToken);
            }

            return 0;

        }

        // [<bind>:]<port>:<host>:<hostport>, as ssh takes it; an IPv6 bind address or host goes in brackets.
        private static Boolean TryParseForward(String Spec, out String? Bind, out UInt16 Port, out String Host, out UInt16 HostPort)
        {

            Bind     = null;
            Port     = 0;
            Host     = "";
            HostPort = 0;

            var parts = new List<String>();
            var rest  = Spec;

            while (rest.Length > 0)
            {

                String part;

                if (rest.StartsWith('['))
                {
                    var close = rest.IndexOf(']');
                    if (close < 0 || (close + 1 < rest.Length && rest[close + 1] != ':'))
                        return false;
                    part = rest[1..close];
                    rest = close + 1 < rest.Length ? rest[(close + 2)..] : "";
                }
                else
                {
                    var colon = rest.IndexOf(':');
                    part = colon < 0 ? rest      : rest[..colon];
                    rest = colon < 0 ? ""        : rest[(colon + 1)..];
                }

                parts.Add(part);

            }

            if (parts.Count is < 3 or > 4)
                return false;

            if (parts.Count == 4)
                Bind = parts[0];

            Host = parts[^2];

            return UInt16.TryParse(parts[^3], out Port) &&
                   UInt16.TryParse(parts[^1], out HostPort) &&
                   Host.Length > 0;

        }

        private static async Task WaitForCtrlCAsync(CancellationToken CancellationToken)
        {
            try { await Task.Delay(Timeout.Infinite, CancellationToken); }
            catch (OperationCanceledException) { }
        }

        #endregion

        #region play

        /// <summary>
        /// Replay a recorded asciicast v2 session to the terminal, honoring the inter-event timing.
        /// </summary>
        public static async Task<Int32> PlayAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var rest = Positional(Arguments);
            if (rest.Count < 1)
                return Usage("play <recording.cast> [--speed <factor>] [--max-idle <seconds>] [--instant]");

            var path = rest[0];
            if (!File.Exists(path))
                return Fail($"No such recording: {path}");

            var speed   = Double.TryParse(Opt(Arguments, "--speed"),    out var s) && s > 0 ? s : 1.0;
            var maxIdle = Double.TryParse(Opt(Arguments, "--max-idle"), out var m) && m > 0 ? m : Double.PositiveInfinity;
            var instant = Has(Arguments, "--instant");

            var recording = AsciicastReader.Parse(await File.ReadAllTextAsync(path, CancellationToken));

            // The banner goes to stderr so it never pollutes the replayed terminal stream on stdout.
            Console.Error.WriteLine($"▶ Replaying {path} — {recording.Header.Width}x{recording.Header.Height}"
                                    + (recording.Header.Command is { } cmd ? $", command: {cmd}" : "")
                                    + $" ({recording.Events.Count} event(s))");

            var stdout   = Console.OpenStandardOutput();
            var previous = 0.0;

            foreach (var e in recording.Events)
            {

                if (e.Code != AsciicastEventCode.Output)
                    continue;

                if (!instant)
                {
                    // ElapsedSeconds is absolute from the start, so the gap is correct even across skipped events.
                    var gap = Math.Min(e.ElapsedSeconds - previous, maxIdle) / speed;
                    if (gap > 0)
                        await Task.Delay(TimeSpan.FromSeconds(gap), CancellationToken);
                }
                previous = e.ElapsedSeconds;

                var bytes = Encoding.UTF8.GetBytes(e.Data);
                await stdout.WriteAsync(bytes, CancellationToken);
                await stdout.FlushAsync(CancellationToken);

            }

            if (recording.ExitStatus is { } exit)
            {
                Console.Error.WriteLine($"▶ Recorded exit status: {exit}");
                return exit;
            }

            return 0;

        }

        #endregion


        #region (shared) ConnectClientAsync

        // Connect + authenticate a façade SshClient from the common -i/-p options and a user@host target.
        private static async Task<SshClient> ConnectClientAsync(String[] Arguments, String Target, CancellationToken CancellationToken)
        {
            var identity     = Opt(Arguments, "-i", "--identity")!;
            var portStr      = Opt(Arguments, "-p", "--port") ?? "22";
            var jumpHosts    = Opt(Arguments, "-J", "--jump");
            var (user, host) = SplitTarget(Target);
            var key          = SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(identity, CancellationToken)).Key;

            Console.Error.WriteLine($"Warning: accepting host key of {host}{(jumpHosts is null ? "" : $" and of every jump host ({jumpHosts})")} without verification (demo) — "
                                    + "this connection is not protected against a machine-in-the-middle.");
            return await SshClient.ConnectAsync(host, UInt16.Parse(portStr), new SshClientOptions {
                Username      = user,
                VerifyHostKey = SshHostKeyVerification.AcceptAnyUnsafe,
                Credentials   = [ key ],
                // -J [user@]host[:port],… as ssh takes it; every jump host borrows the key above.
                ProxyJump     = jumpHosts is null ? [] : SshJumpHost.ParseChain(jumpHosts)
            }, CancellationToken);
        }

        private static UInt32 ReadUInt32(Byte[] Data) { var r = new SshPacketReader(Data); return r.ReadUInt32(); }

        #endregion

        #region serve

        /// <summary>
        /// Run a demo SSH server (façade): authorize keys, answer <c>exec</c>, and optionally serve SFTP + forwarding.
        /// </summary>
        public static async Task<Int32> ServeAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var hostKeyPath = Opt(Arguments, "-k", "--host-key")       ?? "hermod_host_ed25519";
            var authKeys    = Opt(Arguments, "-a", "--authorized-keys");
            var portStr     = Opt(Arguments, "-p", "--port") ?? "2222";
            var sftpRoot    = Opt(Arguments, "--sftp-root");

            if (authKeys is null)
                return Usage("serve -a <authorized_keys> [-k <host-key>] [-p <port>] [--sftp-root <dir>]");

            var hostKey    = await SshKeyGenerator.LoadOrCreateHostKeyAsync(hostKeyPath, "ssh-ed25519", CancellationToken);
            var authorized = (await File.ReadAllLinesAsync(authKeys, CancellationToken))
                                 .Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#'))
                                 .Select(l => SshPublicKey.Parse(l).Blob)
                                 .ToArray();

            await using var server = new SshServer(new SshServerOptions {
                HostKeys         = [ hostKey ],
                Authenticator    = SshUserAuthenticator.ForAuthorizedKeys(authorized),
                ExecHandler      = async (ctx, ct) =>
                {
                    await ctx.WriteLineAsync($"hermod-ssh demo server — you asked to run: {ctx.Command}", ct);
                    await ctx.WriteLineAsync($"host: {Environment.MachineName}, time: {DateTimeOffset.UtcNow:u}", ct);
                    return 0;
                },
                SftpFileSystem   = sftpRoot is null ? null : new LocalSftpFileSystem(sftpRoot),
                ForwardingPolicy = ForwardingPolicy.LoopbackOnly
            });

            await server.StartAsync(new IPSocket(IPv4Address.Any, IPPort.Parse(portStr)), CancellationToken);
            Console.WriteLine($"hermod-ssh serve listening on port {portStr} ({authorized.Length} authorized key(s)"
                              + $"{(sftpRoot is null ? "" : $", SFTP root {sftpRoot}")}) — Ctrl+C to stop");

            try { await Task.Delay(Timeout.Infinite, CancellationToken); }
            catch (OperationCanceledException) { }
            return 0;

        }

        #endregion


        #region (private) arg helpers

        private static String? Opt(String[] Args, params String[] Names)
        {
            for (var i = 0; i < Args.Length - 1; i++)
                if (Names.Contains(Args[i]))
                    return Args[i + 1];
            return null;
        }

        private static Boolean Has(String[] Args, params String[] Names)
            => Args.Any(Names.Contains);

        // Positional arguments = those after the verb that are not options or option-values.
        private static List<String> Positional(String[] Args)
        {
            var result = new List<String>();
            for (var i = 1; i < Args.Length; i++)   // skip the verb at [0]
            {
                if (Args[i].StartsWith('-'))
                {
                    i++;   // skip the option value too
                    continue;
                }
                result.Add(Args[i]);
            }
            return result;
        }

        private static (String User, String Host) SplitTarget(String Target)
        {
            var at = Target.IndexOf('@');
            return at < 0 ? (Environment.UserName, Target) : (Target[..at], Target[(at + 1)..]);
        }

        private static Int32 Usage(String Line)
        {
            Console.Error.WriteLine($"Usage: hermod-ssh {Line}");
            return 64;   // EX_USAGE
        }

        private static Int32 Fail(String Message)
        {
            Console.Error.WriteLine(Message);
            return 1;
        }

        #endregion

    }

}
