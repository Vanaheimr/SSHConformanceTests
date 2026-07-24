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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.CLI
{

    /// <summary>The implementations of the <c>hermod-ssh</c> verbs, each wiring the library features.</summary>
    public static class Commands
    {

        #region keygen

        /// <summary>Generate a key pair and write it (private + <c>.pub</c>), then print its fingerprint.</summary>
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

        /// <summary>Print a public key's fingerprints and its SSHFP DNS records (the <c>ssh-keygen -r</c> view).</summary>
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

        /// <summary>Issue an OpenSSH certificate: sign a subject public key with a CA key (mini-CA).</summary>
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

        /// <summary>Log in with a key, run a command, capture stdout/stderr + exit code, log out.</summary>
        public static async Task<Int32> ExecAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var identity = Opt(Arguments, "-i", "--identity");
            var portStr  = Opt(Arguments, "-p", "--port") ?? "22";
            var rest     = Positional(Arguments);

            if (identity is null || rest.Count < 2)
                return Usage("exec -i <key> [-p <port>] <user@host> <command...>");

            var (user, host) = SplitTarget(rest[0]);
            var command      = String.Join(' ', rest.Skip(1));

            var key  = SshKeyGenerator.LoadPrivateKey(await File.ReadAllTextAsync(identity, CancellationToken)).Key;
            var pipe = await SshTcp.ConnectAsync(host, IPPort.Parse(portStr), CancellationToken);

            using var transport = await SshTransport.ClientHandshakeAsync(pipe, VerifyHostKey: _ => true, CancellationToken: CancellationToken);
            Console.Error.WriteLine($"Warning: accepting host key of {host} without verification (demo).");

            if (!await UserAuthentication.ClientPublicKeyAuthenticateAsync(transport, user, key, CancellationToken: CancellationToken))
                return Fail("Authentication failed.");

            var result = await SshConnection.ExecuteAsync(transport, command, CancellationToken);
            Console.Out.Write(result.StandardOutput);
            Console.Error.Write(result.StandardError);
            return result.ExitCode;

        }

        #endregion

        #region serve

        /// <summary>Run a demo SSH server: authorize keys and answer <c>exec</c> with a canned handler.</summary>
        public static async Task<Int32> ServeAsync(String[] Arguments, CancellationToken CancellationToken)
        {

            var hostKeyPath = Opt(Arguments, "-k", "--host-key")       ?? "hermod_host_ed25519";
            var authKeys    = Opt(Arguments, "-a", "--authorized-keys");
            var portStr     = Opt(Arguments, "-p", "--port") ?? "2222";

            if (authKeys is null)
                return Usage("serve -a <authorized_keys> [-k <host-key>] [-p <port>]");

            var hostKey       = await SshKeyGenerator.LoadOrCreateHostKeyAsync(hostKeyPath, "ssh-ed25519", CancellationToken);
            var authorized    = (await File.ReadAllLinesAsync(authKeys, CancellationToken))
                                     .Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#'))
                                     .Select(l => SshPublicKey.Parse(l).Blob)
                                     .ToArray();
            var authenticator = SshUserAuthenticator.ForAuthorizedKeys(authorized);

            using var listener = SshTcpListener.Start(new IPSocket(IPv4Address.Any, IPPort.Parse(portStr)));
            Console.WriteLine($"hermod-ssh serve listening on port {portStr} ({authorized.Length} authorized key(s)) — Ctrl+C to stop");

            while (!CancellationToken.IsCancellationRequested)
            {
                var pipe = await listener.AcceptAsync(CancellationToken);
                _ = Task.Run(async () =>
                {
                    try
                    {
                        using var t = await SshTransport.ServerHandshakeAsync(pipe, hostKey, CancellationToken: CancellationToken);
                        await UserAuthentication.ServerAuthenticateAsync(t, authenticator, CancellationToken: CancellationToken);
                        await SshConnection.ServeExecAsync(t, "demo", async (ctx, ct) =>
                        {
                            await ctx.WriteLineAsync($"hermod-ssh demo server — you asked to run: {ctx.Command}", ct);
                            await ctx.WriteLineAsync($"host: {Environment.MachineName}, time: {DateTimeOffset.UtcNow:u}", ct);
                            return 0;
                        }, CancellationToken);
                    }
                    catch (Exception e) { Console.Error.WriteLine($"session ended: {e.Message}"); }
                }, CancellationToken);
            }

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
