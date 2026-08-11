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

using System.Reflection;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.CLI
{

    /// <summary>
    /// The <c>hermod-ssh</c> demo command-line tool: set up a demo SSH/SFTP server and connect
    /// clients against it (or against real OpenSSH). The individual verbs are implemented as the
    /// corresponding library features land per milestone; this scaffold prints the planned surface.
    /// </summary>
    public static class Program
    {

        /// <summary>
        /// The command-line entry point.
        /// </summary>
        /// <param name="Arguments">The command-line arguments.</param>
        public static async Task<Int32> Main(String[] Arguments)
        {

            var command = Arguments.Length > 0 ? Arguments[0].ToLowerInvariant() : "help";

            using var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

            try
            {
                switch (command)
                {

                    case "version":
                    case "--version":
                    case "-v":
                        Console.WriteLine($"hermod-ssh {Version}");
                        return 0;

                    case "help":
                    case "--help":
                    case "-h":
                        PrintHelp();
                        return 0;

                    case "keygen":  return await Commands.KeygenAsync (Arguments, cts.Token);
                    case "scan":    return await Commands.ScanAsync   (Arguments, cts.Token);
                    case "ca":      return await Commands.CaAsync     (Arguments, cts.Token);
                    case "exec":    return await Commands.ExecAsync   (Arguments, cts.Token);
                    case "serve":   return await Commands.ServeAsync  (Arguments, cts.Token);
                    case "connect": return await Commands.ConnectAsync(Arguments, cts.Token);
                    case "sftp":    return await Commands.SftpAsync   (Arguments, cts.Token);
                    case "forward": return await Commands.ForwardAsync(Arguments, cts.Token);
                    case "play":    return await Commands.PlayAsync   (Arguments, cts.Token);

                    default:
                        Console.Error.WriteLine($"Unknown command '{command}'.");
                        PrintHelp();
                        return 64;  // EX_USAGE

                }
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("Cancelled.");
                return 130;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine($"error: {e.Message}");
                return 1;
            }

        }


        private static String Version

            => Assembly.GetExecutingAssembly().
                        GetName().Version?.ToString() ?? "0.0.0";


        private static void PrintHelp()
        {

            Console.WriteLine($"""
                hermod-ssh {Version} — HermodSSH demo command-line tool

                Usage:
                  hermod-ssh <command> [options]

                Commands:
                  keygen     Generate host/user keys (Ed25519/ECDSA/RSA) and export any format   [ready]
                  scan       Print a public key's fingerprints and its SSHFP DNS records          [ready]
                  ca         Issue an OpenSSH certificate — sign a subject key with a CA (mini-CA) [ready]
                  exec       Log in, run a command, capture stdout/stderr + exit code, log out     [ready]
                  serve      Run a demo SSH server (authorized_keys auth, exec + SFTP + forwarding) [ready]
                  connect    Open an interactive session (stdin/stdout streamed)                   [ready]
                  sftp       Transfer files over SFTP (ls / get / put)                             [ready]
                  forward    Local port forwarding (ssh -L)                                        [ready]
                  play       Replay a recorded asciicast session                                  [ready]

                  help       Show this help
                  version    Show the version

                Examples:
                  hermod-ssh keygen -t ed25519 -f ./id_ed25519
                  hermod-ssh scan   -f ./id_ed25519.pub -n host.example.
                  hermod-ssh ca --ca ./ca -s ./id_ed25519.pub -I alice@2026 -n alice,admin
                  hermod-ssh serve  -a ./authorized_keys -p 2222 --sftp-root ./root
                  hermod-ssh exec   -i ./id_ed25519 -p 2222 demo@127.0.0.1 "uname -a"
                  hermod-ssh sftp   -i ./id_ed25519 -p 2222 demo@127.0.0.1 put ./file.bin /file.bin
                  hermod-ssh forward -i ./id_ed25519 -p 2222 -L 15432:db.internal:5432 demo@127.0.0.1
                  hermod-ssh play   ./session.cast --speed 2
                """);

        }

    }

}
