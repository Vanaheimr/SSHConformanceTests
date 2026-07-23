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
        public static Int32 Main(String[] Arguments)
        {

            var command = Arguments.Length > 0 ? Arguments[0].ToLowerInvariant() : "help";

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

                // Planned verbs — see PLAN.md section 5 (Demo CLI). Implemented per milestone.
                case "keygen":
                case "serve":
                case "connect":
                case "exec":
                case "sftp":
                case "forward":
                case "ca":
                case "scan":
                case "play":
                    Console.WriteLine($"'{command}' is not implemented yet — this is the M0 scaffold.");
                    Console.WriteLine("See PLAN.md for the milestone that delivers it.");
                    return 64;  // EX_USAGE

                default:
                    Console.Error.WriteLine($"Unknown command '{command}'.");
                    PrintHelp();
                    return 64;  // EX_USAGE

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

                Commands (planned; delivered per milestone):
                  keygen     Generate host/user keys (Ed25519/ECDSA/RSA) and export any format
                  serve      Run a demo SSH/SFTP server (auth, access profiles, recording, banner)
                  connect    Log in and open an interactive session (supports -J jump hosts)
                  exec       Log in, run a command, capture output, log out
                  sftp       Transfer files (get / put / ls) with progress
                  forward    Local / remote / jump-host port forwarding
                  ca         Issue and inspect OpenSSH certificates (mini-CA)
                  scan       Fetch a host key or emit its SSHFP DNS record
                  play       Replay a recorded asciicast session

                  help       Show this help
                  version    Show the version

                This is the M0 scaffold: the wire-format core and its tests are in place;
                the commands above light up as their library features are implemented.
                """);

        }

    }

}
