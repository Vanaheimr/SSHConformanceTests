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

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>The result of running a remote command: the exit status and the captured output.</summary>
    public sealed record SshCommandResult(Int32   ExitCode,
                                          Byte[]  StandardOutputBytes,
                                          Byte[]  StandardErrorBytes)
    {
        /// <summary>The captured standard output decoded as UTF-8 text.</summary>
        public String StandardOutput => Encoding.UTF8.GetString(StandardOutputBytes);

        /// <summary>The captured standard error decoded as UTF-8 text.</summary>
        public String StandardError  => Encoding.UTF8.GetString(StandardErrorBytes);

        /// <summary>Whether the command reported success (exit code 0).</summary>
        public Boolean Success => ExitCode == 0;
    }


    /// <summary>
    /// The context handed to a server-side exec/shell handler: the requested command (empty for a shell),
    /// the authenticated user, and write access to the channel's standard output and error.
    /// </summary>
    public sealed class SshExecContext
    {

        private readonly Func<ReadOnlyMemory<Byte>, Boolean, CancellationToken, ValueTask> write;

        /// <summary>The command line requested via <c>exec</c> (empty string for a <c>shell</c> request).</summary>
        public String  Command   { get; }

        /// <summary>The authenticated user name.</summary>
        public String  Username  { get; }

        internal SshExecContext(String command, String username, Func<ReadOnlyMemory<Byte>, Boolean, CancellationToken, ValueTask> write)
        {
            this.Command   = command;
            this.Username  = username;
            this.write     = write;
        }

        /// <summary>Write bytes to standard output.</summary>
        public ValueTask WriteAsync(ReadOnlyMemory<Byte> Data, CancellationToken CancellationToken = default)
            => write(Data, false, CancellationToken);

        /// <summary>Write bytes to standard error.</summary>
        public ValueTask WriteErrorAsync(ReadOnlyMemory<Byte> Data, CancellationToken CancellationToken = default)
            => write(Data, true, CancellationToken);

        /// <summary>Write a UTF-8 string to standard output.</summary>
        public ValueTask WriteAsync(String Text, CancellationToken CancellationToken = default)
            => WriteAsync(Encoding.UTF8.GetBytes(Text), CancellationToken);

        /// <summary>Write a UTF-8 string plus a newline to standard output.</summary>
        public ValueTask WriteLineAsync(String Text, CancellationToken CancellationToken = default)
            => WriteAsync(Encoding.UTF8.GetBytes(Text + "\n"), CancellationToken);

    }


    /// <summary>
    /// A server-side handler for an <c>exec</c> or <c>shell</c> session: it writes output through the
    /// context and returns the exit status.
    /// </summary>
    public delegate ValueTask<Int32> SshExecHandler(SshExecContext Context, CancellationToken CancellationToken);

}
