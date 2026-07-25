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

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.InteropReport
{

    /// <summary>
    /// Turns the TRX output of an interop test run into <c>docs/INTEROP-MATRIX.md</c>.
    ///
    /// <para>
    /// Usage: <c>hermod-ssh-interop-report &lt;trx-file-or-directory&gt;… [-o &lt;output.md&gt;]</c>
    /// </para>
    /// <para>
    /// Produce the input with, for example:
    /// <c>dotnet test --filter Category=Interop --logger "trx;LogFileName=interop.trx" --results-directory ./artifacts</c>
    /// </para>
    /// </summary>
    public static class Program
    {

        /// <summary>The command-line entry point.</summary>
        /// <param name="Arguments">TRX paths, optionally followed by <c>-o &lt;file&gt;</c>.</param>
        public static Int32 Main(String[] Arguments)
        {

            var inputs = new List<String>();
            var output = "docs/INTEROP-MATRIX.md";

            for (var i = 0; i < Arguments.Length; i++)
            {
                if (Arguments[i] is "-o" or "--output")
                {
                    if (++i >= Arguments.Length)
                    {
                        Console.Error.WriteLine("error: -o needs a file name.");
                        return 64;   // EX_USAGE
                    }
                    output = Arguments[i];
                }
                else
                    inputs.Add(Arguments[i]);
            }

            if (inputs.Count == 0)
            {
                Console.Error.WriteLine("""
                    Usage: hermod-ssh-interop-report <trx-file-or-directory>... [-o <output.md>]

                    Renders the interop test results into a peer × capability matrix.
                    Produce the input with:
                      dotnet test --filter Category=Interop --logger "trx;LogFileName=interop.trx" --results-directory ./artifacts
                    """);
                return 64;
            }

            var results = TrxReader.Read(inputs);

            if (results.Count == 0)
                Console.Error.WriteLine("warning: no interop results found — the matrix will be empty.");

            var directory = Path.GetDirectoryName(Path.GetFullPath(output));
            if (!String.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            File.WriteAllText(output, MatrixRenderer.Render(results, DateTimeOffset.UtcNow));

            var failed = results.Count(r => r.Outcome == InteropOutcome.Failed);

            Console.WriteLine($"Wrote {output} — {results.Count} result(s), "
                              + $"{results.Select(r => r.Peer).Distinct().Count()} peer(s), {failed} failure(s).");

            // A non-zero exit on a real interop failure lets CI gate on the matrix itself.
            return failed > 0 ? 1 : 0;

        }

    }

}
