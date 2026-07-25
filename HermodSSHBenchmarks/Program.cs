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

using BenchmarkDotNet.Running;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Benchmarks
{

    /// <summary>
    /// The benchmark runner (BenchmarkDotNet, deliberately a separate project from the NUnit suite —
    /// PLAN §8).
    ///
    /// <para>
    /// Run everything:
    /// <c>dotnet run --project HermodSSHBenchmarks -c Release -- --filter *</c>
    /// </para>
    /// <para>
    /// One family, e.g. the SFTP throughput target:
    /// <c>dotnet run --project HermodSSHBenchmarks -c Release -- --filter *Sftp*</c>
    /// </para>
    /// <para>
    /// A quick look rather than a full statistical run: add <c>--job short</c>.
    /// <b>Release is required</b> — BenchmarkDotNet refuses a debug build, and rightly so.
    /// </para>
    /// </summary>
    public static class Program
    {

        /// <summary>The command-line entry point; arguments are passed straight to BenchmarkDotNet.</summary>
        /// <param name="Arguments">BenchmarkDotNet switches (<c>--filter</c>, <c>--job</c>, …).</param>
        public static void Main(String[] Arguments)
            => BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(Arguments);

    }

}
