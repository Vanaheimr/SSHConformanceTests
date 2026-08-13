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
    /// Makes sure this test run leaves no SSH daemon listening inside Linux.
    ///
    /// <para>
    /// Every peer server is already reaped when its test disposes it, and that is where the work belongs:
    /// a port held past the test that owns it makes the next run fail. This is the backstop for the cases
    /// disposal cannot cover — a test killed mid-run, a fixture that threw before its <c>finally</c>, a
    /// peer whose disposal itself failed. A leaked <c>sshd</c> is not merely untidy: it keeps accepting
    /// connections on the developer's machine long after the run that started it is forgotten.
    /// </para>
    ///
    /// <para>
    /// Being outside every fixture, it runs once after the whole assembly, whatever subset of tests was
    /// selected — and it costs nothing at all when the run never started a peer.
    /// </para>
    /// </summary>
    [SetUpFixture]
    public class InteropPeerCleanup
    {

        [OneTimeTearDown]
        public async Task ReapLeftoverPeersAsync()
        {

            var strays = await WslInterop.SweepAsync(CancellationToken.None);

            // Not a failure: these belong to a *different* run, so this one has no business killing them
            // and no way to know whether that run is still going. Saying so is the useful part — nothing
            // else will ever collect them.
            if (strays > 0)
                TestContext.Progress.WriteLine(
                    $"[interop] {strays} peer(s) from an earlier test run are still alive inside Linux. " +
                     "If no other test run is in progress, end them with: " +
                     "wsl.exe -e bash -c 'pkill -f \"[.]hermod-interop/\"'");

        }

    }

}
