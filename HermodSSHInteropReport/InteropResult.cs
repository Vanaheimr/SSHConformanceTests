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

using System.Text.RegularExpressions;
using System.Xml.Linq;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.InteropReport
{

    /// <summary>How a single interop test came out.</summary>
    public enum InteropOutcome
    {
        /// <summary>The peer and we agreed.</summary>
        Passed,
        /// <summary>The test ran and failed — a genuine interop defect.</summary>
        Failed,
        /// <summary>Not exercised: the peer or a needed tool was unavailable on this machine.</summary>
        Skipped
    }


    /// <summary>One interop test result, attributed to the peer it exercised and the capability it covers.</summary>
    /// <param name="Peer">The other implementation involved (OpenSSH, SSH.NET, …).</param>
    /// <param name="Feature">The capability the test covers.</param>
    /// <param name="TestName">The test's own name, for the detail listing.</param>
    /// <param name="Outcome">How it came out.</param>
    /// <param name="Note">A short note — for a skip, why; for a failure, the message.</param>
    public sealed record InteropResult(String          Peer,
                                       String          Feature,
                                       String          TestName,
                                       InteropOutcome  Outcome,
                                       String?         Note = null);


    /// <summary>
    /// Reads the interop results out of the TRX files a test run produces.
    ///
    /// <para>
    /// TRX records the fixture class, the test name, the outcome and the test's captured output, but
    /// <b>not</b> NUnit categories — so the peer and the capability are derived from the names, with an
    /// explicit escape hatch: a test may print
    /// <c>INTEROP-MATRIX: peer=… feature=…</c> to override the derivation when the heuristic would get
    /// it wrong.
    /// </para>
    /// </summary>
    public static class TrxReader
    {

        #region Data

        private static readonly XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";

        private static readonly Regex overrideLine =
            new (@"INTEROP-MATRIX:\s*peer=(?<peer>[^\s;]+)\s*;?\s*feature=(?<feature>[^\r\n]+)",
                 RegexOptions.Compiled | RegexOptions.IgnoreCase);

        // Fixture name fragment → peer. First match wins, so order from most to least specific.
        private static readonly (String Fragment, String Peer)[] peersByFixture = [
            ("OpenSsh",   "OpenSSH"),
            ("SshNet",    "SSH.NET"),
            ("Dropbear",  "Dropbear"),
            ("TinySsh",   "TinySSH"),
            ("PuTTY",     "PuTTY"),
            ("Plink",     "PuTTY"),
            ("AsyncSsh",  "AsyncSSH"),
            ("Paramiko",  "Paramiko"),
            ("GoCrypto",  "Go x/crypto/ssh"),
            ("LibSsh",    "curl / libssh")
        ];

        // Keyword → capability, matched against the class and test name together. Order is significant:
        // the first hit wins, so the most specific keyword must come first. "SshKeygenReads_OurCertificate"
        // is about certificates, not key formats, which is why "certificate" precedes "keygen".
        private static readonly (String Keyword, String Feature)[] featuresByKeyword = [
            ("hostkeyrotation",  "Host-key rotation (hostkeys-00)"),
            ("sshfp",            "SSHFP DNS records"),
            ("agent",            "ssh-agent"),
            ("certificate",      "Certificates"),
            ("cert",             "Certificates"),
            ("transport",        "Transport & key exchange"),
            ("keyexchange",      "Transport & key exchange"),
            ("kex",              "Transport & key exchange"),
            ("extinfo",          "Algorithm negotiation"),
            ("sigalgs",          "Algorithm negotiation"),
            ("negotiat",         "Algorithm negotiation"),
            ("algorithm",        "Algorithm negotiation"),
            ("sftp",             "SFTP"),
            ("forward",          "Port forwarding"),
            ("tunnel",           "Port forwarding"),
            ("keyformat",        "Key formats (openssh-key-v1, PEM)"),
            ("keygen",           "Key formats (openssh-key-v1, PEM)"),
            ("privatekey",       "Key formats (openssh-key-v1, PEM)"),
            ("bcrypt",           "Key formats (openssh-key-v1, PEM)"),
            ("hostkey",          "Host-key verification"),
            ("auth",             "Authentication"),
            ("exec",             "Remote command execution"),
            ("command",          "Remote command execution"),
            ("session",          "Remote command execution")
        ];

        #endregion


        #region Read(Paths)

        /// <summary>Read every TRX file under the given files or directories.</summary>
        /// <param name="Paths">TRX files, or directories to search recursively.</param>
        public static IReadOnlyList<InteropResult> Read(IEnumerable<String> Paths)
        {

            var results = new List<InteropResult>();

            foreach (var file in Expand(Paths))
                results.AddRange(ReadFile(file));

            return results;

        }

        #endregion

        #region (private) ReadFile(Path)

        private static IEnumerable<InteropResult> ReadFile(String Path)
        {

            XDocument document;
            try     { document = XDocument.Load(Path); }
            catch   { yield break; }                       // an unreadable file must not sink the report

            // testId → class name, so a result can be attributed to its fixture.
            var classOf = document.Descendants(ns + "UnitTest")
                                  .ToDictionary(t => (String?) t.Attribute("id") ?? "",
                                                t => (String?) t.Element(ns + "TestMethod")?.Attribute("className") ?? "");

            foreach (var result in document.Descendants(ns + "UnitTestResult"))
            {

                var testId    = (String?) result.Attribute("testId")   ?? "";
                var testName  = (String?) result.Attribute("testName") ?? "(unnamed)";
                var outcome   = (String?) result.Attribute("outcome")  ?? "";
                var className = classOf.TryGetValue(testId, out var c) ? c : "";

                // Only interop fixtures belong in this report.
                if (!className.Contains("Interop", StringComparison.OrdinalIgnoreCase))
                    continue;

                var output  = String.Concat(result.Descendants(ns + "StdOut").Select(o => o.Value));
                var message = result.Descendants(ns + "Message").FirstOrDefault()?.Value;

                var (peer, feature) = Attribute(className, testName, output);

                yield return new InteropResult(
                                 peer,
                                 feature,
                                 Simplify(testName),
                                 outcome switch {
                                     "Passed"       => InteropOutcome.Passed,
                                     "Failed"       => InteropOutcome.Failed,
                                     _              => InteropOutcome.Skipped
                                 },
                                 Trim(message));

            }

        }

        #endregion

        #region (private) attribution

        private static (String Peer, String Feature) Attribute(String ClassName, String TestName, String Output)
        {

            // An explicit declaration in the test's own output always wins.
            var match = overrideLine.Match(Output);
            if (match.Success)
                return (match.Groups["peer"].Value.Trim(), match.Groups["feature"].Value.Trim());

            var peer = peersByFixture.FirstOrDefault(p => ClassName.Contains(p.Fragment, StringComparison.OrdinalIgnoreCase)).Peer
                           ?? "(unattributed)";

            var haystack = (ClassName + " " + TestName).ToLowerInvariant();
            var feature  = featuresByKeyword.FirstOrDefault(f => haystack.Contains(f.Keyword)).Feature
                               ?? "Other";

            return (peer, feature);

        }

        // "SshNet_RunsCommand_OnOurServer("fail",42)" → "SshNet_RunsCommand_OnOurServer("fail",42)" minus namespace noise.
        private static String Simplify(String TestName)
        {
            var name = TestName;
            var dot  = name.LastIndexOf('.');
            if (dot >= 0 && dot < name.Length - 1 && !name.Contains('('))
                name = name[(dot + 1)..];
            return name.Replace("&quot;", "\"");
        }

        private static String? Trim(String? Message)
        {
            if (String.IsNullOrWhiteSpace(Message))
                return null;
            var line = Message.Replace("\r", " ").Replace("\n", " ").Trim();
            return line.Length <= 160 ? line : line[..157] + "…";
        }

        private static IEnumerable<String> Expand(IEnumerable<String> Paths)
        {
            foreach (var path in Paths)
            {
                if (Directory.Exists(path))
                    foreach (var file in Directory.EnumerateFiles(path, "*.trx", SearchOption.AllDirectories))
                        yield return file;
                else if (File.Exists(path))
                    yield return path;
            }
        }

        #endregion

    }

}
