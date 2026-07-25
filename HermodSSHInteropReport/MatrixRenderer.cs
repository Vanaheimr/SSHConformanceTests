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

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.InteropReport
{

    /// <summary>
    /// Renders interop results as the peer × capability matrix in <c>docs/INTEROP-MATRIX.md</c> — the
    /// project's living conformance statement.
    ///
    /// <para>
    /// The distinction that matters in a conformance table is between "this peer disagreed with us"
    /// (a defect) and "this peer was not available on the machine that produced the run" (no evidence
    /// either way). A report that renders both as a blank cell would quietly overstate coverage, so
    /// they get different marks and the summary counts them separately.
    /// </para>
    /// </summary>
    public static class MatrixRenderer
    {

        #region Render(Results, GeneratedAt)

        /// <summary>Render the full report.</summary>
        /// <param name="Results">The results gathered from the test run.</param>
        /// <param name="GeneratedAt">The timestamp to record.</param>
        public static String Render(IReadOnlyList<InteropResult> Results, DateTimeOffset GeneratedAt)
        {

            var report = new StringBuilder();

            report.AppendLine("# HermodSSH — interoperability matrix");
            report.AppendLine();
            report.AppendLine("Generated from the interop test run — do not edit by hand.");
            report.AppendLine($"Run at {GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC.");
            report.AppendLine();

            if (Results.Count == 0)
            {
                report.AppendLine("> No interop results were found in the supplied test output.");
                return report.ToString();
            }

            var peers    = Results.Select(r => r.Peer).Distinct().OrderBy(p => p, StringComparer.Ordinal).ToArray();
            var features = Results.Select(r => r.Feature).Distinct().OrderBy(f => f, StringComparer.Ordinal).ToArray();

            AppendSummary (report, Results, peers);
            AppendMatrix  (report, Results, peers, features);
            AppendDetail  (report, Results, peers);
            AppendLegend  (report);

            return report.ToString();

        }

        #endregion

        #region (private) sections

        private static void AppendSummary(StringBuilder Report, IReadOnlyList<InteropResult> Results, String[] Peers)
        {

            var passed  = Results.Count(r => r.Outcome == InteropOutcome.Passed);
            var failed  = Results.Count(r => r.Outcome == InteropOutcome.Failed);
            var skipped = Results.Count(r => r.Outcome == InteropOutcome.Skipped);

            Report.AppendLine("## Summary");
            Report.AppendLine();
            Report.AppendLine($"**{passed} passed · {failed} failed · {skipped} not exercised** across {Peers.Length} peer(s).");
            Report.AppendLine();

            if (failed > 0)
                Report.AppendLine($"> ⚠ {failed} interop test(s) failed — see the detail below.");
            else if (skipped > 0)
                Report.AppendLine("> All exercised tests agreed. Some peers were unavailable on the machine that produced this run, "
                                  + "so their rows record no evidence rather than success.");
            else
                Report.AppendLine("> Every interop test passed.");

            Report.AppendLine();

        }

        private static void AppendMatrix(StringBuilder                 Report,
                                         IReadOnlyList<InteropResult>  Results,
                                         String[]                      Peers,
                                         String[]                      Features)
        {

            Report.AppendLine("## Capability × peer");
            Report.AppendLine();
            Report.AppendLine("| Capability | " + String.Join(" | ", Peers) + " |");
            Report.AppendLine("|---|" + String.Join("|", Peers.Select(_ => "---")) + "|");

            foreach (var feature in Features)
            {

                var cells = Peers.Select(peer => {

                    var cell = Results.Where(r => r.Peer == peer && r.Feature == feature).ToArray();

                    if (cell.Length == 0)
                        return "–";

                    var failed  = cell.Count(r => r.Outcome == InteropOutcome.Failed);
                    var passed  = cell.Count(r => r.Outcome == InteropOutcome.Passed);

                    if (failed > 0)  return $"❌ {failed}/{cell.Length}";
                    if (passed == 0) return "⚪";
                    return passed == cell.Length ? $"✅ {passed}" : $"✅ {passed} ⚪ {cell.Length - passed}";

                });

                Report.AppendLine($"| {feature} | " + String.Join(" | ", cells) + " |");

            }

            Report.AppendLine();

        }

        private static void AppendDetail(StringBuilder Report, IReadOnlyList<InteropResult> Results, String[] Peers)
        {

            Report.AppendLine("## Detail");
            Report.AppendLine();

            foreach (var peer in Peers)
            {

                Report.AppendLine($"### {peer}");
                Report.AppendLine();

                foreach (var result in Results.Where(r => r.Peer == peer)
                                              .OrderBy(r => r.Feature, StringComparer.Ordinal)
                                              .ThenBy (r => r.TestName, StringComparer.Ordinal))
                {

                    var mark = result.Outcome switch {
                                   InteropOutcome.Passed  => "✅",
                                   InteropOutcome.Failed  => "❌",
                                   _                      => "⚪"
                               };

                    Report.Append($"- {mark} `{result.TestName}` — {result.Feature}");

                    if (result.Note is not null)
                        Report.Append($" — {result.Note}");

                    Report.AppendLine();

                }

                Report.AppendLine();

            }

        }

        private static void AppendLegend(StringBuilder Report)
        {
            Report.AppendLine("## Legend");
            Report.AppendLine();
            Report.AppendLine("| Mark | Meaning |");
            Report.AppendLine("|---|---|");
            Report.AppendLine("| ✅ | The peer and HermodSSH agreed. |");
            Report.AppendLine("| ❌ | The test ran and disagreed — a genuine interop defect. |");
            Report.AppendLine("| ⚪ | Not exercised: the peer or a tool it needs was unavailable on this machine. **No evidence either way.** |");
            Report.AppendLine("| – | No test covers this capability for this peer yet. |");
        }

        #endregion

    }

}
