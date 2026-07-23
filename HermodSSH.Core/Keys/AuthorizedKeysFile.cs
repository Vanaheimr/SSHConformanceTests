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

    /// <summary>
    /// Parses an <c>authorized_keys</c> file into <see cref="AuthorizedKey"/> entries, understanding the
    /// leading option list (<c>cert-authority</c>, <c>principals="…"</c>, <c>command="…"</c>, <c>from="…"</c>,
    /// <c>restrict</c>/<c>no-*</c>) and the certificate-style validity options <c>not-before="…"</c>,
    /// <c>not-after="…"</c> and the OpenSSH-compatible <c>expiry-time="…"</c> alias.
    /// </summary>
    public static class AuthorizedKeysFile
    {

        #region Parse(Text)

        /// <summary>Parse the full text of an <c>authorized_keys</c> file.</summary>
        public static IReadOnlyList<AuthorizedKey> Parse(String Text)
        {

            var entries = new List<AuthorizedKey>();

            foreach (var rawLine in Text.Replace("\r\n", "\n").Split('\n'))
            {

                var line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith('#'))
                    continue;

                if (TryParseLine(line, out var entry))
                    entries.Add(entry!);

            }

            return entries;

        }

        #endregion

        #region TryParseLine(Line, out Entry)

        /// <summary>Parse a single <c>authorized_keys</c> line (options optional).</summary>
        public static Boolean TryParseLine(String Line, out AuthorizedKey? Entry)
        {

            Entry = null;

            var (first, rest) = SplitFirstToken(Line);

            // No options: the line starts directly with a key type.
            if (IsKeyType(first))
                return SshPublicKey.TryParse(Line, out var bareKey) && Build(bareKey!, [], out Entry);

            // Otherwise the first token is the option list and the rest is the key.
            if (!SshPublicKey.TryParse(rest, out var key))
                return false;

            return Build(key!, SplitOptions(first), out Entry);

        }

        #endregion


        #region (private) Build(Key, Options, out Entry)

        private static Boolean Build(SshPublicKey Key, IReadOnlyList<String> Options, out AuthorizedKey? Entry)
        {

            var isCa         = false;
            var principals   = new List<String>();
            DateTimeOffset?  notBefore  = null;
            DateTimeOffset?  notAfter   = null;
            String?          command    = null;

            foreach (var option in Options)
            {

                if (String.Equals(option, "cert-authority", StringComparison.OrdinalIgnoreCase))
                    isCa = true;

                else if (TryOptionValue(option, "principals", out var p))
                    principals.AddRange(p.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

                else if (TryOptionValue(option, "command", out var c))
                    command = c;

                else if (TryOptionValue(option, "not-before", out var nb))
                    notBefore = AuthorizedKey.ParseTimestamp(nb);

                else if (TryOptionValue(option, "not-after", out var na) || TryOptionValue(option, "expiry-time", out na))
                    notAfter = AuthorizedKey.ParseTimestamp(na);

            }

            Entry = new AuthorizedKey(Key)
            {
                IsCertAuthority  = isCa,
                Principals       = principals,
                NotBefore        = notBefore,
                NotAfter         = notAfter,
                ForcedCommand    = command,
                Options          = Options
            };

            return true;

        }

        #endregion

        #region (private) option / token parsing

        // Split "key=value" (value optionally double-quoted); returns false if the option isn't "name=…".
        private static Boolean TryOptionValue(String Option, String Name, out String Value)
        {

            Value = "";

            if (!Option.StartsWith(Name + "=", StringComparison.OrdinalIgnoreCase))
                return false;

            var raw = Option[(Name.Length + 1)..];
            Value   = raw.Length >= 2 && raw[0] == '"' && raw[^1] == '"' ? raw[1..^1] : raw;
            return true;

        }

        // A known SSH key-type token (so the line has no options).
        private static Boolean IsKeyType(String Token)
            => Token.StartsWith("ssh-",       StringComparison.Ordinal) ||
               Token.StartsWith("ecdsa-",     StringComparison.Ordinal) ||
               Token.StartsWith("sk-",        StringComparison.Ordinal) ||
               Token.StartsWith("rsa-sha2-",  StringComparison.Ordinal);

        // Split off the first whitespace-delimited token, honouring double quotes; returns (first, rest).
        private static (String First, String Remainder) SplitFirstToken(String Line)
        {

            var inQuotes = false;
            for (var i = 0; i < Line.Length; i++)
            {
                var c = Line[i];
                if (c == '"')
                    inQuotes = !inQuotes;
                else if (!inQuotes && (c == ' ' || c == '\t'))
                    return (Line[..i], Line[(i + 1)..].TrimStart());
            }

            return (Line, "");

        }

        // Split a comma-separated option list, honouring double-quoted values (which may contain commas).
        private static List<String> SplitOptions(String OptionList)
        {

            var options   = new List<String>();
            var current   = new StringBuilder();
            var inQuotes  = false;

            foreach (var c in OptionList)
            {
                if (c == '"')
                {
                    inQuotes = !inQuotes;
                    current.Append(c);
                }
                else if (c == ',' && !inQuotes)
                {
                    if (current.Length > 0) { options.Add(current.ToString()); current.Clear(); }
                }
                else
                    current.Append(c);
            }

            if (current.Length > 0)
                options.Add(current.ToString());

            return options;

        }

        #endregion

    }

}
