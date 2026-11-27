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

using System.IO;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Tests
{

    /// <summary>
    /// A Java toolchain and the jars a Java peer - Apache MINA SSHD, JSch - is built against, on one
    /// <see cref="PeerPlatform"/>.
    ///
    /// <para>
    /// On Linux the jars are the distribution's, in <c>/usr/share/java</c>. On Windows
    /// <c>interop/setup-windows.ps1</c> fetches the same releases from Maven Central, checks each against
    /// a pinned SHA-256, and stores it under the name Debian gives it (<c>sshd-core.jar</c>,
    /// <c>bcprov.jar</c>, ...) in <c>interop/.java-interop-win</c>, so a peer names its jars once and the
    /// class path follows from the platform.
    /// </para>
    /// </summary>
    /// <param name="Platform">Where the peer runs.</param>
    /// <param name="Java">The <c>java</c> launcher, as the platform starts it.</param>
    /// <param name="Javac">The <c>javac</c> compiler, as the platform starts it.</param>
    /// <param name="JarDirectory">Where the jars are, as the platform spells it.</param>
    public sealed record JavaToolchain(PeerPlatform  Platform,
                                       String        Java,
                                       String        Javac,
                                       String        JarDirectory)
    {

        /// <summary>
        /// The class-path separator of the platform the peer runs on.
        /// </summary>
        public String PathSeparator
            => Platform == PeerPlatform.Windows ? ";" : ":";

        /// <summary>
        /// One jar by its distribution name, e.g. <c>sshd-core</c>.
        /// </summary>
        public String Jar(String Name)
            => Platform == PeerPlatform.Windows
                   ? Path.Combine(JarDirectory, Name + ".jar")
                   : $"{JarDirectory}/{Name}.jar";

        /// <summary>
        /// A class path of the given directories and jars, as the platform's <c>java</c> reads it.
        /// </summary>
        /// <param name="Directories">Directories of compiled classes, as the platform spells them.</param>
        /// <param name="Jars">Jars by distribution name.</param>
        public String ClassPath(IEnumerable<String> Directories, IEnumerable<String> Jars)
            => String.Join(PathSeparator, Directories.Concat(Jars.Select(Jar)));

        /// <summary>
        /// Whether every one of the given jars is on disk - only answerable for a native toolchain, whose
        /// jars this process can see.
        /// </summary>
        public Boolean HasJars(IEnumerable<String> Jars)
            => Platform != PeerPlatform.Windows || Jars.All(jar => File.Exists(Jar(jar)));

    }


    /// <summary>
    /// The Java toolchains a Java peer can be built with on this machine.
    /// </summary>
    public static class JavaPeers
    {

        /// <summary>
        /// The distribution's Java and jars in Linux: inside WSL on Windows, directly on Linux.
        /// </summary>
        public static JavaToolchain Linux { get; } = new (PeerPlatform.Linux, "java", "javac", "/usr/share/java");

        /// <summary>
        /// A Java on this Windows machine's PATH with the jars <c>setup-windows.ps1</c> fetched, or
        /// <c>null</c> when there is none.
        /// </summary>
        public static JavaToolchain? Windows { get; } = LocateWindows();

        private static JavaToolchain? LocateWindows()
        {

            if (!OperatingSystem.IsWindows() || WslInterop.InteropDirectory is null)
                return null;

            var java  = PeerPlatform.FindOnPath("java.exe");
            var javac = PeerPlatform.FindOnPath("javac.exe");
            var jars  = Path.Combine(WslInterop.InteropDirectory, ".java-interop-win");

            return java is not null && javac is not null && Directory.Exists(jars)
                       ? new JavaToolchain(PeerPlatform.Windows, java, javac, jars)
                       : null;

        }

        /// <summary>
        /// Why there is no native Java toolchain for the given jars on this Windows machine - for a skip
        /// message when WSL is not there to fall back on.
        /// </summary>
        public static String WhyNotOnWindows(IEnumerable<String> Jars)

            => Windows is null
                   ? "No java.exe and javac.exe on the PATH with the jars of interop\\.java-interop-win - run interop\\setup-windows.ps1"
                   : $"interop\\.java-interop-win lacks {String.Join(", ", Jars.Where(jar => !File.Exists(Windows.Jar(jar))))}.jar - run interop\\setup-windows.ps1";

    }

}
