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

using BenchmarkDotNet.Attributes;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Client;
using org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP;
using org.GraphDefined.Vanaheimr.Hermod.SSH.Server;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Benchmarks
{

    /// <summary>
    /// SFTP throughput over a real loopback TCP connection, through the full stack: encrypted transport,
    /// connection multiplexer, session channel, SFTP subsystem, in-memory file system.
    ///
    /// <para>
    /// PLAN §8 sets the target at <b>≥ 100 MB/s on loopback with AES-GCM</b>. The file system is
    /// in-memory on purpose — the number should describe the protocol stack, not the disk underneath it.
    /// What it does include is the part that actually governs SFTP speed: request pipelining, the
    /// channel window, and per-record crypto.
    /// </para>
    ///
    /// <para>
    /// <b>Cipher caveat:</b> this runs over whatever the two ends negotiate, and our first preference is
    /// <c>chacha20-poly1305@openssh.com</c> (<c>KexInitMessage</c>) — <i>not</i> the AES-GCM the target
    /// names. The façade deliberately exposes no cipher knob, so pinning one here would mean widening
    /// the public API for a benchmark. The per-cipher comparison lives in <see cref="CipherBenchmarks"/>
    /// instead, which measures at the record level where the cipher can be selected.
    /// </para>
    /// </summary>
    [MemoryDiagnoser]
    public class SftpBenchmarks
    {

        private SshServer     server      = null!;
        private SshClient     client      = null!;
        private SftpClient    sftp        = null!;
        private Byte[]        payload     = [];

        /// <summary>The transfer size, in mebibytes.</summary>
        [Params(8, 32)]
        public Int32 Megabytes { get; set; }

        /// <summary>Stand up the server and one authenticated client; only the transfer is measured.</summary>
        [GlobalSetup]
        public void Setup()
        {

            payload = new Byte[Megabytes * 1024 * 1024];
            Random.Shared.NextBytes(payload);

            var hostKey = SshHostKey.GenerateEd25519();
            var userKey = SshHostKey.GenerateEd25519();

            var fileSystem = new InMemorySftpFileSystem();
            fileSystem.AddFile("/download.bin", payload);

            server = new SshServer(new SshServerOptions {
                HostKeys        = [ hostKey ],
                Authenticator   = SshUserAuthenticator.ForAuthorizedKeys(userKey.PublicKeyBlob),
                SftpFileSystem  = fileSystem
            });

            server.StartAsync(new IPSocket(IPv4Address.Localhost, IPPort.Auto)).AsTask().GetAwaiter().GetResult();
            var port = (UInt16) server.LocalEndPoint.Port.ToInt32();

            client = SshClient.ConnectAsync("127.0.0.1", port, new SshClientOptions {
                         Username      = "bench",
                         VerifyHostKey = SshHostKeyVerification.AcceptAnyUnsafe,
                         Credentials   = [ userKey ]
                     }).AsTask().GetAwaiter().GetResult();

            sftp = client.OpenSftpClientAsync().AsTask().GetAwaiter().GetResult();

        }

        /// <summary>Tear the connection down.</summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            try { sftp?.DisposeAsync().AsTask().GetAwaiter().GetResult();   } catch { }
            try { client?.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { }
            try { server?.DisposeAsync().AsTask().GetAwaiter().GetResult(); } catch { }
        }

        /// <summary>Upload the payload (client → server).</summary>
        [Benchmark]
        public async Task Upload()
            => await sftp.UploadAsync("/upload.bin", payload);

        /// <summary>Download the payload (server → client).</summary>
        [Benchmark]
        public async Task<Int32> Download()
            => (await sftp.DownloadAsync("/download.bin")).Length;

    }

}
