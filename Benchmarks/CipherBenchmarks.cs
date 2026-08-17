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

using org.GraphDefined.Vanaheimr.Hermod.SSH;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.Benchmarks
{

    /// <summary>
    /// Per-cipher record throughput: a packet all the way through the transport — framing, padding,
    /// encryption, MAC/AEAD tag — and back out the other side.
    ///
    /// <para>
    /// Measured at the transport rather than on the raw cipher, because that is the cost a real session
    /// pays: an SSH record is not just a block of ciphertext. The handshake is done once in setup so it
    /// does not show up in the per-packet number.
    /// </para>
    /// </summary>
    [MemoryDiagnoser]
    public class CipherBenchmarks
    {

        private SshTransport  client   = null!;
        private SshTransport  server   = null!;
        private Byte[]        payload  = [];

        /// <summary>
        /// The cipher to measure.
        /// </summary>
        [Params(SshAlgorithmNames.Cipher.ChaCha20Poly1305,
                SshAlgorithmNames.Cipher.Aes256Gcm,
                SshAlgorithmNames.Cipher.Aes256Ctr)]
        public String Cipher { get; set; } = "";

        /// <summary>
        /// The application payload per record, in bytes.
        /// </summary>
        [Params(1024, 32768)]
        public Int32 PayloadSize { get; set; }

        /// <summary>
        /// Establish one encrypted transport pair; the handshake is not part of the measurement.
        /// </summary>
        [GlobalSetup]
        public void Setup()
        {

            payload = new Byte[PayloadSize];
            Random.Shared.NextBytes(payload);

            var hostKey = SshHostKey.GenerateEd25519();
            var (clientPipe, serverPipe) = DuplexPipe.CreateConnectedPair();

            var serverTask = Task.Run(() => SshTransport.ServerHandshakeAsync(serverPipe, hostKey, Ciphers: [ Cipher ]).AsTask());

            client = SshTransport.ClientHandshakeAsync(clientPipe,
                                                       VerifyHostKey: SshHostKeyVerification.AcceptAnyUnsafe,
                                                       Ciphers:       [ Cipher ]).AsTask().GetAwaiter().GetResult();
            server = serverTask.GetAwaiter().GetResult();

        }

        /// <summary>
        /// Release the transports.
        /// </summary>
        [GlobalCleanup]
        public void Cleanup()
        {
            client?.Dispose();
            server?.Dispose();
        }

        /// <summary>
        /// Send one record and receive it at the far end.
        /// </summary>
        [Benchmark]
        public async Task<Int32> RoundTripRecord()
        {
            await client.SendPacketAsync(payload);
            var received = await server.ReceivePacketAsync();
            return received.Length;
        }

    }

}
