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
    /// Handshake latency: version exchange → KEXINIT → key exchange → host-key signature → NEWKEYS,
    /// both roles, over an in-memory pipe pair.
    ///
    /// <para>
    /// Running client and server in one process over a memory pipe removes the network from the
    /// measurement, so what is left is the cost that is actually ours: the asymmetric maths and the KDF.
    /// The point of parameterising by key exchange is the post-quantum comparison — a hybrid carries a
    /// far larger public key than X25519, and this shows what that costs per connection.
    /// </para>
    /// </summary>
    [MemoryDiagnoser]
    public class HandshakeBenchmarks
    {

        private ISshHostKey hostKey = null!;

        /// <summary>
        /// The key exchange to measure.
        /// </summary>
        [Params(SshAlgorithmNames.Kex.Curve25519Sha256,
                SshAlgorithmNames.Kex.EcdhNistP256,
                SshAlgorithmNames.Kex.MlKem768X25519Sha256,
                SshAlgorithmNames.Kex.SntruP761X25519Sha512)]
        public String KeyExchange { get; set; } = "";

        /// <summary>
        /// Generate the host key once — key generation is not what is being measured.
        /// </summary>
        [GlobalSetup]
        public void Setup()
            => hostKey = SshHostKey.GenerateEd25519();

        /// <summary>
        /// One complete handshake, client and server.
        /// </summary>
        [Benchmark]
        public async Task Handshake()
        {

            var (clientPipe, serverPipe) = DuplexPipe.CreateConnectedPair();

            var server = Task.Run(async () => {
                using var t = await SshTransport.ServerHandshakeAsync(serverPipe, hostKey, KeyExchanges: [ KeyExchange ]);
            });

            using (var client = await SshTransport.ClientHandshakeAsync(
                                          clientPipe,
                                          VerifyHostKey: SshHostKeyVerification.AcceptAnyUnsafe,
                                          KeyExchanges:  [ KeyExchange ]))
            {
                await server;
            }

        }

    }

}
