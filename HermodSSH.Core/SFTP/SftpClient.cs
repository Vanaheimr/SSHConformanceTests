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

using System.Buffers;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP
{

    /// <summary>
    /// A minimal SFTP (version 3) client over a channel duplex: upload, download, directory listing and
    /// the common file-management operations. One request is outstanding at a time.
    /// </summary>
    public sealed class SftpClient
    {

        #region Data

        private const Int32 TransferChunk = 30 * 1024;   // stay under the 32 KiB channel packet

        private readonly SshChannelDuplex  channel;
        private UInt32                     requestId;

        #endregion

        #region Properties

        /// <summary>The extensions the server advertised in its SSH_FXP_VERSION (name → data).</summary>
        public IReadOnlyDictionary<String, String> ServerExtensions { get; }

        /// <summary>Whether the server advertised the named extension.</summary>
        public Boolean Supports(String Extension) => ServerExtensions.ContainsKey(Extension);

        #endregion

        #region Constructor(s)

        private SftpClient(SshChannelDuplex Channel, IReadOnlyDictionary<String, String> ServerExtensions)
        {
            this.channel           = Channel;
            this.ServerExtensions  = ServerExtensions;
        }

        #endregion


        #region (static) OpenAsync(Transport, CancellationToken)

        /// <summary>Open the <c>sftp</c> subsystem and negotiate the protocol version.</summary>
        public static async ValueTask<SftpClient> OpenAsync(SshTransport Transport, CancellationToken CancellationToken = default)
        {

            var channel = await SshConnection.OpenSubsystemAsync(Transport, "sftp", CancellationToken).ConfigureAwait(false);

            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SftpPacketType.Init);
            w.WriteUInt32(SftpVersion.Three);
            await SftpServer.SendAsync(channel, abw.WrittenSpan.ToArray(), CancellationToken).ConfigureAwait(false);

            var version = await SftpServer.ReadPacketAsync(channel, CancellationToken).ConfigureAwait(false)
                          ?? throw new SshWireException("The SFTP server closed the channel before SSH_FXP_VERSION.");
            if ((SftpPacketType) version[0] != SftpPacketType.Version)
                throw new SshWireException("Expected SSH_FXP_VERSION.");

            // Parse the advertised extension name/data pairs that follow the version word.
            var extensions = new Dictionary<String, String>(StringComparer.Ordinal);
            var vReader    = new SshPacketReader(version);
            vReader.ReadByte(); vReader.ReadUInt32();   // type + version
            while (vReader.Position < version.Length)
            {
                var name = vReader.ReadString();
                var data = vReader.ReadString();
                extensions[name] = data;
            }

            return new SftpClient(channel, extensions);

        }

        #endregion


        #region UploadAsync / DownloadAsync

        /// <summary>Upload bytes to a remote path (creating/truncating it).</summary>
        public async ValueTask UploadAsync(String RemotePath, Byte[] Content, CancellationToken CancellationToken = default)
        {

            var handle = await OpenFileAsync(RemotePath, SftpOpenFlags.Create | SftpOpenFlags.Write | SftpOpenFlags.Truncate, CancellationToken).ConfigureAwait(false);

            try
            {
                for (var offset = 0; offset < Content.Length; offset += TransferChunk)
                {
                    var chunk = Content.AsMemory(offset, Math.Min(TransferChunk, Content.Length - offset));
                    await WriteAsync(handle, offset, chunk, CancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                await CloseAsync(handle, CancellationToken).ConfigureAwait(false);
            }

        }

        /// <summary>Download a remote file's contents.</summary>
        public async ValueTask<Byte[]> DownloadAsync(String RemotePath, CancellationToken CancellationToken = default)
        {

            var handle  = await OpenFileAsync(RemotePath, SftpOpenFlags.Read, CancellationToken).ConfigureAwait(false);
            var output  = new ArrayBufferWriter<Byte>();

            try
            {
                var offset = 0L;
                while (true)
                {
                    var data = await ReadAsync(handle, offset, TransferChunk, CancellationToken).ConfigureAwait(false);
                    if (data.Length == 0)
                        break;
                    output.Write(data);
                    offset += data.Length;
                }
            }
            finally
            {
                await CloseAsync(handle, CancellationToken).ConfigureAwait(false);
            }

            return output.WrittenSpan.ToArray();

        }

        #endregion

        #region ListDirectoryAsync(RemotePath)

        /// <summary>List a remote directory (excluding <c>.</c> and <c>..</c>).</summary>
        public async ValueTask<IReadOnlyList<SftpDirectoryEntry>> ListDirectoryAsync(String RemotePath, CancellationToken CancellationToken = default)
        {

            var handle   = await OpenDirectoryAsync(RemotePath, CancellationToken).ConfigureAwait(false);
            var entries  = new List<SftpDirectoryEntry>();

            try
            {
                while (true)
                {
                    var batch = await ReadDirectoryAsync(handle, CancellationToken).ConfigureAwait(false);
                    if (batch.Count == 0)
                        break;
                    entries.AddRange(batch.Where(e => e.Name is not ("." or "..")));
                }
            }
            finally
            {
                await CloseAsync(handle, CancellationToken).ConfigureAwait(false);
            }

            return entries;

        }

        #endregion

        #region file-management operations

        /// <summary>Get the attributes of a remote path.</summary>
        public async ValueTask<SftpFileAttributes> StatAsync(String RemotePath, CancellationToken CancellationToken = default)
        {
            var response = await RoundtripAsync(SftpPacketType.Stat, (ref SshPacketWriter w) => w.WriteString(RemotePath), CancellationToken).ConfigureAwait(false);
            var reader   = new SshPacketReader(response); reader.ReadByte(); reader.ReadUInt32();
            EnsureNotStatusError(response);
            return SftpFileAttributes.Decode(ref reader);
        }

        /// <summary>Create a remote directory.</summary>
        public ValueTask MakeDirectoryAsync(String RemotePath, CancellationToken CancellationToken = default)
            => ExpectOkAsync(SftpPacketType.MkDir, (ref SshPacketWriter w) => { w.WriteString(RemotePath); SftpFileAttributes.Directory().Encode(ref w); }, CancellationToken);

        /// <summary>Remove a remote file.</summary>
        public ValueTask RemoveAsync(String RemotePath, CancellationToken CancellationToken = default)
            => ExpectOkAsync(SftpPacketType.Remove, (ref SshPacketWriter w) => w.WriteString(RemotePath), CancellationToken);

        /// <summary>Remove a remote directory.</summary>
        public ValueTask RemoveDirectoryAsync(String RemotePath, CancellationToken CancellationToken = default)
            => ExpectOkAsync(SftpPacketType.RmDir, (ref SshPacketWriter w) => w.WriteString(RemotePath), CancellationToken);

        /// <summary>Rename a remote file or directory.</summary>
        public ValueTask RenameAsync(String OldPath, String NewPath, CancellationToken CancellationToken = default)
            => ExpectOkAsync(SftpPacketType.Rename, (ref SshPacketWriter w) => { w.WriteString(OldPath); w.WriteString(NewPath); }, CancellationToken);

        /// <summary>Atomically rename with replace semantics via <c>posix-rename@openssh.com</c>.</summary>
        public ValueTask PosixRenameAsync(String OldPath, String NewPath, CancellationToken CancellationToken = default)
            => ExpectOkAsync(SftpPacketType.Extended, (ref SshPacketWriter w) => { w.WriteString("posix-rename@openssh.com"); w.WriteString(OldPath); w.WriteString(NewPath); }, CancellationToken);

        /// <summary>Query the server's protocol limits via <c>limits@openssh.com</c>.</summary>
        public async ValueTask<SftpProtocolLimits> LimitsAsync(CancellationToken CancellationToken = default)
        {
            var response = await RoundtripAsync(SftpPacketType.Extended, (ref SshPacketWriter w) => w.WriteString("limits@openssh.com"), CancellationToken).ConfigureAwait(false);
            EnsureNotStatusError(response);
            var reader = new SshPacketReader(response); reader.ReadByte(); reader.ReadUInt32();
            return new SftpProtocolLimits(reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64());
        }

        /// <summary>Query file-system statistics via <c>statvfs@openssh.com</c> (we surface the session quota as free space).</summary>
        public async ValueTask<SftpFileSystemStats> StatVfsAsync(String RemotePath, CancellationToken CancellationToken = default)
        {
            var response = await RoundtripAsync(SftpPacketType.Extended, (ref SshPacketWriter w) => { w.WriteString("statvfs@openssh.com"); w.WriteString(RemotePath); }, CancellationToken).ConfigureAwait(false);
            EnsureNotStatusError(response);
            var reader = new SshPacketReader(response); reader.ReadByte(); reader.ReadUInt32();
            return new SftpFileSystemStats(
                reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64(),
                reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64(),
                reader.ReadUInt64(), reader.ReadUInt64(), reader.ReadUInt64());
        }

        /// <summary>Close the SFTP channel.</summary>
        public ValueTask DisposeAsync()
            => channel.CloseAsync();

        #endregion


        #region (private) primitives

        private async ValueTask<String> OpenFileAsync(String Path, SftpOpenFlags Flags, CancellationToken CancellationToken)
        {
            var response = await RoundtripAsync(SftpPacketType.Open, (ref SshPacketWriter w) => { w.WriteString(Path); w.WriteUInt32((UInt32) Flags); SftpFileAttributes.File(0).Encode(ref w); }, CancellationToken).ConfigureAwait(false);
            return ReadHandle(response);
        }

        private async ValueTask<String> OpenDirectoryAsync(String Path, CancellationToken CancellationToken)
        {
            var response = await RoundtripAsync(SftpPacketType.OpenDir, (ref SshPacketWriter w) => w.WriteString(Path), CancellationToken).ConfigureAwait(false);
            return ReadHandle(response);
        }

        private async ValueTask<Byte[]> ReadAsync(String Handle, Int64 Offset, Int32 Length, CancellationToken CancellationToken)
        {
            var response = await RoundtripAsync(SftpPacketType.Read, (ref SshPacketWriter w) => { w.WriteString(Handle); w.WriteUInt64((UInt64) Offset); w.WriteUInt32((UInt32) Length); }, CancellationToken).ConfigureAwait(false);
            if ((SftpPacketType) response[0] == SftpPacketType.Status)
                return [];   // EOF (or an error surfaced as empty here; download stops)
            var reader = new SshPacketReader(response); reader.ReadByte(); reader.ReadUInt32();
            return reader.ReadBinaryString();
        }

        private ValueTask WriteAsync(String Handle, Int64 Offset, ReadOnlyMemory<Byte> Data, CancellationToken CancellationToken)
        {
            var data = Data.ToArray();
            return ExpectOkAsync(SftpPacketType.Write, (ref SshPacketWriter w) => { w.WriteString(Handle); w.WriteUInt64((UInt64) Offset); w.WriteBinaryString(data); }, CancellationToken);
        }

        private ValueTask CloseAsync(String Handle, CancellationToken CancellationToken)
            => ExpectOkAsync(SftpPacketType.Close, (ref SshPacketWriter w) => w.WriteString(Handle), CancellationToken);

        private async ValueTask<IReadOnlyList<SftpDirectoryEntry>> ReadDirectoryAsync(String Handle, CancellationToken CancellationToken)
        {
            var response = await RoundtripAsync(SftpPacketType.ReadDir, (ref SshPacketWriter w) => w.WriteString(Handle), CancellationToken).ConfigureAwait(false);
            if ((SftpPacketType) response[0] == SftpPacketType.Status)
                return [];   // EOF

            var reader = new SshPacketReader(response); reader.ReadByte(); reader.ReadUInt32();
            var count  = reader.ReadUInt32();
            var result = new List<SftpDirectoryEntry>((Int32) count);
            for (var i = 0U; i < count; i++)
            {
                var name = reader.ReadString();
                reader.ReadString();   // longname
                var attrs = SftpFileAttributes.Decode(ref reader);
                result.Add(new SftpDirectoryEntry(name, attrs));
            }
            return result;
        }

        // Send a request (a body-writer that must not await) and read the single matching response.
        private async ValueTask<Byte[]> RoundtripAsync(SftpPacketType Type, WriteBody Write, CancellationToken CancellationToken)
        {

            var id  = ++requestId;
            var abw = new ArrayBufferWriter<Byte>();
            var w   = new SshPacketWriter(abw);
            w.WriteByte((Byte) Type);
            w.WriteUInt32(id);
            Write(ref w);

            await SftpServer.SendAsync(channel, abw.WrittenSpan.ToArray(), CancellationToken).ConfigureAwait(false);

            return await SftpServer.ReadPacketAsync(channel, CancellationToken).ConfigureAwait(false)
                   ?? throw new SshChannelClosedException();

        }

        private async ValueTask ExpectOkAsync(SftpPacketType Type, WriteBody Write, CancellationToken CancellationToken)
        {
            var response = await RoundtripAsync(Type, Write, CancellationToken).ConfigureAwait(false);
            EnsureNotStatusError(response);
        }

        private delegate void WriteBody(ref SshPacketWriter Writer);

        private static String ReadHandle(Byte[] Response)
        {
            EnsureNotStatusError(Response);
            var reader = new SshPacketReader(Response); reader.ReadByte(); reader.ReadUInt32();
            return reader.ReadString();
        }

        private static void EnsureNotStatusError(Byte[] Response)
        {
            if ((SftpPacketType) Response[0] != SftpPacketType.Status)
                return;
            var reader = new SshPacketReader(Response); reader.ReadByte(); reader.ReadUInt32();
            var code   = (SftpStatusCode) reader.ReadUInt32();
            if (code != SftpStatusCode.Ok)
                throw new SftpException(code, reader.ReadString());
        }

        #endregion

    }

}
