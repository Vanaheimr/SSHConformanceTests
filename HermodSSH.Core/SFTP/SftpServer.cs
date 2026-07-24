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
using System.Buffers;
using System.Buffers.Binary;

#endregion

namespace org.GraphDefined.Vanaheimr.Hermod.SSH.SFTP
{

    /// <summary>
    /// Serves the SFTP protocol (version 3) over a channel duplex, dispatching requests to an
    /// <see cref="ISftpFileSystem"/> and returning the appropriate STATUS / HANDLE / DATA / NAME / ATTRS
    /// responses. One request is processed at a time (no pipelining), which is sufficient for correctness.
    /// </summary>
    public static class SftpServer
    {

        #region ServeAsync(Channel, FileSystem, CancellationToken)

        /// <summary>
        /// Run the SFTP server loop over an established subsystem channel. When <paramref name="Profile"/>
        /// is given, each operation is gated against it (least privilege): a denied operation returns
        /// SSH_FX_PERMISSION_DENIED without touching the file system.
        /// </summary>
        public static async ValueTask ServeAsync(SshChannelDuplex   Channel,
                                                 ISftpFileSystem    FileSystem,
                                                 SshAccessProfile?  Profile            = null,
                                                 CancellationToken  CancellationToken  = default)
        {

            // 1. INIT → VERSION.
            var init = await ReadPacketAsync(Channel, CancellationToken).ConfigureAwait(false)
                       ?? throw new SshWireException("The SFTP client closed the channel before SSH_FXP_INIT.");

            if ((SftpPacketType) init[0] != SftpPacketType.Init)
                throw new SshWireException("Expected SSH_FXP_INIT.");

            await SendAsync(Channel, BuildVersion(), CancellationToken).ConfigureAwait(false);

            // 2. Request loop.
            while (true)
            {

                var packet = await ReadPacketAsync(Channel, CancellationToken).ConfigureAwait(false);
                if (packet is null)
                    return;   // channel closed

                var request = ParseRequest(packet);
                Byte[] response;

                try
                {
                    if (Profile is not null && !Profile.AllowsSftp(RequiredPermission(request)))
                        response = BuildStatus(request.RequestId, SftpStatusCode.PermissionDenied, "Operation not permitted by the access profile.");
                    else
                        response = await DispatchAsync(FileSystem, request, CancellationToken).ConfigureAwait(false);
                }
                catch (SftpException e)
                {
                    response = BuildStatus(request.RequestId, e.Code, e.Message);
                }
                catch (Exception e)
                {
                    response = BuildStatus(request.RequestId, SftpStatusCode.Failure, e.Message);
                }

                await SendAsync(Channel, response, CancellationToken).ConfigureAwait(false);

            }

        }

        #endregion


        #region (private) DispatchAsync(FileSystem, Request, CancellationToken)

        private static async ValueTask<Byte[]> DispatchAsync(ISftpFileSystem FileSystem, SftpRequest Request, CancellationToken CancellationToken)
        {

            switch (Request.Type)
            {

                case SftpPacketType.RealPath:
                    return BuildName(Request.RequestId, [ new SftpDirectoryEntry(await FileSystem.RealPathAsync(Request.Path, CancellationToken).ConfigureAwait(false), SftpFileAttributes.Directory()) ]);

                case SftpPacketType.Open:
                    return BuildHandle(Request.RequestId, await FileSystem.OpenAsync(Request.Path, Request.OpenFlags, CancellationToken).ConfigureAwait(false));

                case SftpPacketType.OpenDir:
                    return BuildHandle(Request.RequestId, await FileSystem.OpenDirectoryAsync(Request.Path, CancellationToken).ConfigureAwait(false));

                case SftpPacketType.Close:
                    await FileSystem.CloseAsync(Request.Handle, CancellationToken).ConfigureAwait(false);
                    return BuildStatus(Request.RequestId, SftpStatusCode.Ok, "OK");

                case SftpPacketType.Read:
                {
                    var data = await FileSystem.ReadAsync(Request.Handle, Request.Offset, (Int32) Request.Length, CancellationToken).ConfigureAwait(false);
                    return data.Length == 0
                               ? BuildStatus(Request.RequestId, SftpStatusCode.Eof, "EOF")
                               : BuildData(Request.RequestId, data);
                }

                case SftpPacketType.Write:
                    await FileSystem.WriteAsync(Request.Handle, Request.Offset, Request.Data, CancellationToken).ConfigureAwait(false);
                    return BuildStatus(Request.RequestId, SftpStatusCode.Ok, "OK");

                case SftpPacketType.ReadDir:
                {
                    var entries = await FileSystem.ReadDirectoryAsync(Request.Handle, CancellationToken).ConfigureAwait(false);
                    return entries.Count == 0
                               ? BuildStatus(Request.RequestId, SftpStatusCode.Eof, "EOF")
                               : BuildName(Request.RequestId, entries);
                }

                case SftpPacketType.Stat or SftpPacketType.LStat:
                    return BuildAttrs(Request.RequestId, await FileSystem.StatAsync(Request.Path, CancellationToken).ConfigureAwait(false));

                case SftpPacketType.MkDir:
                    await FileSystem.MakeDirectoryAsync(Request.Path, CancellationToken).ConfigureAwait(false);
                    return BuildStatus(Request.RequestId, SftpStatusCode.Ok, "OK");

                case SftpPacketType.Remove:
                    await FileSystem.RemoveAsync(Request.Path, CancellationToken).ConfigureAwait(false);
                    return BuildStatus(Request.RequestId, SftpStatusCode.Ok, "OK");

                case SftpPacketType.RmDir:
                    await FileSystem.RemoveDirectoryAsync(Request.Path, CancellationToken).ConfigureAwait(false);
                    return BuildStatus(Request.RequestId, SftpStatusCode.Ok, "OK");

                case SftpPacketType.Rename:
                    await FileSystem.RenameAsync(Request.Path, Request.TargetPath, CancellationToken).ConfigureAwait(false);
                    return BuildStatus(Request.RequestId, SftpStatusCode.Ok, "OK");

                default:
                    return BuildStatus(Request.RequestId, SftpStatusCode.OpUnsupported, $"Unsupported request {Request.Type}.");

            }

        }

        #endregion

        #region (private) request parsing

        private readonly record struct SftpRequest(SftpPacketType Type, UInt32 RequestId, String Path, String TargetPath,
                                                   String Handle, Int64 Offset, UInt32 Length, SftpOpenFlags OpenFlags, Byte[] Data);

        private static SftpRequest ParseRequest(Byte[] Packet)
        {

            var reader     = new SshPacketReader(Packet);
            var type       = (SftpPacketType) reader.ReadByte();
            var requestId  = reader.ReadUInt32();

            String path = "", target = "", handle = "";
            Int64 offset = 0; UInt32 length = 0; SftpOpenFlags flags = 0; Byte[] data = [];

            switch (type)
            {
                case SftpPacketType.Open:
                    path  = reader.ReadString();
                    flags = (SftpOpenFlags) reader.ReadUInt32();
                    SftpFileAttributes.Decode(ref reader);
                    break;

                case SftpPacketType.OpenDir or SftpPacketType.RealPath or SftpPacketType.Stat or
                     SftpPacketType.LStat or SftpPacketType.MkDir or SftpPacketType.Remove or SftpPacketType.RmDir:
                    path = reader.ReadString();
                    break;

                case SftpPacketType.Rename:
                    path   = reader.ReadString();
                    target = reader.ReadString();
                    break;

                case SftpPacketType.Close:
                    handle = reader.ReadString();
                    break;

                case SftpPacketType.Read:
                    handle = reader.ReadString();
                    offset = (Int64) reader.ReadUInt64();
                    length = reader.ReadUInt32();
                    break;

                case SftpPacketType.Write:
                    handle = reader.ReadString();
                    offset = (Int64) reader.ReadUInt64();
                    data   = reader.ReadBinaryString();
                    break;

                case SftpPacketType.ReadDir:
                    handle = reader.ReadString();
                    break;
            }

            return new SftpRequest(type, requestId, path, target, handle, offset, length, flags, data);

        }

        // The SFTP permission an operation requires, for access-profile gating.
        private static SftpPermissions RequiredPermission(SftpRequest Request)
            => Request.Type switch {
                   SftpPacketType.Open      => Request.OpenFlags.HasFlag(SftpOpenFlags.Write) || Request.OpenFlags.HasFlag(SftpOpenFlags.Create)
                                                   ? (Request.OpenFlags.HasFlag(SftpOpenFlags.Create) ? SftpPermissions.Create : SftpPermissions.Write)
                                                   : SftpPermissions.Read,
                   SftpPacketType.Read      => SftpPermissions.Read,
                   SftpPacketType.Write     => SftpPermissions.Write,
                   SftpPacketType.OpenDir   => SftpPermissions.List,
                   SftpPacketType.ReadDir   => SftpPermissions.List,
                   SftpPacketType.MkDir     => SftpPermissions.MakeDirectory,
                   SftpPacketType.Remove    => SftpPermissions.Delete,
                   SftpPacketType.RmDir     => SftpPermissions.Delete,
                   SftpPacketType.Rename    => SftpPermissions.Rename,
                   SftpPacketType.Stat      => SftpPermissions.Stat,
                   SftpPacketType.LStat     => SftpPermissions.Stat,
                   SftpPacketType.FStat     => SftpPermissions.Stat,
                   _                        => SftpPermissions.None   // Close, RealPath, Init — always allowed
               };

        #endregion

        #region (private) response builders

        private static Byte[] BuildVersion()
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SftpPacketType.Version);
            w.WriteUInt32(SftpVersion.Three);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildStatus(UInt32 RequestId, SftpStatusCode Code, String Message)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SftpPacketType.Status);
            w.WriteUInt32(RequestId); w.WriteUInt32((UInt32) Code); w.WriteString(Message); w.WriteString("");
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildHandle(UInt32 RequestId, String Handle)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SftpPacketType.Handle);
            w.WriteUInt32(RequestId); w.WriteString(Handle);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildData(UInt32 RequestId, Byte[] Data)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SftpPacketType.Data);
            w.WriteUInt32(RequestId); w.WriteBinaryString(Data);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildAttrs(UInt32 RequestId, SftpFileAttributes Attributes)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SftpPacketType.Attrs);
            w.WriteUInt32(RequestId);
            Attributes.Encode(ref w);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildName(UInt32 RequestId, IReadOnlyList<SftpDirectoryEntry> Entries)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SftpPacketType.Name);
            w.WriteUInt32(RequestId);
            w.WriteUInt32((UInt32) Entries.Count);
            foreach (var entry in Entries)
            {
                w.WriteString(entry.Name);
                w.WriteString(LongName(entry));
                entry.Attributes.Encode(ref w);
            }
            return abw.WrittenSpan.ToArray();
        }

        private static String LongName(SftpDirectoryEntry Entry)
        {
            var type = Entry.Attributes.IsDirectory ? 'd' : '-';
            var size = Entry.Attributes.Size ?? 0;
            return $"{type}rw-r--r-- 1 owner group {size,10} Jan  1 00:00 {Entry.Name}";
        }

        #endregion

        #region (private) framing

        internal static async ValueTask<Byte[]?> ReadPacketAsync(SshChannelDuplex Channel, CancellationToken CancellationToken)
        {
            var lengthBytes = await Channel.TryReadExactAsync(4, CancellationToken).ConfigureAwait(false);
            if (lengthBytes is null)
                return null;
            var length = BinaryPrimitives.ReadUInt32BigEndian(lengthBytes);
            return await Channel.ReadExactAsync((Int32) length, CancellationToken).ConfigureAwait(false);
        }

        internal static ValueTask SendAsync(SshChannelDuplex Channel, Byte[] Body, CancellationToken CancellationToken)
        {
            var framed = new Byte[4 + Body.Length];
            BinaryPrimitives.WriteUInt32BigEndian(framed, (UInt32) Body.Length);
            Body.CopyTo(framed, 4);
            return Channel.SendAsync(framed, CancellationToken);
        }

        #endregion

    }

}
