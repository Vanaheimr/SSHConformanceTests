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

namespace org.GraphDefined.Vanaheimr.Hermod.SSH
{

    /// <summary>
    /// The SSH connection protocol (RFC 4254) for interactive command execution: opening a
    /// <c>session</c> channel, the <c>exec</c> request, channel data with window-based flow control, and
    /// <c>exit-status</c>. This covers the "log in, run a command, capture the output, log out" use case
    /// on both roles; a full multi-channel connection object grows from here.
    /// </summary>
    public static class SshConnection
    {

        #region Constants

        private const UInt32 InitialWindow  = 2 * 1024 * 1024;   // 2 MiB
        private const UInt32 MaxPacket      = 32 * 1024;         // 32 KiB
        private const String SessionType    = "session";

        #endregion


        #region ExecuteAsync(Transport, Command, CancellationToken)

        /// <summary>
        /// Run a single command on the peer over a fresh session channel, capturing stdout, stderr and the
        /// exit status (the client side of remote command execution).
        /// </summary>
        public static async ValueTask<SshCommandResult> ExecuteAsync(SshTransport       Transport,
                                                                     String             Command,
                                                                     CancellationToken  CancellationToken = default)
        {

            const UInt32 localChannel = 0;

            await Transport.SendPacketAsync(BuildChannelOpen(localChannel, InitialWindow, MaxPacket), CancellationToken).ConfigureAwait(false);

            // Wait for the channel to be confirmed (or refused).
            var remoteChannel = await AwaitOpenConfirmationAsync(Transport, CancellationToken).ConfigureAwait(false);

            await Transport.SendPacketAsync(BuildExecRequest(remoteChannel, Command), CancellationToken).ConfigureAwait(false);

            var stdout      = new ArrayBufferWriter<Byte>();
            var stderr      = new ArrayBufferWriter<Byte>();
            var exitCode    = -1;
            var myWindow    = InitialWindow;
            var closeSent   = false;

            while (true)
            {

                var payload = await Transport.ReceivePacketAsync(CancellationToken).ConfigureAwait(false);
                var message = (SshMessageNumber) payload[0];

                switch (message)
                {

                    case SshMessageNumber.ChannelSuccess:
                        break;   // the exec request was accepted

                    case SshMessageNumber.ChannelFailure:
                        throw new SshWireException("The peer rejected the exec request.");

                    case SshMessageNumber.ChannelData:
                    {
                        var data = ParseChannelData(payload);
                        stdout.Write(data);
                        myWindow = await ReplenishAsync(Transport, remoteChannel, myWindow, (UInt32) data.Length, CancellationToken).ConfigureAwait(false);
                        break;
                    }

                    case SshMessageNumber.ChannelExtendedData:
                    {
                        var (code, data) = ParseChannelExtendedData(payload);
                        if (code == 1)   // SSH_EXTENDED_DATA_STDERR
                            stderr.Write(data);
                        myWindow = await ReplenishAsync(Transport, remoteChannel, myWindow, (UInt32) data.Length, CancellationToken).ConfigureAwait(false);
                        break;
                    }

                    case SshMessageNumber.ChannelRequest:
                    {
                        var request = ParseChannelRequest(payload);
                        if (request.RequestType == "exit-status")
                            exitCode = (Int32) request.ExitStatus;
                        else if (request.RequestType == "exit-signal")
                            exitCode = 255;
                        break;
                    }

                    case SshMessageNumber.ChannelWindowAdjust:
                    case SshMessageNumber.ChannelEof:
                        break;

                    case SshMessageNumber.ChannelClose:
                        if (!closeSent)
                            await Transport.SendPacketAsync(BuildChannelClose(remoteChannel), CancellationToken).ConfigureAwait(false);
                        return new SshCommandResult(exitCode, stdout.WrittenSpan.ToArray(), stderr.WrittenSpan.ToArray());

                    default:
                        break;   // ignore unrelated global/channel traffic

                }

            }

        }

        #endregion

        #region ServeExecAsync(Transport, Username, Handler, CancellationToken)

        /// <summary>
        /// Serve one interactive session: accept a <c>session</c> channel, dispatch an <c>exec</c> or
        /// <c>shell</c> request to <paramref name="Handler"/>, stream its output, and report the exit status.
        /// </summary>
        public static async ValueTask ServeExecAsync(SshTransport       Transport,
                                                     String             Username,
                                                     SshExecHandler     Handler,
                                                     CancellationToken  CancellationToken = default)
        {

            const UInt32 localChannel = 0;

            UInt32  remoteChannel  = 0;
            var     remoteWindow   = 0L;
            var     closeSent      = false;
            var     handlerDone    = false;

            while (true)
            {

                var payload = await Transport.ReceivePacketAsync(CancellationToken).ConfigureAwait(false);
                var message = (SshMessageNumber) payload[0];

                switch (message)
                {

                    case SshMessageNumber.ChannelOpen:
                    {
                        var open = ParseChannelOpen(payload);
                        if (open.ChannelType != SessionType)
                        {
                            await Transport.SendPacketAsync(BuildChannelOpenFailure(open.SenderChannel), CancellationToken).ConfigureAwait(false);
                            break;
                        }
                        remoteChannel  = open.SenderChannel;
                        remoteWindow   = open.InitialWindow;
                        await Transport.SendPacketAsync(BuildChannelOpenConfirmation(remoteChannel, localChannel, InitialWindow, MaxPacket), CancellationToken).ConfigureAwait(false);
                        break;
                    }

                    case SshMessageNumber.ChannelWindowAdjust:
                    {
                        remoteWindow += ParseWindowAdjust(payload);
                        break;
                    }

                    case SshMessageNumber.ChannelRequest:
                    {

                        var request = ParseChannelRequest(payload);

                        if (request.RequestType is "exec" or "shell")
                        {

                            if (request.WantReply)
                                await Transport.SendPacketAsync(BuildChannelSuccess(remoteChannel), CancellationToken).ConfigureAwait(false);

                            // Write callback used by the handler; chunks to the max packet and tracks the window.
                            var channel = remoteChannel;
                            ValueTask Write(ReadOnlyMemory<Byte> data, Boolean isStderr, CancellationToken ct)
                                => WriteChannelDataAsync(Transport, channel, data, isStderr, () => remoteWindow, n => remoteWindow -= n, ct);

                            var context   = new SshExecContext(request.Command, Username, Write);
                            var exitCode  = await Handler(context, CancellationToken).ConfigureAwait(false);

                            await Transport.SendPacketAsync(BuildExitStatus(remoteChannel, (UInt32) exitCode), CancellationToken).ConfigureAwait(false);
                            await Transport.SendPacketAsync(BuildChannelEof(remoteChannel), CancellationToken).ConfigureAwait(false);
                            await Transport.SendPacketAsync(BuildChannelClose(remoteChannel), CancellationToken).ConfigureAwait(false);
                            closeSent    = true;
                            handlerDone  = true;

                        }
                        else if (request.WantReply)
                        {
                            // pty-req, env, … — accept silently so the client proceeds to exec/shell.
                            var reply = request.RequestType is "pty-req" or "env" or "shell" or "window-change"
                                            ? BuildChannelSuccess(remoteChannel)
                                            : BuildChannelFailure(remoteChannel);
                            await Transport.SendPacketAsync(reply, CancellationToken).ConfigureAwait(false);
                        }

                        break;

                    }

                    case SshMessageNumber.ChannelEof:
                        break;

                    case SshMessageNumber.ChannelClose:
                        if (!closeSent)
                            await Transport.SendPacketAsync(BuildChannelClose(remoteChannel), CancellationToken).ConfigureAwait(false);
                        return;

                    default:
                        break;

                }

                // If the exec finished and the peer already closed, we are done even without another read.
                if (handlerDone && closeSent && CancellationToken.IsCancellationRequested)
                    return;

            }

        }

        #endregion


        #region (private) flow control

        private static async ValueTask<UInt32> ReplenishAsync(SshTransport Transport, UInt32 RemoteChannel, UInt32 Window, UInt32 Consumed, CancellationToken CancellationToken)
        {

            Window = Consumed >= Window ? 0 : Window - Consumed;

            if (Window < InitialWindow / 2)
            {
                var increment = InitialWindow - Window;
                await Transport.SendPacketAsync(BuildWindowAdjust(RemoteChannel, increment), CancellationToken).ConfigureAwait(false);
                Window += increment;
            }

            return Window;

        }

        private static async ValueTask WriteChannelDataAsync(SshTransport Transport, UInt32 Channel, ReadOnlyMemory<Byte> Data, Boolean IsStderr, Func<Int64> Window, Action<Int64> Consume, CancellationToken CancellationToken)
        {

            var offset = 0;
            while (offset < Data.Length)
            {
                var chunk = Math.Min((Int32) MaxPacket, Data.Length - offset);
                var slice = Data.Slice(offset, chunk);

                await Transport.SendPacketAsync(IsStderr
                                                    ? BuildChannelExtendedData(Channel, 1, slice.Span)
                                                    : BuildChannelData(Channel, slice.Span),
                                                CancellationToken).ConfigureAwait(false);

                Consume(chunk);
                offset += chunk;
            }

        }

        #endregion

        #region (private) message builders

        private static Byte[] BuildChannelOpen(UInt32 Sender, UInt32 Window, UInt32 MaxPacketSize)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelOpen);
            w.WriteString(SessionType);
            w.WriteUInt32(Sender); w.WriteUInt32(Window); w.WriteUInt32(MaxPacketSize);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildChannelOpenConfirmation(UInt32 Recipient, UInt32 Sender, UInt32 Window, UInt32 MaxPacketSize)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelOpenConfirmation);
            w.WriteUInt32(Recipient); w.WriteUInt32(Sender); w.WriteUInt32(Window); w.WriteUInt32(MaxPacketSize);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildChannelOpenFailure(UInt32 Recipient)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelOpenFailure);
            w.WriteUInt32(Recipient); w.WriteUInt32(3); w.WriteString("unknown channel type"); w.WriteString("");
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildExecRequest(UInt32 Recipient, String Command)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelRequest);
            w.WriteUInt32(Recipient); w.WriteString("exec"); w.WriteBoolean(true); w.WriteString(Command);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildExitStatus(UInt32 Recipient, UInt32 Code)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelRequest);
            w.WriteUInt32(Recipient); w.WriteString("exit-status"); w.WriteBoolean(false); w.WriteUInt32(Code);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildChannelData(UInt32 Recipient, ReadOnlySpan<Byte> Data)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelData);
            w.WriteUInt32(Recipient); w.WriteBinaryString(Data);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildChannelExtendedData(UInt32 Recipient, UInt32 Code, ReadOnlySpan<Byte> Data)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelExtendedData);
            w.WriteUInt32(Recipient); w.WriteUInt32(Code); w.WriteBinaryString(Data);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildWindowAdjust(UInt32 Recipient, UInt32 Increment)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) SshMessageNumber.ChannelWindowAdjust);
            w.WriteUInt32(Recipient); w.WriteUInt32(Increment);
            return abw.WrittenSpan.ToArray();
        }

        private static Byte[] BuildChannelEof(UInt32 Recipient)   => Simple(SshMessageNumber.ChannelEof,     Recipient);
        private static Byte[] BuildChannelClose(UInt32 Recipient) => Simple(SshMessageNumber.ChannelClose,   Recipient);
        private static Byte[] BuildChannelSuccess(UInt32 Recipient) => Simple(SshMessageNumber.ChannelSuccess, Recipient);
        private static Byte[] BuildChannelFailure(UInt32 Recipient) => Simple(SshMessageNumber.ChannelFailure, Recipient);

        private static Byte[] Simple(SshMessageNumber Message, UInt32 Recipient)
        {
            var abw = new ArrayBufferWriter<Byte>(); var w = new SshPacketWriter(abw);
            w.WriteByte((Byte) Message); w.WriteUInt32(Recipient);
            return abw.WrittenSpan.ToArray();
        }

        #endregion

        #region (private) message parsers

        private static async ValueTask<UInt32> AwaitOpenConfirmationAsync(SshTransport Transport, CancellationToken CancellationToken)
        {
            while (true)
            {
                var payload = await Transport.ReceivePacketAsync(CancellationToken).ConfigureAwait(false);
                var message = (SshMessageNumber) payload[0];

                if (message == SshMessageNumber.ChannelOpenConfirmation)
                {
                    var reader = new SshPacketReader(payload);
                    reader.ReadByte();
                    reader.ReadUInt32();                        // our channel (recipient)
                    return reader.ReadUInt32();                 // the peer's channel (sender)
                }

                if (message == SshMessageNumber.ChannelOpenFailure)
                    throw new SshWireException("The peer refused to open the session channel.");
            }
        }

        private static Byte[] ParseChannelData(ReadOnlySpan<Byte> Payload)
        {
            var reader = new SshPacketReader(Payload);
            reader.ReadByte(); reader.ReadUInt32();
            return reader.ReadBinaryString();
        }

        private static (UInt32 Code, Byte[] Data) ParseChannelExtendedData(ReadOnlySpan<Byte> Payload)
        {
            var reader = new SshPacketReader(Payload);
            reader.ReadByte(); reader.ReadUInt32();
            var code = reader.ReadUInt32();
            return (code, reader.ReadBinaryString());
        }

        private static UInt32 ParseWindowAdjust(ReadOnlySpan<Byte> Payload)
        {
            var reader = new SshPacketReader(Payload);
            reader.ReadByte(); reader.ReadUInt32();
            return reader.ReadUInt32();
        }

        private readonly record struct ChannelOpenInfo(String ChannelType, UInt32 SenderChannel, UInt32 InitialWindow, UInt32 MaxPacketSize);

        private static ChannelOpenInfo ParseChannelOpen(ReadOnlySpan<Byte> Payload)
        {
            var reader = new SshPacketReader(Payload);
            reader.ReadByte();
            var type    = reader.ReadString();
            var sender  = reader.ReadUInt32();
            var window  = reader.ReadUInt32();
            var maxPkt  = reader.ReadUInt32();
            return new ChannelOpenInfo(type, sender, window, maxPkt);
        }

        private readonly record struct ChannelRequestInfo(String RequestType, Boolean WantReply, String Command, UInt32 ExitStatus);

        private static ChannelRequestInfo ParseChannelRequest(ReadOnlySpan<Byte> Payload)
        {

            var reader = new SshPacketReader(Payload);
            reader.ReadByte();
            reader.ReadUInt32();                       // recipient channel
            var type       = reader.ReadString();
            var wantReply  = reader.ReadBoolean();

            var command    = "";
            UInt32 exit    = 0;

            if (type is "exec")
                command = reader.ReadString();
            else if (type == "exit-status")
                exit = reader.ReadUInt32();

            return new ChannelRequestInfo(type, wantReply, command, exit);

        }

        #endregion

    }

}
