#!/usr/bin/env python3
#
# asyncssh_messaging.py - Hermod's message protocol over an SSH subsystem, written from its
# specification alone (libs/Hermod/Hermod/SSH/Messaging/README.md) on top of AsyncSSH, for the NUnit
# interop suite. Nothing here comes from Hermod's code: what this file and Hermod agree on, the
# specification says.
#
# Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
# This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
# Licensed under the Apache License, Version 2.0.
#
# Two roles:
#
#   asyncssh_messaging.py <config.json>
#       A client against our server (PythonPeers.RunDriverAsync): connects, asks for the subsystem and
#       runs the "steps" of the configuration - frames to send, frames to read - then prints exactly one
#       JSON object with every frame it read. A failed SSH operation is {"ok": false, ...} with exit
#       code 0; a non-zero exit means the driver itself broke.
#
#       Configuration: host, port, username, key_path, known_hosts, subsystem, steps. A step is one of
#         {"op": "frame",  "kind": 16, "text": "..." | "hex": "..." | "json": {...}}   send a frame
#         {"op": "header", "kind": 16, "length": 1025}   send a frame header alone, no payload
#         {"op": "close",  "code": 1000, "reason": "..."}
#         {"op": "recv"}                                 read one frame (or the end of the channel)
#         {"op": "recv_until_eof"}                       read frames until the channel ends
#         {"op": "sleep",  "seconds": 2.5}               wait, reading nothing: a PING stays unanswered
#       A PING read on the way is answered with its PONG and listed in "pings", not in "frames" - where
#       the channel is still open: a PING read after the server closed it goes unanswered.
#
#   asyncssh_messaging.py server <port> <config.json>
#       A server for our client (PythonPeers.StartServerAsync), listening on 127.0.0.1:<port>. Writes its
#       host key's public half to "host_key_path" before it listens, takes the one key in
#       "authorized_key", and serves "subsystem" until it is killed.
#
#       Configuration: host_key_path, authorized_key, subsystem, subprotocols (what it speaks),
#       max_message_size (what it takes), refuse ({"code", "description", "retryAfter"}: refuse every
#       HELLO), welcome_subprotocol (choose this one, offered or not - to see the client refuse it).
#
#       After WELCOME it echoes TEXT and BINARY, answers PING with PONG and CLOSE with CLOSE - except for
#       the TEXT messages "close-me" (it sends CLOSE 1001 first), "ping-me" (it sends a PING),
#       "ext" (a frame of kind 0x80, then TEXT "after-extension") and "big:<n>" (a TEXT of n characters).
#       It logs to stderr what it read: "HELLO <json>", "CLOSE <code> <reason>", "PONG <hex>".

import asyncio
import json
import struct
import sys
import traceback

import asyncssh


# --- The frames (README, "Frames") -----------------------------------------------------------------

HELLO, WELCOME, REFUSED   = 0x01, 0x02, 0x03
TEXT,  BINARY             = 0x10, 0x11
PING,  PONG               = 0x20, 0x21
CLOSE                     = 0x30
KNOWN                     = { HELLO, WELCOME, REFUSED, TEXT, BINARY, PING, PONG, CLOSE }

MAX_CONTROL_PAYLOAD       = 64 * 1024


def encode(kind, payload=b""):
    """uint32 length (kind and payload), the kind, the payload."""
    return struct.pack(">IB", len(payload) + 1, kind) + payload


def encode_close(code, reason=""):
    return encode(CLOSE, struct.pack(">H", code) + reason.encode("utf-8"))


async def read_frame(reader, max_message_size):
    """
    One frame, or None at the end of the channel. The length is judged before anything is read for
    the payload; a frame too long is a ProtocolError with the close code the README gives.
    """
    try:
        header = await reader.readexactly(5)
    except asyncio.IncompleteReadError:
        return None
    length, kind = struct.unpack(">IB", header)
    if length < 1:
        raise ProtocolError(1002, "a frame of length 0")
    size = length - 1
    if kind in (TEXT, BINARY):
        if max_message_size is not None and size > max_message_size:
            raise ProtocolError(1009, f"a message of {size} bytes")
    elif size > MAX_CONTROL_PAYLOAD:
        raise ProtocolError(1002, f"a frame of kind 0x{kind:02x} with {size} bytes")
    try:
        payload = await reader.readexactly(size) if size else b""
    except asyncio.IncompleteReadError:
        return None
    return kind, payload


class ProtocolError(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code   = code
        self.reason = reason


def describe(kind, payload):
    """A frame as the JSON contract reports it."""
    frame = { "kind": kind, "hex": payload.hex() }
    if kind in (HELLO, WELCOME, REFUSED):
        try:
            frame["json"] = json.loads(payload.decode("utf-8"))
        except Exception:
            pass
    elif kind == TEXT:
        frame["text"] = payload.decode("utf-8", "replace")
    elif kind == CLOSE and len(payload) >= 2:
        frame["code"]   = struct.unpack(">H", payload[:2])[0]
        frame["reason"] = payload[2:].decode("utf-8", "replace")
    return frame


# --- The client ------------------------------------------------------------------------------------

async def run_client(config, result):

    result["stage"] = "connecting"

    async with asyncssh.connect(config["host"], config["port"],
                                username     = config["username"],
                                client_keys  = [ config["key_path"] ],
                                known_hosts  = config["known_hosts"]) as conn:

        result["stage"] = "subsystem"
        writer, reader, _ = await conn.open_session(subsystem=config["subsystem"], encoding=None)

        result["stage"]  = "steps"
        frames           = result["frames"]
        pings            = result["pings"]

        async def receive():
            while True:
                frame = await read_frame(reader, None)
                if frame is None:
                    frames.append({ "eof": True })
                    return False
                kind, payload = frame
                if kind == PING:
                    pings.append(payload.hex())
                    try:
                        writer.write(encode(PONG, payload))
                    except (BrokenPipeError, ConnectionError):
                        pass
                    continue
                frames.append(describe(kind, payload))
                return True

        for step in config["steps"]:

            op = step["op"]

            if op == "frame":
                if "text" in step:
                    payload = step["text"].encode("utf-8")
                elif "json" in step:
                    payload = json.dumps(step["json"]).encode("utf-8")
                else:
                    payload = bytes.fromhex(step.get("hex", ""))
                writer.write(encode(step["kind"], payload))

            elif op == "header":
                writer.write(struct.pack(">IB", step["length"], step["kind"]))

            elif op == "close":
                writer.write(encode_close(step["code"], step.get("reason", "")))

            elif op == "recv":
                await asyncio.wait_for(receive(), 20)

            elif op == "recv_until_eof":
                while await asyncio.wait_for(receive(), 20):
                    pass

            elif op == "sleep":
                await asyncio.sleep(step["seconds"])

        writer.close()

    result["ok"]    = True
    result["stage"] = "done"


# --- The server ------------------------------------------------------------------------------------

def log(line):
    print(line, file=sys.stderr, flush=True)


async def serve_subsystem(process, config):

    reader, writer = process.stdin, process.stdout
    limit          = config.get("max_message_size")
    close_sent     = False

    def close(code, reason=""):
        nonlocal close_sent
        if not close_sent:
            close_sent = True
            writer.write(encode_close(code, reason))

    try:

        # The handshake: HELLO first, or REFUSED hello-expected.
        frame = await asyncio.wait_for(read_frame(reader, MAX_CONTROL_PAYLOAD), 10)
        if frame is None:
            return
        kind, payload = frame
        if kind != HELLO:
            writer.write(encode(REFUSED, json.dumps({ "code": "hello-expected" }).encode("utf-8")))
            return

        hello = json.loads(payload.decode("utf-8"))
        log("HELLO " + json.dumps(hello, sort_keys=True))

        if "refuse" in config:
            writer.write(encode(REFUSED, json.dumps(config["refuse"]).encode("utf-8")))
            return

        offered = hello.get("subprotocols") or []
        spoken  = config.get("subprotocols") or []
        welcome = {}

        if "welcome_subprotocol" in config:
            welcome["subprotocol"] = config["welcome_subprotocol"]
        elif offered:
            chosen = next((p for p in offered if p in spoken), None)
            if chosen is None:
                writer.write(encode(REFUSED, json.dumps({ "code": "unsupported-subprotocol" }).encode("utf-8")))
                return
            welcome["subprotocol"] = chosen

        if limit is not None:
            welcome["maxMessageSize"] = limit
        welcome["peer"] = "asyncssh"

        writer.write(encode(WELCOME, json.dumps(welcome).encode("utf-8")))

        # Messages, until a CLOSE or the end of the channel.
        while True:

            frame = await read_frame(reader, limit)
            if frame is None:
                log("EOF")
                return
            kind, payload = frame

            if kind == TEXT:
                try:
                    text = payload.decode("utf-8")
                except UnicodeDecodeError:
                    raise ProtocolError(1007, "TEXT that is not UTF-8")
                if text == "close-me":
                    close(1001, "going away")
                elif text == "ping-me":
                    writer.write(encode(PING, b"from-asyncssh"))
                elif text == "ext":
                    writer.write(encode(0x80, b"an extension the client skips"))
                    writer.write(encode(TEXT, b"after-extension"))
                elif text.startswith("big:"):
                    writer.write(encode(TEXT, b"x" * int(text[4:])))
                else:
                    writer.write(encode(TEXT, payload))

            elif kind == BINARY:
                writer.write(encode(BINARY, payload))

            elif kind == PING:
                writer.write(encode(PONG, payload))

            elif kind == PONG:
                log("PONG " + payload.hex())

            elif kind == CLOSE:
                code   = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else None
                reason = payload[2:].decode("utf-8", "replace")
                log(f"CLOSE {code} {reason}")
                if code is not None:
                    close(code, reason)
                return

            elif kind in (HELLO, WELCOME, REFUSED) or (kind < 0x80 and kind not in KNOWN):
                raise ProtocolError(1002, f"a frame of kind 0x{kind:02x} after the handshake")

            # From 0x80 on: an extension, skipped.

    except ProtocolError as error:
        log(f"PROTOCOL-ERROR {error.code} {error.reason}")
        close(error.code, error.reason)

    except asyncio.TimeoutError:
        log("HELLO-TIMEOUT")

    finally:
        process.exit(0)


async def run_server(port, config):

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    with open(config["host_key_path"], "wb") as stream:
        stream.write(host_key.export_public_key("openssh"))

    authorized = asyncssh.import_authorized_keys(config["authorized_key"] + "\n")

    async def process_factory(process):
        if process.subsystem != config["subsystem"]:
            process.exit(1)
            return
        await serve_subsystem(process, config)

    await asyncssh.create_server(asyncssh.SSHServer, "127.0.0.1", port,
                                 server_host_keys        = [ host_key ],
                                 authorized_client_keys  = authorized,
                                 process_factory         = process_factory,
                                 encoding                = None)

    await asyncio.Event().wait()


# --- main ------------------------------------------------------------------------------------------

def main():

    if len(sys.argv) >= 2 and sys.argv[1] == "server":
        with open(sys.argv[3], "r", encoding="utf-8") as stream:
            config = json.load(stream)
        asyncio.run(run_server(int(sys.argv[2]), config))
        return

    with open(sys.argv[1], "r", encoding="utf-8") as stream:
        config = json.load(stream)

    result = { "ok": False, "stage": "starting", "frames": [], "pings": [],
               "peer_version": f"asyncssh {asyncssh.__version__}" }

    try:
        asyncio.run(run_client(config, result))
    except Exception as error:
        result["ok"]         = False
        result["error"]      = str(error)
        result["error_type"] = type(error).__name__
        result["debug_log"]  = traceback.format_exc().splitlines()

    print(json.dumps(result))


if __name__ == "__main__":
    main()
