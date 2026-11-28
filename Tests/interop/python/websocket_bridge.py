#!/usr/bin/env python3
#
# SSH over WebSocket with a WebSocket that is not ours: Python's "websockets" (RFC 6455) carrying a
# byte stream in binary messages under the subprotocol "ssh.open.charging.cloud", written from what
# Hermod's SSH/README.md says in "Over a WebSocket" and nothing else. OpenSSH is the SSH on the
# other side of it, so neither end of the tunnel is Hermod's in these tests but the one under test.
#
#   client <url>
#       stdin/stdout through one WebSocket to <url>: OpenSSH's ProxyCommand. It offers what a
#       browser-grade client offers - permessage-deflate among it -, so that what the endpoint
#       takes is the endpoint's choice.
#
#   server <port> forward <host> <tcp-port>
#       A WebSocket endpoint on 127.0.0.1:<port>; every connection is carried on to a TCP connection
#       of its own to <host>:<tcp-port> - an sshd behind it.
#
#   server <port> accept <tcp-port>
#       A WebSocket endpoint on 127.0.0.1:<port> and a TCP listener on 127.0.0.1:<tcp-port>; the next
#       TCP connection is paired with the next WebSocket. A back end that runs OpenSSH's client on what
#       a charging station opened: the station is the SSH server, and connects out.
#
#   server ... tls <certificate.pem> <key.pem>
#       Either endpoint as "wss": TLS with that certificate, before the WebSocket handshake.
#
#   server ... basic <user> <password>
#       Either endpoint behind HTTP Basic (RFC 7617): a handshake without these credentials is
#       answered 401 with a challenge of realm "hermod-endpoint", before the subprotocol is asked.
#
#   probe <config.json>
#       One handshake or one rule break against an endpoint, with a JSON verdict on stdout:
#       {"case": "none" | "other" | "anonymous" | "text" | "deflate", "url": ...}. Credentials
#       go in the URL's user information, which websockets sends as HTTP Basic.
#
# Every endpoint refuses a client that does not offer the subprotocol with 400, as the README asks.
# A bridge says on stderr what it carried, one line on opening and one on closing:
#
#   BRIDGE ws-open subprotocol=<name> extensions=<header or none>[ tls=<version>]
#   BRIDGE ws-close code=<code> sent=<messages> received=<messages> largest=<bytes>

import asyncio
import base64
import hmac
import json
import os
import signal
import ssl
import sys

from http import HTTPStatus

import websockets

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions     import ConnectionClosed, InvalidStatus


SUBPROTOCOL = "ssh.open.charging.cloud"
CHUNK       = 64 * 1024


def log(line):
    print(line, file=sys.stderr, flush=True)


class Stats:

    def __init__(self):
        self.sent     = 0
        self.received = 0
        self.largest  = 0


def opened(ws):
    extensions = ws.response.headers.get("Sec-WebSocket-Extensions") if ws.response is not None else None
    tls        = ws.transport.get_extra_info("ssl_object") if ws.transport is not None else None
    log(f"BRIDGE ws-open subprotocol={ws.subprotocol} extensions={extensions or 'none'}" +
        (f" tls={tls.version()}" if tls is not None else ""))


def closed(ws, stats):
    code = ws.close_code if ws.close_code is not None else "none"
    log(f"BRIDGE ws-close code={code} sent={stats.sent} received={stats.received} largest={stats.largest}")


# --- carrying bytes --------------------------------------------------------------------------------

async def ws_to(ws, write, stats):
    """Every binary message on, as it came; a text message is a breach of the rules."""
    async for message in ws:
        if isinstance(message, str):
            raise RuntimeError(f"a text message where SSH goes in binary ones: {message[:40]!r}")
        stats.received += 1
        stats.largest   = max(stats.largest, len(message))
        await write(message)


async def to_ws(read, ws, stats):
    """Whatever arrives, in messages cut where the reads happened to end - which means nothing."""
    while True:
        chunk = await read()
        if not chunk:
            break
        await ws.send(chunk)
        stats.sent += 1


async def both_ways(ws, read, write, end_of_stream, stats):
    """Carry both ways until either side is done, then end the other."""
    upstream   = asyncio.create_task(to_ws(read, ws, stats))
    downstream = asyncio.create_task(ws_to(ws, write, stats))

    done, _ = await asyncio.wait({ upstream, downstream }, return_when=asyncio.FIRST_COMPLETED)

    if upstream in done:
        # The stream ended: say so with a close, and let what is still in flight arrive.
        await ws.close()
        try:
            await asyncio.wait_for(downstream, 10)
        except (asyncio.TimeoutError, ConnectionClosed):
            pass
    else:
        upstream.cancel()

    await end_of_stream()

    for task in (upstream, downstream):
        if task.done() and not task.cancelled() and task.exception() is not None \
                       and not isinstance(task.exception(), ConnectionClosed):
            raise task.exception()


# --- client: OpenSSH's ProxyCommand ----------------------------------------------------------------

async def run_client(url):

    stats = Stats()

    async with connect(url, subprotocols=[SUBPROTOCOL]) as ws:

        opened(ws)

        if ws.subprotocol != SUBPROTOCOL:
            raise RuntimeError(f"the endpoint chose subprotocol {ws.subprotocol!r}")

        # ssh ends its ProxyCommand with a SIGHUP once it is done, often before the close has come
        # round: what was carried is said all the same.
        if hasattr(signal, "SIGHUP"):
            asyncio.get_running_loop().add_signal_handler(signal.SIGHUP, lambda: (closed(ws, stats), os._exit(0)))

        async def read():
            return await asyncio.to_thread(os.read, 0, CHUNK)

        async def write(data):
            await asyncio.to_thread(write_all, 1, data)

        async def end_of_stream():
            os.close(1)

        try:
            await both_ways(ws, read, write, end_of_stream, stats)
        finally:
            closed(ws, stats)

    # A thread may still sit in os.read on stdin, which nothing can interrupt; it is not waited for.
    os._exit(0)


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view    = view[written:]


# --- server: an endpoint in front of TCP -----------------------------------------------------------

def require_subprotocol(connection, request):
    offered = [ name.strip()
                for header in request.headers.get_all("Sec-WebSocket-Protocol")
                for name   in header.split(",") ]
    if SUBPROTOCOL not in offered:
        log(f"BRIDGE refused offered={offered or 'none'}")
        return connection.respond(HTTPStatus.BAD_REQUEST, f"This endpoint speaks {SUBPROTOCOL} only.\n")
    return None


def require_basic(user, password):

    expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def check(connection, request):
        given = request.headers.get("Authorization", "")
        if not hmac.compare_digest(given.encode(), expected.encode()):
            log(f"BRIDGE refused authorization={'wrong' if given else 'none'}")
            response = connection.respond(HTTPStatus.UNAUTHORIZED, "Who is connecting?\n")
            response.headers["WWW-Authenticate"] = 'Basic realm="hermod-endpoint"'
            return response
        return require_subprotocol(connection, request)

    return check


async def carry(ws, reader, writer):

    stats = Stats()
    opened(ws)

    async def read():
        return await reader.read(CHUNK)

    async def write(data):
        writer.write(data)
        await writer.drain()

    async def end_of_stream():
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    try:
        await both_ways(ws, read, write, end_of_stream, stats)
    except Exception as error:
        log(f"BRIDGE error {type(error).__name__}: {error}")
        await ws.close(1011)
    finally:
        closed(ws, stats)


async def run_server(port, mode, arguments):

    tls             = None
    process_request = require_subprotocol

    # The options after the mode's own arguments, in any order.
    for option in ("tls", "basic"):
        if option in arguments:
            at             = arguments.index(option)
            first, second  = arguments[at + 1], arguments[at + 2]
            arguments      = arguments[:at] + arguments[at + 3:]
            if option == "tls":
                tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                tls.load_cert_chain(first, second)
            else:
                process_request = require_basic(first, second)

    if mode == "forward":

        host, tcp_port = arguments[0], int(arguments[1])

        async def handler(ws):
            reader, writer = await asyncio.open_connection(host, tcp_port)
            await carry(ws, reader, writer)

    elif mode == "accept":

        waiting = asyncio.Queue()

        async def on_tcp(reader, writer):
            done = asyncio.get_running_loop().create_future()
            await waiting.put((reader, writer, done))
            await done

        # Listening before the WebSocket does: once its port answers, so does this one.
        await asyncio.start_server(on_tcp, "127.0.0.1", int(arguments[0]))

        async def handler(ws):
            reader, writer, done = await waiting.get()
            try:
                await carry(ws, reader, writer)
            finally:
                done.set_result(None)

    else:
        raise SystemExit(f"unknown server mode {mode!r}")

    async with serve(handler, "127.0.0.1", port,
                     subprotocols     = [ SUBPROTOCOL ],
                     process_request  = process_request,
                     ssl              = tls):
        await asyncio.Event().wait()


# --- probe: one handshake or rule break, judged ----------------------------------------------------

async def run_probe(config, result):

    case = config["case"]
    url  = config["url"]

    # Credentials, where the endpoint asks for them, go in the URL's user information.
    offered = { "none":      None,
                "other":     [ "ocpp2.1" ],
                "anonymous": [ SUBPROTOCOL ],
                "text":      [ SUBPROTOCOL ],
                "deflate":   [ SUBPROTOCOL ] }[case]

    result["stage"] = "handshake"

    try:
        ws = await connect(url, subprotocols=offered, compression="deflate")
    except InvalidStatus as refused:
        result["status"] = refused.response.status_code
        result["ok"]     = True
        return

    result["status"]      = 101
    result["subprotocol"] = ws.subprotocol
    result["extensions"]  = ws.response.headers.get("Sec-WebSocket-Extensions")

    try:

        if case == "text":
            result["stage"] = "text"
            await ws.send("SSH-2.0-as-text")

        # Whatever the endpoint sends until it closes - or, where nothing was broken, its first message.
        result["stage"]    = "receive"
        result["messages"] = []

        while True:
            message = await asyncio.wait_for(ws.recv(), 15)
            result["messages"].append({ "binary": isinstance(message, bytes),
                                        "text":   (message if isinstance(message, str) else message.decode("latin-1"))[:64] })
            if case == "deflate":
                break

    except ConnectionClosed as close:
        result["close_code"]   = close.rcvd.code   if close.rcvd is not None else None
        result["close_reason"] = close.rcvd.reason if close.rcvd is not None else None

    finally:
        await ws.close()

    result["ok"] = True


# --- main ------------------------------------------------------------------------------------------

def main():

    mode = sys.argv[1] if len(sys.argv) >= 2 else ""

    if mode == "client" and len(sys.argv) == 3:
        try:
            asyncio.run(run_client(sys.argv[2]))
        except Exception as error:
            log(f"BRIDGE error {type(error).__name__}: {error}")
            sys.exit(2)
        return

    if mode == "server" and len(sys.argv) >= 4:
        asyncio.run(run_server(int(sys.argv[2]), sys.argv[3], sys.argv[4:]))
        return

    with open(sys.argv[-1], "r", encoding="utf-8") as stream:
        config = json.load(stream)

    result = { "ok": False, "stage": "starting", "case": config.get("case"),
               "peer_version": f"websockets {websockets.__version__}" }

    try:
        asyncio.run(run_probe(config, result))
    except Exception as error:
        result["ok"]         = False
        result["error"]      = str(error)
        result["error_type"] = type(error).__name__

    print(json.dumps(result))


if __name__ == "__main__":
    main()
