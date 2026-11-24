#!/usr/bin/env python3
#
# ncclient_driver.py — drive a NETCONF subsystem on HermodSSH's server from ncclient, for the NUnit
# interop suite.
#
# Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
# This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
# Licensed under the Apache License, Version 2.0.
#
# Contract with the C# side (WslInterop.RunPeerDriverAsync):
#   argv[1] is a JSON configuration file; exactly one JSON object is printed to stdout.
#   A failed NETCONF or SSH operation is reported as {"ok": false, ...} with exit code 0 — a non-zero
#   exit means the driver itself broke, which the test surfaces as a harness bug.
#
# Configuration keys:
#   host, port, username, key_path   where to connect, and as whom
#   host_key_b64                     the server's host key blob, base64; anything else is refused
#   timeout_seconds                  (optional) the budget for the whole session, default 30
#
# What it does, in this order, as an application would: connect (which requests the "netconf"
# subsystem and exchanges <hello>s), <get-config> of "running", a <lock> the server is expected to
# refuse with an <rpc-error>, and <close-session>.

import json
import logging
import sys
import threading
import traceback
import xml.etree.ElementTree as ElementTree

import ncclient
from ncclient import manager
from ncclient.operations import RPCError


class _RingHandler(logging.Handler):
    """
    Keeps ncclient's and Paramiko's own trace, so a failed run can hand it to the test — and only
    then, since it is noise when the run succeeds.
    """

    def __init__(self, capacity=400):
        super().__init__(level=logging.DEBUG)
        self.records = []
        self.capacity = capacity

    def emit(self, record):
        self.records.append(self.format(record))
        if len(self.records) > self.capacity:
            del self.records[0]


def _framing(session):
    """
    Which framing ncclient settled on after the <hello>s: base:1.1's chunks or base:1.0's end-of-message
    marker. Read defensively from a private attribute and used as diagnostic evidence only - the server
    side records what actually arrived on the wire.
    """
    base  = getattr(session, "_base", None)
    value = getattr(base, "value", base)
    return { 1: "1.0", 2: "1.1" }.get(value, str(base))


def _run(config, result):

    result["stage"] = "connecting"

    # Not as a context manager: leaving one sends a <close-session> of its own, and this one is ours to
    # send - and to see answered.
    session = manager.connect(host            = config["host"],
                              port            = config["port"],
                              username        = config["username"],
                              key_filename    = config["key_path"],
                              hostkey_verify  = True,
                              hostkey_b64     = config["host_key_b64"],
                              allow_agent     = False,
                              look_for_keys   = False,
                              timeout         = config.get("timeout_seconds", 30),
                              device_params   = { "name": "default" })

    try:

        result["stage"]               = "hello"
        result["session_id"]          = session.session_id
        result["server_capabilities"] = sorted(session.server_capabilities)
        result["framing"]             = _framing(session._session)

        result["stage"] = "get-config"
        reply = session.get_config(source="running")
        blob  = ElementTree.fromstring(reply.data_xml.encode("utf-8")).find(".//{urn:test:hermod}blob")
        result["config_blob"] = blob.text if blob is not None else None

        result["stage"] = "lock"
        try:
            session.lock(target="running")
            result["lock_error"] = None
        except RPCError as error:
            result["lock_error"] = { "type": error.type, "tag": error.tag, "severity": error.severity, "message": error.message }

        result["stage"] = "close-session"
        session.close_session()

    finally:
        if session.connected:
            session._session.close()

    result["stage"] = "closed"
    result["ok"]    = True


def _run_guarded(config, result):
    """
    Run the session under our own timeout, on a worker thread: ncclient blocks while it waits for a
    reply, and failing here keeps the 'stage' field, which says how far the session got.
    """
    timeout = config.get("timeout_seconds", 30)
    failure = {}

    def work():
        try:
            _run(config, result)
        except Exception as exception:                                 # noqa: BLE001 — reported, not swallowed
            failure["error"] = str(exception) or repr(exception)
            failure["type"]  = type(exception).__name__

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(timeout)

    if worker.is_alive():
        result["ok"]         = False
        result["error"]      = f"timed out after {timeout}s in stage '{result.get('stage')}'"
        result["error_type"] = "TimeoutError"
    elif failure:
        result["ok"]         = False
        result["error"]      = failure["error"]
        result["error_type"] = failure["type"]


def main():

    if len(sys.argv) != 2:
        print("usage: ncclient_driver.py <configuration.json>", file=sys.stderr)
        return 2

    result = {
        "ok":                  False,
        "error":               None,
        "error_type":          None,
        "stage":               "starting",
        "peer_version":        ncclient.__version__,
        "session_id":          None,
        "server_capabilities": None,
        "framing":             None,
        "config_blob":         None,
        "lock_error":          None,
    }

    trace = _RingHandler()
    trace.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    for name in ("ncclient", "paramiko"):
        logging.getLogger(name).addHandler(trace)
        logging.getLogger(name).setLevel(logging.DEBUG)

    try:
        with open(sys.argv[1], "r", encoding="utf-8") as stream:
            config = json.load(stream)
        _run_guarded(config, result)
    except Exception:                                                  # noqa: BLE001 — a harness bug
        traceback.print_exc(file=sys.stderr)
        return 2

    if not result["ok"]:
        result["debug_log"] = trace.records

    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
