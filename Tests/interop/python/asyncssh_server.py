#!/usr/bin/env python3
#
# asyncssh_server.py — an AsyncSSH server for HermodSSH's client to log in to, for the NUnit interop suite.
#
# Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
# This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
# Licensed under the Apache License, Version 2.0.
#
# Contract with the C# side (WslInterop.StartServerAsync + WslInterop.PythonPeerCommand):
#   argv[1] is the port to listen on (127.0.0.1), argv[2] a JSON configuration file.
#   The server generates its host key and writes the public half to "host_key_path" before it
#   listens - so once the port answers, the key to pin is on disk. It serves until it is killed.
#
# Configuration keys:
#   host_key_path   where to write the host key's public half (OpenSSH format)
#   username        the one account that may log in
#   password        accept this password (omit: no "password" method)
#   kbdint          {"name", "instruction", "prompts": [[text, echo], ...], "answers": [...]}
#                   (omit: no "keyboard-interactive" method)
#   marker          what an exec prints, followed by the command and the method that let it in
#   user_ca         accept publickey only with a user certificate of this CA (an OpenSSH public key
#                   line), as a "cert-authority" line in authorized_keys would
#   host_certificate {"principals": [...], "ca_path": ...}: present the host key with a certificate
#                   AsyncSSH issues from a CA of its own, whose public key it writes to "ca_path"
#
# The start of authentication ("AUTH begin <user>") and every password or keyboard-interactive
# request it is asked to judge ("AUTH <method> <user>") are logged to stderr, which the test reads
# back from the server's output to tell what our client sent.

import asyncio
import json
import sys
import time

import asyncssh


class _Server(asyncssh.SSHServer):

    def __init__(self, config):
        self._config  = config

    def connection_made(self, conn):
        self._conn = conn

    def begin_auth(self, username):
        print(f"AUTH begin {username}", file=sys.stderr, flush=True)
        if "user_ca" in self._config:
            self._conn.set_authorized_keys(asyncssh.import_authorized_keys(f"cert-authority {self._config['user_ca']}\n"))
        return True

    # password (RFC 4252 §8)

    def password_auth_supported(self):
        return "password" in self._config

    def validate_password(self, username, password):
        print(f"AUTH password {username}", file=sys.stderr, flush=True)
        ok = username == self._config["username"] and password == self._config["password"]
        if ok:
            self._conn.set_extra_info(hermod_method="password")
        return ok

    # keyboard-interactive (RFC 4256)

    def kbdint_auth_supported(self):
        return "kbdint" in self._config

    def get_kbdint_challenge(self, username, lang, submethods):
        print(f"AUTH keyboard-interactive {username}", file=sys.stderr, flush=True)
        kbdint = self._config["kbdint"]
        return (kbdint["name"], kbdint["instruction"], "", [(text, echo) for text, echo in kbdint["prompts"]])

    def validate_kbdint_response(self, username, responses):
        ok = username == self._config["username"] and list(responses) == self._config["kbdint"]["answers"]
        if ok:
            self._conn.set_extra_info(hermod_method="keyboard-interactive")
        return ok

    # publickey only with a certificate of the CA in "user_ca": the key alone is never taken.

    def public_key_auth_supported(self):
        return "user_ca" in self._config

    def auth_completed(self):
        if self._conn.get_extra_info("hermod_method") is None:
            self._conn.set_extra_info(hermod_method="publickey")


async def _main():

    port = int(sys.argv[1])
    with open(sys.argv[2], "r", encoding="utf-8") as stream:
        config = json.load(stream)

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    with open(config["host_key_path"], "wb") as stream:
        stream.write(host_key.export_public_key("openssh"))

    # With "host_certificate", the host key comes with a certificate AsyncSSH issues from a CA of its
    # own, whose public key goes to "ca_path" for the client to trust.
    server_host_keys = [host_key]
    if "host_certificate" in config:
        ca   = asyncssh.generate_private_key("ssh-ed25519")
        now  = int(time.time())
        cert = ca.generate_host_certificate(host_key.convert_to_public(), "issued-by-asyncssh",
                                            serial       = 4711,
                                            principals   = config["host_certificate"]["principals"],
                                            valid_after  = now - 3600,
                                            valid_before = now + 3600)
        with open(config["host_certificate"]["ca_path"], "wb") as stream:
            stream.write(ca.export_public_key("openssh"))
        server_host_keys = [(host_key, cert)]

    async def process(proc):
        method = proc.get_extra_info("hermod_method") or "?"
        proc.stdout.write(f"{config['marker']} {proc.command} {method}\n")
        proc.exit(0)

    await asyncssh.create_server(lambda: _Server(config), "127.0.0.1", port,
                                 server_host_keys = server_host_keys,
                                 process_factory  = process)

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(_main())
