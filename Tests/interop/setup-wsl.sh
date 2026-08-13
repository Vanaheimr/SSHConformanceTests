#!/usr/bin/env bash
#
# setup-wsl.sh — provision the interoperability peers for the HermodSSH test harness.
#
# Installs the third-party SSH/SFTP implementations that the interop suite (PLAN.md, section 11)
# drives our client and server against: OpenSSH, Dropbear, TinySSH, PuTTY tools, curl and the
# Python peers (AsyncSSH, Paramiko). Intended to run inside a WSL2 Debian/Ubuntu (or any
# Debian-family Linux). Idempotent: safe to re-run.
#
# Usage:   ./setup-wsl.sh            # install everything
#          ./setup-wsl.sh --check    # only report what is present, install nothing
#
# Requires root for the apt packages — as sudo from an interactive shell (it will normally ask for
# a password, so a non-interactive caller just gets a failure), or directly when the caller already
# is root, as inside a CI container, where no sudo binary exists at all. The Python peers go into a
# local virtual environment (.venv-interop next to this script), which needs no privileges at all,
# so '--check' and the venv half work fine unattended.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv-interop"

CHECK_ONLY=0
if [[ "${1:-}" == "--check" ]]; then
    CHECK_ONLY=1
fi

APT_PACKAGES=(
    openssh-server      # sshd — the reference server
    openssh-client      # ssh, sftp, ssh-keygen, ssh-keyscan, ssh-agent
    dropbear-bin        # dropbear / dbclient — embedded-world peer
    tinysshd            # radically minimal server (ed25519 + chacha20 + sntrup761)
    putty-tools         # plink / psftp / puttygen
    curl                # SFTP via libssh/libssh2 — a different stack
    socat               # run inetd-style tinysshd on a socket
    procps              # ps/pkill — the peer-lifecycle test's evidence; absent in the debian:13 container image
    golang-go           # builds the golang.org/x/crypto/ssh harness in go/
    openssl             # key/cert plumbing helpers
    ca-certificates
    python3
    python3-venv
    python3-pip
)

log()  { printf '\033[1;34m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn ]\033[0m %s\n' "$*"; }

# ---------------------------------------------------------------------------------------------------

if ! command -v apt-get >/dev/null 2>&1; then
    warn "apt-get not found — this script targets Debian/Ubuntu (WSL2). Install the peers manually."
    exit 1
fi

# Root needs no sudo — and a CI container has none to offer.
SUDO="sudo"
if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
fi

if [[ "${CHECK_ONLY}" -eq 0 ]]; then
    log "Installing interop peers via apt (root required) ..."
    ${SUDO} apt-get update -qq
    ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${APT_PACKAGES[@]}"

    log "Creating the Python virtual environment for AsyncSSH / Paramiko ..."

    # --copies, because symlinks do not survive a move across the /mnt boundary.
    if [[ ! -x "${VENV_DIR}/bin/python3" ]]; then
        rm -rf "${VENV_DIR}"
        python3 -m venv --copies "${VENV_DIR}"
    fi

    # The interpreter is invoked directly rather than through 'activate'. That script hard-codes the
    # absolute path the environment was created at, so after the checkout is moved or renamed it
    # silently points nowhere — 'pip' then resolves to the system one and Debian rejects it with
    # "externally-managed-environment" (PEP 668). Going through the venv's own python3 cannot miss.
    "${VENV_DIR}/bin/python3" -m pip install --quiet --upgrade pip
    "${VENV_DIR}/bin/python3" -m pip install --quiet asyncssh paramiko

fi

# ---------------------------------------------------------------------------------------------------

log "Installed peer versions:"

report() {
    local name="$1"; shift
    if command -v "$1" >/dev/null 2>&1; then
        printf '  %-12s %s\n' "${name}" "$("$@" 2>&1 | head -n1)"
    else
        printf '  %-12s \033[1;33mMISSING\033[0m\n' "${name}"
    fi
}

# TinySSH has no version flag, so report what the package manager knows.
report_tinyssh() {
    if command -v tinysshd >/dev/null 2>&1; then
        printf '  %-12s %s\n' "TinySSH" "$(dpkg-query -W -f='${Version}' tinysshd 2>/dev/null || echo installed)"
    else
        printf '  %-12s \033[1;33mMISSING\033[0m\n' "TinySSH"
    fi
}

# OpenSSH prints its version on stderr; grab it via -V.
report "OpenSSH"  ssh -V
report "sshd"     sshd -V
report "Dropbear" dropbear -V
report "dbclient" dbclient -V
report_tinyssh
report "plink"    plink -V
report "curl"     curl --version
report "socat"    socat -V

if [[ -d "${VENV_DIR}" ]]; then
    # The interpreter is invoked directly rather than through 'activate', which hard-codes the absolute
    # path the environment was created at — exactly as the tests do it, and so a relocated checkout
    # still reports the truth instead of a traceback.
    report "AsyncSSH" "${VENV_DIR}/bin/python3" -c 'import asyncssh; print(asyncssh.__version__)'
    report "Paramiko" "${VENV_DIR}/bin/python3" -c 'import paramiko; print(paramiko.__version__)'
else
    printf '  %-12s (python venv not created — run without --check)\n' "AsyncSSH/…"
fi

report "Go" go version

log "Done. NUnit reaches these peers via 'wsl.exe -e' from Windows, or directly on a Linux host."
