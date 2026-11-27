#!/usr/bin/env bash
#
# setup-wsl.sh — provision the interoperability peers for the HermodSSH test harness.
#
# Installs the third-party SSH/SFTP implementations that the interop suite (PLAN.md, section 11)
# drives our client and server against: OpenSSH, Dropbear, TinySSH, PuTTY tools, curl, libssh,
# wolfSSL for wolfSSH, Apache MINA SSHD, JSch, the Rust toolchain for Russh and the Python peers (AsyncSSH, Paramiko). Intended to
# run inside a WSL2 Debian/Ubuntu (or any Debian-family Linux). Idempotent: safe to re-run.
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
RUSSH_DIR="${SCRIPT_DIR}/russh"
# tr first: a Windows checkout (core.autocrlf) has CRLF in these files, and the trailing \r would end up
# in the toolchain name, which rustup then refuses as invalid.
RUST_TOOLCHAIN="$(tr -d '\r' < "${RUSSH_DIR}/rust-toolchain.toml" | sed -n 's/^channel *= *"\(.*\)"/\1/p')"

# The rustup.rs installer puts rustup into ~/.cargo/bin, which a non-login shell does not have on its PATH.
export PATH="${HOME}/.cargo/bin:${PATH}"

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
    gcc                 # builds the libssh peer in libssh/ ...
    pkg-config          # ... which finds its two libraries through pkg-config:
    libssh-dev          #     libssh itself - client and server in one library
    libjansson-dev      #     and a JSON reader/writer for the peer contract
    libwolfssl-dev      # wolfCrypt for the wolfSSH peer in wolfssh/, whose library build-wolfssh.sh builds ...
    make                #     ... from the pinned upstream release, as autotools projects are built:
    autoconf            #     a tag archive carries no configure script, so autogen.sh makes one
    automake
    libtool
    default-jdk-headless # builds and runs the Java peers in mina/ and jsch/ ...
    libmina-sshd-java   #     Apache MINA SSHD - client, server and SFTP server in Java
    libjsch-java        #     JSch, the maintained 0.2.x fork - client and SFTP client (pulls in BouncyCastle)
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

    # Not every archive carries every peer: Ubuntu has no Apache MINA SSHD package, and the nightly's
    # OpenSSH lanes provision Ubuntu images. A package the archive lacks is left out with a warning,
    # and the fixtures of its peer skip themselves by name. Debian 13 has them all, and the gate there
    # fails on any skip, so a misspelt package name still cannot pass unnoticed.
    INSTALLABLE=()
    for package in "${APT_PACKAGES[@]}"; do
        if apt-cache show "${package}" >/dev/null 2>&1; then
            INSTALLABLE+=("${package}")
        else
            warn "This archive has no package ${package} - its peer's checks will skip."
        fi
    done
    ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${INSTALLABLE[@]}"

    log "Creating the Python virtual environment for AsyncSSH / Paramiko / ncclient ..."

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
    "${VENV_DIR}/bin/python3" -m pip install --quiet asyncssh paramiko ncclient

    # Russh needs a newer Rust than Debian ships, so the compiler comes from rustup, at the version
    # russh/rust-toolchain.toml pins. A rustup that is already there - on the PATH or in ~/.cargo/bin -
    # is used as it is. Otherwise Debian's rustup package provides one, unless Debian's own rustc or
    # cargo is installed: that package conflicts with both, and this script does not remove a
    # developer's compiler to make room for it.
    if ! command -v rustup >/dev/null 2>&1; then
        if dpkg-query -W -f='${Status}\n' rustc cargo 2>/dev/null | grep -q "install ok installed"; then
            warn "Debian's rustc/cargo are installed, which Debian's rustup conflicts with - install rustup from https://rustup.rs for the Russh peer."
        elif ! apt-cache show rustup >/dev/null 2>&1; then
            # Ubuntu 22.04, for one, has no rustup package.
            warn "This archive has no package rustup - install it from https://rustup.rs for the Russh peer."
        else
            log "Installing rustup for the Russh peer ..."
            ${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq rustup
        fi
    fi

    if command -v rustup >/dev/null 2>&1; then
        log "Installing Rust ${RUST_TOOLCHAIN} for the Russh peer ..."
        # --no-self-update: a distribution's rustup may not replace itself, and Ubuntu 24.04's 1.26 still
        # tries after installing the toolchain and fails the script ("rustup is not installed at ~/.cargo").
        rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal --no-self-update
    fi

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
    report "ncclient" "${VENV_DIR}/bin/python3" -c 'import ncclient; print(ncclient.__version__)'
else
    printf '  %-12s (python venv not created — run without --check)\n' "AsyncSSH/…"
fi

report "Go" go version

if pkg-config --exists libssh 2>/dev/null; then
    printf '  %-12s %s\n' "libssh" "$(pkg-config --modversion libssh)"
else
    printf '  %-12s \033[1;33mMISSING\033[0m\n' "libssh"
fi

# wolfSSH itself is built by WolfSshInteropTests on first use, at the version build-wolfssh.sh pins;
# what has to be here is the wolfSSL it is built against.
if [[ -f /usr/include/wolfssl/options.h ]]; then
    printf '  %-12s %s\n' "wolfSSL" "$(dpkg-query -W -f='${Version}' libwolfssl-dev 2>/dev/null || echo installed)"
else
    printf '  %-12s \033[1;33mMISSING\033[0m\n' "wolfSSL"
fi
printf '  %-12s %s (build-wolfssh.sh)\n' "wolfSSH" "$(sed -n 's/^WOLFSSH_VERSION="\(.*\)"$/\1/p' "${SCRIPT_DIR}/wolfssh/build-wolfssh.sh")"

if command -v java >/dev/null 2>&1; then
    printf '  %-12s %s\n' "Java" "$(java -version 2>&1 | head -n1)"
else
    printf '  %-12s \033[1;33mMISSING\033[0m\n' "Java"
fi

if [[ -f /usr/share/java/sshd-core.jar ]]; then
    printf '  %-12s %s\n' "MINA SSHD" "$(dpkg-query -W -f='${Version}' libmina-sshd-java 2>/dev/null || echo installed)"
else
    printf '  %-12s \033[1;33mMISSING\033[0m\n' "MINA SSHD"
fi

if [[ -f /usr/share/java/jsch.jar ]]; then
    printf '  %-12s %s\n' "JSch" "$(dpkg-query -W -f='${Version}' libjsch-java 2>/dev/null || echo installed)"
else
    printf '  %-12s \033[1;33mMISSING\033[0m\n' "JSch"
fi

# The compiler the Russh peer is built with is the one its directory pins, not rustup's default. Asked
# through the toolchain list, because running rustc for a pinned toolchain that is missing makes rustup
# install it - and '--check' installs nothing.
if command -v rustup >/dev/null 2>&1 && rustup toolchain list | grep -q "^${RUST_TOOLCHAIN}-"; then
    printf '  %-12s %s\n' "Rust" "$(rustup run "${RUST_TOOLCHAIN}" rustc --version)"
else
    printf '  %-12s \033[1;33mMISSING\033[0m (rustup with Rust %s)\n' "Rust" "${RUST_TOOLCHAIN}"
fi
printf '  %-12s %s (Cargo.lock)\n' "Russh" "$(tr -d '\r' < "${RUSSH_DIR}/Cargo.lock" | sed -n '/^name = "russh"$/{n;s/^version = "\(.*\)"/\1/p}')"

log "Done. NUnit reaches these peers via 'wsl.exe -e' from Windows, or directly on a Linux host."
