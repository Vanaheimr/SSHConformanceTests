#!/usr/bin/env bash
#
# build-openssh.sh — build one OpenSSH portable release from source into a private prefix, for the
# version spread of the interop suite (PLAN.md, section 11.6).
#
# Usage:   ./build-openssh.sh <release> <prefix>
#          ./build-openssh.sh openssh-9.9p1 /opt/openssh-9.9p1
#
# Afterwards put "<prefix>/bin:<prefix>/sbin" in front of PATH: every OpenSSH fixture resolves its
# binaries through PATH (ssh, sftp, ssh-keygen through the PATH walk, sshd through `command -v`), so
# that is the entire integration — no harness change, no configuration switch.
#
# Two callers: the nightly's informational half, which discovers the newest release and passes its
# name, and the backward half's lane for a release no supported distribution ships any more. Both
# need the same three things the first real build taught us, each of which kills every check that
# needs their sshd before it ever listens:
#
#  * --with-pam. Without it sshd REJECTS `-o UsePAM=no` as an unknown option and exits. The fixture
#    passes it unconditionally and is right to, because the distribution sshd is built with PAM.
#    Nothing here authenticates through PAM; the option merely has to be recognised.
#  * --prefix, and an actual `make install-nokeys`. Without a prefix sshd looks for its configuration
#    under /usr/local/etc and gives up; and since 9.8 sshd re-executes $libexecdir/sshd-session for
#    every connection, so a binary run out of the build directory fails at the first one.
#  * A private prefix rather than /usr/local, so the distribution's own OpenSSH and /etc/ssh stay
#    exactly as they were. Host keys are not generated: the fixtures bring their own.
#
# Requires root for the build prerequisites (apt) — as sudo from an interactive shell, or directly
# when the caller already is root, as inside a CI container, where no sudo binary exists at all.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <release, e.g. openssh-9.9p1> <install prefix>" >&2
    exit 2
fi

RELEASE="$1"
PREFIX="$2"

if [[ ! "${RELEASE}" =~ ^openssh-[0-9]+\.[0-9]+p[0-9]+$ ]]; then
    echo "not a portable release name: '${RELEASE}' (expected e.g. openssh-9.9p1)" >&2
    exit 2
fi

MIRROR="https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable"

log() { printf '\033[1;34m[build]\033[0m %s\n' "$*"; }

SUDO="sudo"
if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=""
fi

log "Installing the build prerequisites ..."
${SUDO} env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    build-essential zlib1g-dev libssl-dev libpam0g-dev curl ca-certificates

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

log "Fetching ${RELEASE} ..."
curl -sSfL --max-time 300 -o "${WORK}/${RELEASE}.tar.gz" "${MIRROR}/${RELEASE}.tar.gz"
tar xzf "${WORK}/${RELEASE}.tar.gz" -C "${WORK}"

# A subshell so the cd stays in here. Plain `make`, not a hand-picked target list: the default target
# is the trodden path, and naming targets invites a parallel build to race on libssh.a.
log "Building ${RELEASE} into ${PREFIX} ..."
( cd "${WORK}/${RELEASE}" \
  && ./configure --prefix="${PREFIX}" --with-pam >/dev/null \
  && make -j"$(nproc)" >/dev/null \
  && make install-nokeys >/dev/null )

log "Built: $("${PREFIX}/bin/ssh" -V 2>&1)"
