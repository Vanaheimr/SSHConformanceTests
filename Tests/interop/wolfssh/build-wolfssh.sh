#!/usr/bin/env bash
#
# build-wolfssh.sh — build the wolfSSH library the interop peer links against, once per version.
#
# Usage:   ./build-wolfssh.sh <prefix>
#
# Debian packages wolfSSL but not wolfSSH, so the library comes from the pinned upstream release below:
# downloaded, checked against its SHA-256, built against the distribution's libwolfssl-dev and put into
# <prefix> as lib/, include/ and a file "cppflags". Nothing is installed system-wide, and nothing needs
# root. A <prefix> that already holds this version is left as it is, so only the first run pays for the
# build; RusshInteropTests treats its cargo target directory the same way.
#
# Only the library is built. wolfSSH's own examples call wc_ForceZero, which Debian 13's wolfSSL 5.7.2
# does not export yet, and the peer needs none of them.
#
# "cppflags" matters more than it looks. wolfSSH has no generated options header: configure hands its
# feature switches (WOLFSSH_SFTP, WOLFSSH_TERM, DEBUG_WOLFSSH, ...) to the compiler on the command
# line, and the public headers declare functions and lay out structs according to them. A program
# built without the same switches compiles cleanly against a struct the library does not have, so the
# peer is compiled with exactly the flags this build used.
#
# The prerequisites come from setup-wsl.sh: gcc, make, autoconf, automake, libtool, curl and
# libwolfssl-dev.

set -euo pipefail

WOLFSSH_VERSION="1.6.0"
WOLFSSH_SHA256="e345b580643af6715a4293ed7bab4e99ea562bb379adb8898eeae55c38b12f56"
WOLFSSH_URL="https://github.com/wolfSSL/wolfssh/archive/refs/tags/v${WOLFSSH_VERSION}-stable.tar.gz"

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <prefix>" >&2
    exit 2
fi

PREFIX="$1"

if [[ "$(cat "${PREFIX}/.version" 2>/dev/null)" == "${WOLFSSH_VERSION}" ]]; then
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

curl -sSfL --retry 3 -o "${WORK}/wolfssh.tar.gz" "${WOLFSSH_URL}"
echo "${WOLFSSH_SHA256}  ${WORK}/wolfssh.tar.gz" | sha256sum --check --quiet -

tar -C "${WORK}" -xzf "${WORK}/wolfssh.tar.gz"
cd "${WORK}/wolfssh-${WOLFSSH_VERSION}-stable"

# A tag archive carries no configure script; autogen.sh makes one.
./autogen.sh >/dev/null 2>&1

# SFTP for both roles; debug for the log the peer hands back with every result.
./configure --quiet --with-wolfssl=/usr --enable-sftp --enable-debug >/dev/null
make -j"$(nproc)" src/libwolfssh.la >/dev/null

# Assembled next to the prefix and moved into place in one step, so a run that is interrupted, or one
# racing another, never leaves a half-built prefix that looks finished.
STAGE="${PREFIX}.staging.$$"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/lib" "${STAGE}/include/wolfssh"
cp -a src/.libs/libwolfssh.so* "${STAGE}/lib/"
cp wolfssh/*.h "${STAGE}/include/wolfssh/"
sed -n 's/^AM_CPPFLAGS = //p' Makefile > "${STAGE}/cppflags"
echo "${WOLFSSH_VERSION}" > "${STAGE}/.version"

rm -rf "${PREFIX}"
mv "${STAGE}" "${PREFIX}"
