#!/usr/bin/env bash
#
# forward-proxy.sh - one real forward proxy, in the foreground, for the SSH-over-WebSocket interop
# tests that go through one (ForwardProxyInteropTests.cs): Squid, the proxy of most corporate
# networks, or tinyproxy, the small one of routers and embedded Linux. Either opens a tunnel with
# CONNECT (RFC 9110, Section 9.3.6), and neither is ours.
#
# Usage:   ./forward-proxy.sh <squid|tinyproxy> <port> <directory> <allowed-port>
#                             [basic <user> <password>] [tls <certificate.pem> <key.pem>]
#
#   <port>          where the proxy listens, on 127.0.0.1
#   <directory>     where its configuration, pid file and password file go - the caller's to remove
#   <allowed-port>  the one port it opens a tunnel to; a CONNECT to any other is refused with 403,
#                   as a corporate proxy refuses all but 443
#   basic           ask for HTTP Basic in Proxy-Authorization, and take only this user and password
#   tls             speak TLS to the client (Squid only): an "https" proxy
#
# Both log to stdout, one line per request (Squid's access log, tinyproxy's CONNECT log level), so
# that a test reads what the proxy was asked for from the output it already collects. Squid writes
# its access log line once a tunnel has ended, tinyproxy as the CONNECT comes in.

set -euo pipefail

if (( $# < 4 )); then
    sed -n '3,21p' "$0" >&2
    exit 64
fi

kind=$1 port=$2 directory=$3 allowed=$4
shift 4

user="" password="" certificate="" key=""

while (( $# )); do
    case $1 in
        basic) user=$2 password=$3; shift 3 ;;
        tls)   certificate=$2 key=$3; shift 3 ;;
        *)     echo "forward-proxy.sh: unknown option '$1'" >&2; exit 64 ;;
    esac
done

mkdir -p "${directory}"

# Squid started as root - as in the CI container - runs as the user "proxy" once it has read its
# configuration, and so do its helpers: basic_ncsa_auth reads the password file then, and could not
# under a home directory of mode 700. The caller puts the directory under /tmp; here it is made
# readable, and the certificate and key are copied into it. Test keys, made for one run.
if [[ -n ${certificate} ]]; then
    cp "${certificate}" "${directory}/proxy-certificate.pem"
    cp "${key}"         "${directory}/proxy-key.pem"
    certificate=${directory}/proxy-certificate.pem
    key=${directory}/proxy-key.pem
fi

case ${kind} in

    squid)

        configuration=${directory}/squid.conf

        {
            if (( EUID == 0 )); then
                echo "cache_effective_user proxy"
            fi

            if [[ -n ${certificate} ]]; then
                echo "https_port 127.0.0.1:${port} tls-cert=${certificate} tls-key=${key}"
            else
                echo "http_port 127.0.0.1:${port}"
            fi

            echo "pid_filename ${directory}/squid.pid"
            echo "coredump_dir ${directory}"
            echo "cache_log ${directory}/cache.log"
            echo "access_log stdio:${directory}/access.log squid"
            echo "logfile_rotate 0"
            echo "cache deny all"
            echo "cache_mem 8 MB"
            echo "shutdown_lifetime 0 seconds"

            echo "acl CONNECT method CONNECT"
            echo "acl allowed_ports port ${allowed}"
            echo "http_access deny !CONNECT"
            echo "http_access deny CONNECT !allowed_ports"

            if [[ -n ${user} ]]; then
                # basic_ncsa_auth reads htpasswd's format, and an Apache MD5 hash is one it takes.
                # Squid lowercases user names unless told not to, and "CP001" would then be "cp001".
                printf '%s:%s\n' "${user}" "$(openssl passwd -apr1 "${password}")" > "${directory}/passwd"
                echo "auth_param basic program /usr/lib/squid/basic_ncsa_auth ${directory}/passwd"
                echo "auth_param basic realm hermod-interop"
                echo "auth_param basic casesensitive on"
                echo "acl authenticated proxy_auth REQUIRED"
                echo "http_access allow authenticated"
            else
                echo "http_access allow CONNECT"
            fi

            echo "http_access deny all"
        } > "${configuration}"

        # Its logs go to files and from there to stdout and stderr: Squid run as "proxy" may not open
        # /dev/stdout, a pipe that belongs to root. The two tails are in the proxy's process group,
        # and end with it.
        touch "${directory}/access.log" "${directory}/cache.log"

        if (( EUID == 0 )); then
            chmod -R a+rX "${directory}"
            chown -R proxy "${directory}"
        fi

        tail -n +1 -F "${directory}/access.log" 2>/dev/null &
        tail -n +1 -F "${directory}/cache.log" >&2 2>/dev/null &

        # -N: in the foreground, no daemon; -n: a service name of its own, so that two at once do not
        # meet in their shared memory segments. Squid removes those as it shuts down, and a proxy
        # killed at the end of a test does not: whatever one on this port left is removed first, as
        # Squid refuses to start beside it ("shm_open ... File exists").
        rm -f /dev/shm/hermod"${port}"-* 2>/dev/null || true

        exec squid -N -n "hermod${port}" -f "${configuration}"
        ;;

    tinyproxy)

        if [[ -n ${certificate} ]]; then
            echo "forward-proxy.sh: tinyproxy speaks no TLS to its clients" >&2
            exit 64
        fi

        configuration=${directory}/tinyproxy.conf

        {
            echo "Port ${port}"
            echo "Listen 127.0.0.1"
            echo "Timeout 600"
            echo "PidFile \"${directory}/tinyproxy.pid\""
            echo "LogLevel Connect"
            echo "MaxClients 50"
            echo "Allow 127.0.0.1"
            echo "ConnectPort ${allowed}"
            echo "DisableViaHeader Yes"

            if [[ -n ${user} ]]; then
                echo "BasicAuth ${user} ${password}"
            fi
        } > "${configuration}"

        # -d: in the foreground, and without a LogFile it logs to stdout.
        exec tinyproxy -d -c "${configuration}"
        ;;

    *)
        echo "forward-proxy.sh: '${kind}' is neither squid nor tinyproxy" >&2
        exit 64
        ;;

esac
