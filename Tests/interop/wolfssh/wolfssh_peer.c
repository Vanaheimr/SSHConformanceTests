/*
 * wolfssh-peer - drive HermodSSH from wolfSSH and serve it with wolfSSH, for the NUnit interop suite.
 *
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 * Licensed under the Apache License, Version 2.0.
 *
 * wolfSSH is the embedded C lineage beside Dropbear: wolfSSL's SSH library for devices and RTOSes,
 * built on wolfCrypt rather than OpenSSL and sharing no code with OpenSSH, libssh or Dropbear. It
 * ships example programs rather than tools, so this program is both a client and a server, linked
 * against the release build-wolfssh.sh pins.
 *
 *   wolfssh-peer client <config.json>
 *
 *     The contract of WslInterop.RunPeerAsync: exactly one JSON object is printed to stdout. A failed
 *     SSH operation is {"ok": false, ...} with exit code 0; a non-zero exit means the harness broke.
 *
 *     action           "connect" | "exec" | "sftp"
 *     host, port, username, key_path (the public key is read from key_path + ".pub")
 *     host_key_b64     the only host key accepted (the base64 key blob)
 *     command          for "exec"
 *     kex_algs, ciphers, macs, host_key_algs
 *                      restrict what wolfSSH offers; a list wolfSSH will not take is reported as
 *                      error_type "Unsupported", which is a statement about wolfSSH, not about us
 *     upload_path, download_path, remote_dir
 *                      for "sftp": the local file to upload, where to download it back to, and the
 *                      remote directory to work in (created)
 *
 *     wolfSSH names what it negotiated only in prose ("ECDH"), so "algorithms" here is a diagnostic;
 *     the tests take the names from our own server's audit instead.
 *
 *   wolfssh-peer server <port> <host-key-file> <authorized-public-key-file>
 *
 *     A wolfSSH server on 127.0.0.1:<port>, one forked child per connection. It accepts exactly the
 *     given public key, answers "exec" with "wolfssh ran: <command>\n" and exit status 0 (42 for the
 *     command "fail"), and serves the "sftp" subsystem with wolfSSH's own SFTP server - the real file
 *     system, as the account running it sees it.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <jansson.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssh/ssh.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/log.h>
#include <wolfssh/version.h>

#define CHUNK 32768


/* ------------------------------------------------------------------------------------------------
 * shared helpers
 * ---------------------------------------------------------------------------------------------- */

static json_t *result;
static json_t *debug_log;

/* A growing string for what a command printed and for the SFTP report. */
typedef struct { char *data; size_t length; size_t capacity; } text;

static void text_append(text *t, const char *data, size_t length)
{
    if (t->length + length + 1 > t->capacity) {
        t->capacity = (t->length + length + 1) * 2;
        t->data     = realloc(t->data, t->capacity);
        if (t->data == NULL) { perror("realloc"); exit(2); }
    }
    memcpy(t->data + t->length, data, length);
    t->length += length;
    t->data[t->length] = '\0';
}

static void text_printf(text *t, const char *format, long long value)
{
    char line[256];
    int  n = snprintf(line, sizeof line, format, value);
    text_append(t, line, (size_t) n);
}

static void set_stage(const char *stage)
{
    json_object_set_new(result, "stage", json_string(stage));
}

static int fail(const char *type, const char *message)
{
    json_object_set_new(result, "ok",         json_false());
    json_object_set_new(result, "error_type", json_string(type));
    json_object_set_new(result, "error",      json_string(message != NULL ? message : "(no message)"));
    return -1;
}

static int fail_ssh(const char *type, const char *what, WOLFSSH *ssh)
{
    char message[512];
    int  error = ssh != NULL ? wolfSSH_get_error(ssh) : 0;
    snprintf(message, sizeof message, "%s: %s (%d)", what, wolfSSH_ErrorToName(error), error);
    return fail(type, message);
}

static void log_callback(enum wolfSSH_LogLevel level, const char *const message)
{
    (void) level;
    if (debug_log != NULL && json_array_size(debug_log) < 400)
        json_array_append_new(debug_log, json_string(message));
}

static const char *string_of(json_t *config, const char *key)
{
    return json_string_value(json_object_get(config, key));
}

/* A JSON array of strings joined with commas, as wolfSSH's algorithm lists take them; NULL if absent. */
static char *joined(json_t *config, const char *key)
{
    json_t *list = json_object_get(config, key);
    if (!json_is_array(list) || json_array_size(list) == 0)
        return NULL;

    text    t = { 0 };
    size_t  i;
    json_t *item;
    json_array_foreach(list, i, item) {
        if (i > 0) text_append(&t, ",", 1);
        text_append(&t, json_string_value(item), strlen(json_string_value(item)));
    }
    return t.data;
}

static void base64(const uint8_t *in, size_t length, char *out, size_t capacity)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0;
    for (size_t i = 0; i < length && o + 5 < capacity; i += 3) {
        uint32_t v = (uint32_t) in[i] << 16;
        if (i + 1 < length) v |= (uint32_t) in[i + 1] << 8;
        if (i + 2 < length) v |= in[i + 2];
        out[o++] = alphabet[(v >> 18) & 63];
        out[o++] = alphabet[(v >> 12) & 63];
        out[o++] = i + 1 < length ? alphabet[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < length ? alphabet[v & 63]        : '=';
    }
    out[o] = '\0';
}

/* The first string of an SSH key blob: its type. */
static void key_type_of(const uint8_t *blob, size_t length, char *out, size_t capacity)
{
    out[0] = '\0';
    if (length < 4)
        return;
    uint32_t n = ((uint32_t) blob[0] << 24) | ((uint32_t) blob[1] << 16) | ((uint32_t) blob[2] << 8) | blob[3];
    if (n + 4 > length || n + 1 > capacity)
        return;
    memcpy(out, blob + 4, n);
    out[n] = '\0';
}


/* ------------------------------------------------------------------------------------------------
 * client
 * ---------------------------------------------------------------------------------------------- */

static const char *pinned_b64;
static char        presented_b64[4096];
static char        presented_type[64];
static bool        host_key_refused;
static bool        keys_taken;
static bool        authenticating;

static byte       *user_private;
static word32      user_private_size;
static const byte *user_private_type;
static word32      user_private_type_size;
static byte       *user_public;
static word32      user_public_size;
static const byte *user_public_type;
static word32      user_public_type_size;

/* The pin is the whole check: 0 accepts, anything else ends the key exchange. */
static int on_host_key(const byte *key, word32 size, void *context)
{
    (void) context;
    base64(key, size, presented_b64, sizeof presented_b64);
    key_type_of(key, size, presented_type, sizeof presented_type);

    if (pinned_b64 == NULL || strcmp(presented_b64, pinned_b64) != 0) {
        host_key_refused = true;
        return -1;
    }
    return 0;
}

static void on_keyed(void *context)
{
    (void) context;
    keys_taken = true;
}

static int on_user_auth(byte type, WS_UserAuthData *data, void *context)
{
    (void) context;
    authenticating = true;

    if (type != WOLFSSH_USERAUTH_PUBLICKEY || user_public == NULL)
        return WOLFSSH_USERAUTH_FAILURE;

    WS_UserAuthData_PublicKey *key = &data->sf.publicKey;
    key->publicKeyType   = user_public_type;
    key->publicKeyTypeSz = user_public_type_size;
    key->publicKey       = user_public;
    key->publicKeySz     = user_public_size;
    key->privateKey      = user_private;
    key->privateKeySz    = user_private_size;
    return WOLFSSH_USERAUTH_SUCCESS;
}

static int restrict_list(WOLFSSH_CTX *ctx, json_t *config, const char *key, int (*set)(WOLFSSH_CTX *, const char *))
{
    char *list = joined(config, key);
    if (list == NULL)
        return 0;

    int rc = set(ctx, list);
    if (rc != WS_SUCCESS) {
        char message[512];
        snprintf(message, sizeof message, "wolfSSH %s does not support %s='%s' (%s)", LIBWOLFSSH_VERSION_STRING, key, list, wolfSSH_ErrorToName(rc));
        free(list);
        return fail("Unsupported", message);
    }

    /* The list is not copied: it stays allocated for the whole run. */
    return 0;
}

static int dial(const char *host, int port)
{
    char            service[16];
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *found = NULL;

    snprintf(service, sizeof service, "%d", port);
    if (getaddrinfo(host, service, &hints, &found) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *a = found; a != NULL && fd < 0; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd >= 0 && connect(fd, a->ai_addr, a->ai_addrlen) != 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(found);
    return fd;
}

/* Turns the crank until the peer has closed the channel, so exit-status and close are processed. */
static void drain(WOLFSSH *ssh)
{
    int rc = wolfSSH_shutdown(ssh);
    if (rc == WS_SOCKET_ERROR_E || wolfSSH_get_error(ssh) == WS_SOCKET_ERROR_E || wolfSSH_get_error(ssh) == WS_CHANNEL_CLOSED)
        return;
    for (int i = 0; i < 50; i++) {
        rc = wolfSSH_worker(ssh, NULL);
        if (rc == WS_CHANNEL_CLOSED || rc == WS_SOCKET_ERROR_E || rc == WS_EOF || rc == WS_FATAL_ERROR)
            return;
        int error = wolfSSH_get_error(ssh);
        if (error == WS_CHANNEL_CLOSED || error == WS_SOCKET_ERROR_E || error == WS_EOF)
            return;
    }
}

static int run_exec(WOLFSSH *ssh)
{
    set_stage("exec");

    text out = { 0 }, err = { 0 };
    byte buffer[4096];

    text_append(&out, "", 0);
    text_append(&err, "", 0);

    for (int spins = 0; spins < 100000; spins++) {
        int n = wolfSSH_stream_read(ssh, buffer, sizeof buffer);
        if (n > 0) {
            text_append(&out, (const char *) buffer, (size_t) n);
            continue;
        }

        int error = wolfSSH_get_error(ssh);
        if (n == WS_EXTDATA || error == WS_EXTDATA) {
            n = wolfSSH_extended_data_read(ssh, buffer, sizeof buffer);
            if (n > 0)
                text_append(&err, (const char *) buffer, (size_t) n);
            continue;
        }
        if (n == WS_EOF || error == WS_EOF || n == WS_CHANNEL_CLOSED || error == WS_CHANNEL_CLOSED || n == 0)
            break;
        if (error == WS_WANT_READ || error == WS_WANT_WRITE || error == WS_CHAN_RXD || error == WS_REKEYING)
            continue;

        free(out.data);
        free(err.data);
        return fail_ssh("ChannelError", "reading the command's output", ssh);
    }

    drain(ssh);

    json_object_set_new(result, "stdout",      json_string(out.data));
    json_object_set_new(result, "stderr",      json_string(err.data));
    json_object_set_new(result, "exit_status", json_integer(wolfSSH_GetExitStatus(ssh)));

    free(out.data);
    free(err.data);
    return 0;
}

/* wolfSSH's SFTP calls may ask to be called again; on a blocking socket that is rare but legal. */
#define SFTP_RETRY(call)                                                                              \
    ({ int rc_ = (call), tries_ = 0;                                                                \
       while (rc_ != WS_SUCCESS && tries_++ < 1000) {                                                  \
           int e_ = wolfSSH_get_error(ssh);                                                           \
           if (e_ != WS_WANT_READ && e_ != WS_WANT_WRITE && e_ != WS_REKEYING) break;                  \
           rc_ = (call);                                                                              \
       }                                                                                              \
       rc_; })

static int sftp_put(WOLFSSH *ssh, const char *local_path, const char *remote_path)
{
    FILE *local = fopen(local_path, "rb");
    if (local == NULL)
        return fail("HarnessError", strerror(errno));

    WS_SFTP_FILEATRB attributes;
    byte             handle[WOLFSSH_MAX_HANDLE];
    word32           handle_size = sizeof handle;

    memset(&attributes, 0, sizeof attributes);
    if (SFTP_RETRY(wolfSSH_SFTP_Open(ssh, (char *) remote_path, WOLFSSH_FXF_WRITE | WOLFSSH_FXF_CREAT | WOLFSSH_FXF_TRUNC,
                                     &attributes, handle, &handle_size)) != WS_SUCCESS) {
        fclose(local);
        return fail_ssh("SftpError", "open for writing", ssh);
    }

    byte     buffer[CHUNK];
    uint64_t offset = 0;
    size_t   n;
    while ((n = fread(buffer, 1, sizeof buffer, local)) > 0) {
        size_t done = 0;
        while (done < n) {
            word32 at[2] = { (word32) ((offset + done) & 0xFFFFFFFFu), (word32) ((offset + done) >> 32) };
            int    sent  = wolfSSH_SFTP_SendWritePacket(ssh, handle, handle_size, at, buffer + done, (word32) (n - done));
            if (sent <= 0) {
                int error = wolfSSH_get_error(ssh);
                if (error == WS_WANT_READ || error == WS_WANT_WRITE || error == WS_REKEYING)
                    continue;
                fclose(local);
                return fail_ssh("SftpError", "write", ssh);
            }
            done += (size_t) sent;
        }
        offset += n;
    }
    fclose(local);

    /* The close is checked: it is where a server may still refuse what it was sent. */
    if (SFTP_RETRY(wolfSSH_SFTP_Close(ssh, handle, handle_size)) != WS_SUCCESS)
        return fail_ssh("SftpError", "close after writing", ssh);

    return 0;
}

static int run_sftp(WOLFSSH *ssh, json_t *config)
{
    const char      *dir      = string_of(config, "remote_dir");
    const char      *upload   = string_of(config, "upload_path");
    const char      *download = string_of(config, "download_path");
    char             uploaded[1024], data[1024], doomed[1024];
    text             report   = { 0 };
    WS_SFTP_FILEATRB attributes;

    snprintf(uploaded, sizeof uploaded, "%s/upload.bin", dir);
    snprintf(data,     sizeof data,     "%s/data.bin",   dir);
    snprintf(doomed,   sizeof doomed,   "%s/doomed.bin", dir);
    text_append(&report, "", 0);

    set_stage("sftp-mkdir");
    memset(&attributes, 0, sizeof attributes);
    if (SFTP_RETRY(wolfSSH_SFTP_MKDIR(ssh, (char *) dir, &attributes)) != WS_SUCCESS)
        return fail_ssh("SftpError", "mkdir", ssh);

    set_stage("sftp-put");
    if (sftp_put(ssh, upload, uploaded) != 0)
        return -1;

    set_stage("sftp-rename");
    if (SFTP_RETRY(wolfSSH_SFTP_Rename(ssh, uploaded, data)) != WS_SUCCESS)
        return fail_ssh("SftpError", "rename", ssh);

    set_stage("sftp-stat");
    memset(&attributes, 0, sizeof attributes);
    if (SFTP_RETRY(wolfSSH_SFTP_STAT(ssh, data, &attributes)) != WS_SUCCESS)
        return fail_ssh("SftpError", "stat", ssh);
    text_printf(&report, "stat_size=%lld\n", (long long) (((uint64_t) attributes.sz[1] << 32) | attributes.sz[0]));

    /* wolfSSH has no SSH_FXP_SYMLINK or SSH_FXP_READLINK, in either role: the file is read back
     * directly, where the other peers read it through a link. */
    set_stage("sftp-get");
    if (SFTP_RETRY(wolfSSH_SFTP_Get(ssh, data, (char *) download, 0, NULL)) != WS_SUCCESS)
        return fail_ssh("SftpError", "get", ssh);

    /* A second, small file, uploaded only to be removed again. */
    set_stage("sftp-put");
    if (sftp_put(ssh, upload, doomed) != 0)
        return -1;

    set_stage("sftp-list");
    WS_SFTPNAME *names = NULL;
    for (int tries = 0; names == NULL && tries < 1000; tries++) {
        names = wolfSSH_SFTP_LS(ssh, (char *) dir);
        int error = wolfSSH_get_error(ssh);
        if (names == NULL && error != WS_WANT_READ && error != WS_WANT_WRITE && error != WS_REKEYING)
            break;
    }
    if (names == NULL)
        return fail_ssh("SftpError", "list", ssh);

    json_t *listing = json_array();
    for (WS_SFTPNAME *name = names; name != NULL; name = name->next)
        if (name->fName != NULL && strcmp(name->fName, ".") != 0 && strcmp(name->fName, "..") != 0)
            json_array_append_new(listing, json_string(name->fName));
    wolfSSH_SFTPNAME_list_free(names);
    json_object_set_new(result, "listing", listing);

    set_stage("sftp-remove");
    if (SFTP_RETRY(wolfSSH_SFTP_Remove(ssh, doomed)) != WS_SUCCESS)
        return fail_ssh("SftpError", "remove", ssh);

    json_object_set_new(result, "stdout", json_string(report.data));
    free(report.data);
    return 0;
}

static void record_algorithms(WOLFSSH *ssh)
{
    static const struct { const char *key; WS_Text id; } texts[] = {
        { "kex",        WOLFSSH_TEXT_KEX_ALGO          },
        { "kex_curve",  WOLFSSH_TEXT_KEX_CURVE         },
        { "kex_hash",   WOLFSSH_TEXT_KEX_HASH          },
        { "cipher_out", WOLFSSH_TEXT_CRYPTO_OUT_CIPHER },
        { "cipher_in",  WOLFSSH_TEXT_CRYPTO_IN_CIPHER  },
        { "mac_out",    WOLFSSH_TEXT_CRYPTO_OUT_MAC    },
        { "mac_in",     WOLFSSH_TEXT_CRYPTO_IN_MAC     },
    };

    json_t *algorithms = json_object();
    char    value[128];
    for (size_t i = 0; i < sizeof texts / sizeof texts[0]; i++) {
        value[0] = '\0';
        wolfSSH_GetText(ssh, texts[i].id, value, sizeof value);
        json_object_set_new(algorithms, texts[i].key, json_string(value));
    }
    json_object_set_new(algorithms, "host_key",   json_string(presented_type));
    json_object_set_new(algorithms, "strict_kex", json_string(wolfSSH_GetStrictKexNegotiated(ssh) ? "True" : "False"));
    json_object_set_new(result, "algorithms", algorithms);
}

static int run_client(json_t *config)
{
    const char *action   = string_of(config, "action");
    const char *key_path = string_of(config, "key_path");
    int         port     = (int) json_integer_value(json_object_get(config, "port"));
    char        public_path[1024];
    byte        is_private = 0;

    set_stage("configuring");
    pinned_b64 = string_of(config, "host_key_b64");

    /* No conversion: wolfSSH reads the openssh-key-v1 file our generator wrote, and its .pub. */
    if (wolfSSH_ReadKey_file(key_path, &user_private, &user_private_size, &user_private_type, &user_private_type_size, &is_private, NULL) != WS_SUCCESS)
        return fail("KeyImportError", "wolfSSH could not read the private key file");

    snprintf(public_path, sizeof public_path, "%s.pub", key_path);
    if (wolfSSH_ReadKey_file(public_path, &user_public, &user_public_size, &user_public_type, &user_public_type_size, &is_private, NULL) != WS_SUCCESS)
        return fail("KeyImportError", "wolfSSH could not read the public key file");

    WOLFSSH_CTX *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
    if (ctx == NULL)
        return fail("HarnessError", "wolfSSH_CTX_new failed");

    wolfSSH_CTX_SetPublicKeyCheck(ctx, on_host_key);
    wolfSSH_SetUserAuth(ctx, on_user_auth);
    wolfSSH_SetKeyingCompletionCb(ctx, on_keyed);

    if (restrict_list(ctx, config, "kex_algs",      wolfSSH_CTX_SetAlgoListKex)    != 0 ||
        restrict_list(ctx, config, "ciphers",       wolfSSH_CTX_SetAlgoListCipher) != 0 ||
        restrict_list(ctx, config, "macs",          wolfSSH_CTX_SetAlgoListMac)    != 0 ||
        restrict_list(ctx, config, "host_key_algs", wolfSSH_CTX_SetAlgoListKey)    != 0)
        return -1;

    set_stage("connecting");
    int fd = dial(string_of(config, "host"), port);
    if (fd < 0)
        return fail("ConnectError", strerror(errno));

    WOLFSSH *ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        return fail("HarnessError", "wolfSSH_new failed");

    wolfSSH_SetUsername(ssh, string_of(config, "username"));
    wolfSSH_set_fd(ssh, fd);

    int rc;
    if (strcmp(action, "sftp") == 0) {
        rc = wolfSSH_SFTP_connect(ssh);
    }
    else {
        /* "connect" runs a command as well: wolfSSH opens a session channel either way, and an exec
         * is the one request every server here answers. */
        const char *command = strcmp(action, "exec") == 0 ? string_of(config, "command") : "connect";
        wolfSSH_SetChannelType(ssh, WOLFSSH_SESSION_EXEC, (byte *) command, (word32) strlen(command));
        rc = wolfSSH_connect(ssh);
    }

    if (rc != WS_SUCCESS) {
        if (host_key_refused) {
            set_stage("host-key");
            return fail_ssh("HostKeyMismatch", "the server presented a host key other than the pinned one", ssh);
        }
        if (authenticating) {
            set_stage("authenticating");
            return fail_ssh("AuthenticationFailed", "authentication", ssh);
        }
        if (keys_taken) {
            set_stage("authenticating");
            return fail_ssh("ChannelError", "after the key exchange", ssh);
        }
        set_stage("connected");
        return fail_ssh("KexError", "key exchange", ssh);
    }

    set_stage("authenticated");
    record_algorithms(ssh);

    rc = 0;
    if (strcmp(action, "exec") == 0)
        rc = run_exec(ssh);
    else if (strcmp(action, "sftp") == 0)
        rc = run_sftp(ssh, config);
    else if (strcmp(action, "connect") == 0)
        drain(ssh);
    else
        rc = fail("HarnessError", "unknown action");

    if (rc == 0) {
        json_object_set_new(result, "ok", json_true());
        set_stage("done");
    }

    if (strcmp(action, "sftp") == 0)
        drain(ssh);

    wolfSSH_free(ssh);
    close(fd);
    wolfSSH_CTX_free(ctx);
    return 0;
}


/* ------------------------------------------------------------------------------------------------
 * server
 * ---------------------------------------------------------------------------------------------- */

static byte  *authorized;
static word32 authorized_size;

/* The library verifies the signature; whether the key is the one we accept is ours to say. */
static int on_server_auth(byte type, WS_UserAuthData *data, void *context)
{
    (void) context;
    if (type != WOLFSSH_USERAUTH_PUBLICKEY)
        return WOLFSSH_USERAUTH_FAILURE;

    WS_UserAuthData_PublicKey *key = &data->sf.publicKey;
    if (key->publicKeySz != authorized_size || memcmp(key->publicKey, authorized, authorized_size) != 0)
        return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;

    return WOLFSSH_USERAUTH_SUCCESS;
}

static void serve_sftp(WOLFSSH *ssh)
{
    /* At most five minutes of requests - the harness kills the process group long before that. */
    for (int i = 0; i < 1000000; i++) {
        int rc    = wolfSSH_SFTP_read(ssh);
        int error = wolfSSH_get_error(ssh);
        if (rc >= 0 || error == WS_WANT_READ || error == WS_WANT_WRITE || error == WS_CHAN_RXD ||
            error == WS_REKEYING || error == WS_WINDOW_FULL)
            continue;
        break;     /* WS_EOF, a closed channel or a dead socket: the session is over */
    }
}

static void serve_connection(WOLFSSH_CTX *ctx, int fd)
{
    WOLFSSH *ssh = wolfSSH_new(ctx);
    if (ssh == NULL)
        return;

    wolfSSH_set_fd(ssh, fd);

    int rc = wolfSSH_accept(ssh);

    if (rc == WS_SFTP_COMPLETE) {
        serve_sftp(ssh);
    }
    else if (rc == WS_SUCCESS && wolfSSH_GetSessionType(ssh) == WOLFSSH_SESSION_EXEC) {
        const char *command = wolfSSH_GetSessionCommand(ssh);
        char        output[4096];
        int         n = snprintf(output, sizeof output, "wolfssh ran: %s\n", command != NULL ? command : "");
        wolfSSH_stream_send(ssh, (byte *) output, (word32) n);
        wolfSSH_stream_exit(ssh, command != NULL && strcmp(command, "fail") == 0 ? 42 : 0);
    }
    else if (rc != WS_SUCCESS) {
        fprintf(stderr, "wolfssh-peer: accept failed: %s (%d)\n", wolfSSH_ErrorToName(wolfSSH_get_error(ssh)), wolfSSH_get_error(ssh));
    }

    drain(ssh);
    wolfSSH_free(ssh);
}

/* A cursor over SSH wire data: uint32 lengths, strings and mpints. */
typedef struct { const byte *data; word32 length; word32 at; } wire;

static int wire_u32(wire *w, word32 *value)
{
    if (w->length - w->at < 4)
        return -1;
    const byte *p = w->data + w->at;
    *value = ((word32) p[0] << 24) | ((word32) p[1] << 16) | ((word32) p[2] << 8) | p[3];
    w->at += 4;
    return 0;
}

/* A string or an mpint; an mpint's sign byte is dropped, as wolfCrypt's raw imports want it. */
static int wire_string(wire *w, const byte **value, word32 *size, bool mpint)
{
    word32 n;
    if (wire_u32(w, &n) != 0 || w->length - w->at < n)
        return -1;
    *value = w->data + w->at;
    *size  = n;
    w->at += n;
    while (mpint && *size > 1 && (*value)[0] == 0) {
        (*value)++;
        (*size)--;
    }
    return 0;
}

static bool wire_is(const byte *value, word32 size, const char *expected)
{
    return size == strlen(expected) && memcmp(value, expected, size) == 0;
}

/*
 * wolfSSH 1.6.0 takes an openssh-key-v1 host key only for its composite ML-DSA keys; for every
 * classical type its server wants DER or PEM. So the file our generator wrote is read by wolfSSH's
 * own reader (which checks the envelope and strips the armour), its private section is taken apart
 * here, and wolfCrypt writes the key out again as DER: PKCS#8 for Ed25519, SEC1 for ECDSA, PKCS#1
 * for RSA. Only an unencrypted file can be read this way, which is what the generator writes.
 */
static int host_key_der(const char *path, byte **der, word32 *der_size)
{
    byte       *binary = NULL;
    word32      binary_size = 0;
    const byte *type_name = NULL;
    word32      type_name_size = 0;
    byte        is_private = 0;

    if (wolfSSH_ReadKey_file(path, &binary, &binary_size, &type_name, &type_name_size, &is_private, NULL) != WS_SUCCESS)
        return -1;

    static const char magic[] = "openssh-key-v1";
    if (binary_size < sizeof magic || memcmp(binary, magic, sizeof magic) != 0)
        return -1;

    wire        w = { binary, binary_size, (word32) sizeof magic };
    const byte *cipher, *kdf, *kdf_options, *public_blob, *section;
    word32      cipher_size, kdf_size, kdf_options_size, count, public_size, section_size;

    if (wire_string(&w, &cipher, &cipher_size, false) != 0 || !wire_is(cipher, cipher_size, "none") ||
        wire_string(&w, &kdf, &kdf_size, false) != 0 ||
        wire_string(&w, &kdf_options, &kdf_options_size, false) != 0 ||
        wire_u32(&w, &count) != 0 || count != 1 ||
        wire_string(&w, &public_blob, &public_size, false) != 0 ||
        wire_string(&w, &section, &section_size, false) != 0)
        return -1;

    wire        s = { section, section_size, 0 };
    word32      check1, check2, key_type_size;
    const byte *key_type;

    if (wire_u32(&s, &check1) != 0 || wire_u32(&s, &check2) != 0 || check1 != check2 ||
        wire_string(&s, &key_type, &key_type_size, false) != 0)
        return -1;

    *der_size = 8192;
    *der      = malloc(*der_size);
    int written = -1;

    if (wire_is(key_type, key_type_size, "ssh-ed25519")) {
        const byte *pub, *priv;
        word32      pub_size, priv_size;
        ed25519_key key;
        if (wire_string(&s, &pub, &pub_size, false) == 0 && wire_string(&s, &priv, &priv_size, false) == 0 &&
            pub_size == ED25519_PUB_KEY_SIZE && priv_size == ED25519_PRV_KEY_SIZE &&
            wc_ed25519_init(&key) == 0) {
            if (wc_ed25519_import_private_key(priv, ED25519_KEY_SIZE, pub, pub_size, &key) == 0)
                written = wc_Ed25519KeyToDer(&key, *der, *der_size);
            wc_ed25519_free(&key);
        }
    }
    else if (key_type_size > 11 && memcmp(key_type, "ecdsa-sha2-", 11) == 0) {
        const byte *curve, *q, *d;
        word32      curve_size, q_size, d_size;
        ecc_key     key;
        int         curve_id = -1;
        if (wire_string(&s, &curve, &curve_size, false) == 0 && wire_string(&s, &q, &q_size, false) == 0 &&
            wire_string(&s, &d, &d_size, true) == 0) {
            if      (wire_is(curve, curve_size, "nistp256")) curve_id = ECC_SECP256R1;
            else if (wire_is(curve, curve_size, "nistp384")) curve_id = ECC_SECP384R1;
            else if (wire_is(curve, curve_size, "nistp521")) curve_id = ECC_SECP521R1;
        }
        if (curve_id >= 0 && wc_ecc_init(&key) == 0) {
            if (wc_ecc_import_private_key_ex(d, d_size, q, q_size, &key, curve_id) == 0)
                written = wc_EccKeyToDer(&key, *der, *der_size);
            wc_ecc_free(&key);
        }
    }
    else if (wire_is(key_type, key_type_size, "ssh-rsa")) {
        const byte *n, *e, *d, *iqmp, *p, *q;
        word32      n_size, e_size, d_size, iqmp_size, p_size, q_size;
        RsaKey      key;
        if (wire_string(&s, &n, &n_size, true) == 0 && wire_string(&s, &e, &e_size, true) == 0 &&
            wire_string(&s, &d, &d_size, true) == 0 && wire_string(&s, &iqmp, &iqmp_size, true) == 0 &&
            wire_string(&s, &p, &p_size, true) == 0 && wire_string(&s, &q, &q_size, true) == 0 &&
            wc_InitRsaKey(&key, NULL) == 0) {
            /* dP and dQ are not in the file; wolfCrypt derives them from d, p and q. */
            if (wc_RsaPrivateKeyDecodeRaw(n, n_size, e, e_size, d, d_size, iqmp, iqmp_size,
                                          p, p_size, q, q_size, NULL, 0, NULL, 0, &key) == 0)
                written = wc_RsaKeyToDer(&key, *der, *der_size);
            wc_FreeRsaKey(&key);
        }
    }

    if (written <= 0) {
        fprintf(stderr, "wolfssh-peer: cannot turn the %.*s key into DER (%d)\n", (int) key_type_size, key_type, written);
        return -1;
    }

    *der_size = (word32) written;
    return 0;
}

static int run_server(const char *port, const char *host_key, const char *authorized_key)
{
    const byte *type = NULL;
    word32      type_size = 0;
    byte        is_private = 0;

    if (wolfSSH_ReadKey_file(authorized_key, &authorized, &authorized_size, &type, &type_size, &is_private, NULL) != WS_SUCCESS) {
        fprintf(stderr, "wolfssh-peer: cannot read the authorized key '%s'\n", authorized_key);
        return 2;
    }

    WOLFSSH_CTX *ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    wolfSSH_SetUserAuth(ctx, on_server_auth);

    byte  *key;
    word32 key_size;
    if (host_key_der(host_key, &key, &key_size) != 0 ||
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, key, key_size, WOLFSSH_FORMAT_ASN1) != WS_SUCCESS) {
        fprintf(stderr, "wolfssh-peer: cannot use the host key '%s'\n", host_key);
        return 2;
    }

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    int yes      = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons((uint16_t) atoi(port)) };
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if (bind(listener, (struct sockaddr *) &address, sizeof address) != 0 || listen(listener, 16) != 0) {
        fprintf(stderr, "wolfssh-peer: cannot listen on port %s: %s\n", port, strerror(errno));
        return 2;
    }

    fprintf(stderr, "wolfssh-peer: wolfSSH %s listening on 127.0.0.1:%s\n", LIBWOLFSSH_VERSION_STRING, port);
    signal(SIGCHLD, SIG_IGN);    /* no zombies: nobody waits for the children */

    for (;;) {

        int fd = accept(listener, NULL, NULL);
        if (fd < 0)
            continue;

        pid_t child = fork();
        if (child == 0) {
            close(listener);
            serve_connection(ctx, fd);
            close(fd);
            _exit(0);
        }

        close(fd);

    }
}


/* ------------------------------------------------------------------------------------------------ */

static void stderr_log(enum wolfSSH_LogLevel level, const char *const message)
{
    (void) level;
    fprintf(stderr, "wolfssh: %s\n", message);
}

int main(int argc, char **argv)
{
    wolfSSH_Init();

    if (argc == 5 && strcmp(argv[1], "server") == 0) {
        /* WOLFSSH_PEER_TRACE=1 puts wolfSSH's own debug log into the server's output. */
        if (getenv("WOLFSSH_PEER_TRACE") != NULL) {
            wolfSSH_SetLoggingCb(stderr_log);
            wolfSSH_Debugging_ON();
        }
        return run_server(argv[2], argv[3], argv[4]);
    }

    if (argc != 3 || strcmp(argv[1], "client") != 0) {
        fprintf(stderr, "usage: %s client <config.json>\n       %s server <port> <host-key> <authorized-key>\n", argv[0], argv[0]);
        return 2;
    }

    json_error_t error;
    json_t      *config = json_load_file(argv[2], 0, &error);
    if (config == NULL) {
        fprintf(stderr, "wolfssh-peer: cannot read %s: %s\n", argv[2], error.text);
        return 2;
    }

    result    = json_object();
    debug_log = json_array();
    json_object_set_new(result, "ok",           json_false());
    json_object_set_new(result, "peer_version", json_string("wolfSSH " LIBWOLFSSH_VERSION_STRING));

    wolfSSH_SetLoggingCb(log_callback);
    wolfSSH_Debugging_ON();

    run_client(config);

    json_object_set_new(result, "debug_log", debug_log);
    json_dumpf(result, stdout, JSON_COMPACT);
    putchar('\n');
    return 0;
}
