/*
 * libssh-peer - drive HermodSSH from libssh and serve it with libssh, for the NUnit interop suite.
 *
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 * Licensed under the Apache License, Version 2.0.
 *
 * libssh is the third C lineage beside OpenSSH and Dropbear, and the one embedded in products rather
 * than run as a tool: KDE, GNOME's gvfs, Ansible's network modules, curl and countless devices link it.
 * It ships no command-line client or server of its own, so this program is both.
 *
 *   libssh-peer client <config.json>
 *
 *     The contract of WslInterop.RunPeerAsync: exactly one JSON object is printed to stdout. A failed
 *     SSH operation is {"ok": false, ...} with exit code 0; a non-zero exit means the harness broke.
 *
 *     action           "connect" | "exec" | "sftp"
 *     host, port, username, key_path
 *     host_key_b64     the only host key accepted (the base64 key blob)
 *     command          for "exec"
 *     kex_algs, ciphers, macs, host_key_algs
 *                      restrict what libssh offers; a list libssh will not take at all is reported
 *                      as error_type "Unsupported", which is a statement about libssh, not about us
 *     upload_path, download_path, remote_dir
 *                      for "sftp": the local file to upload, where to download it back to, and the
 *                      remote directory to work in (created)
 *
 *   libssh-peer server <port> <host-key-file> <authorized-public-key-file>
 *
 *     A libssh server on 127.0.0.1:<port>, one forked child per connection. It accepts exactly the
 *     given public key, answers "exec" with "libssh ran: <command>\n" and exit status 0 (42 for the
 *     command "fail"), and serves the "sftp" subsystem with libssh's own SFTP server - the real file
 *     system, as the account running it sees it.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <jansson.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/server.h>
#include <libssh/sftp.h>
#include <libssh/sftpserver.h>

#define CHUNK 32768


/* ------------------------------------------------------------------------------------------------
 * client
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

static void log_callback(int priority, const char *function, const char *buffer, void *userdata)
{
    (void) priority; (void) function; (void) userdata;
    json_array_append_new(debug_log, json_string(buffer));
}

/* A JSON array of strings joined with commas, as libssh's algorithm options take them; NULL if absent. */
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

static const char *string_of(json_t *config, const char *key)
{
    return json_string_value(json_object_get(config, key));
}

/* Restrict one algorithm list; libssh refuses a list in which it supports nothing. */
static int restrict_algorithms(ssh_session session, json_t *config, const char *key, enum ssh_options_e option1, int option2)
{
    char *list = joined(config, key);
    if (list == NULL)
        return 0;

    int rc = ssh_options_set(session, option1, list);
    if (rc == SSH_OK && option2 >= 0)
        rc = ssh_options_set(session, (enum ssh_options_e) option2, list);

    if (rc != SSH_OK) {
        char message[512];
        snprintf(message, sizeof message, "libssh %s does not support any of %s='%s'", ssh_version(0), key, list);
        free(list);
        return fail("Unsupported", message);
    }

    free(list);
    return 0;
}

static int run_exec(ssh_session session, json_t *config)
{
    set_stage("exec");

    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL || ssh_channel_open_session(channel) != SSH_OK)
        return fail("ChannelError", ssh_get_error(session));

    if (ssh_channel_request_exec(channel, string_of(config, "command")) != SSH_OK) {
        ssh_channel_free(channel);
        return fail("ChannelError", ssh_get_error(session));
    }

    text out = { 0 }, err = { 0 };
    char buffer[4096];
    int  n;

    text_append(&out, "", 0);
    text_append(&err, "", 0);

    while ((n = ssh_channel_read(channel, buffer, sizeof buffer, 0)) > 0)
        text_append(&out, buffer, (size_t) n);
    if (n < 0) {
        ssh_channel_free(channel);
        return fail("ChannelError", ssh_get_error(session));
    }

    while ((n = ssh_channel_read(channel, buffer, sizeof buffer, 1)) > 0)
        text_append(&err, buffer, (size_t) n);

    uint32_t code     = 0;
    char    *signal   = NULL;
    int      core     = 0;
    int      exitRc   = ssh_channel_get_exit_state(channel, &code, &signal, &core);

    json_object_set_new(result, "stdout", json_string(out.data));
    json_object_set_new(result, "stderr", json_string(err.data));
    if (exitRc == SSH_OK && signal == NULL)
        json_object_set_new(result, "exit_status", json_integer(code));

    free(out.data);
    free(err.data);
    ssh_string_free_char(signal);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return 0;
}

static int sftp_fail(sftp_session sftp, const char *what)
{
    char message[512];
    snprintf(message, sizeof message, "%s: SFTP error %d, %s", what, sftp_get_error(sftp), ssh_get_error(sftp->session));
    return fail("SftpError", message);
}

static int run_sftp(ssh_session session, json_t *config)
{
    const char *dir      = string_of(config, "remote_dir");
    const char *upload   = string_of(config, "upload_path");
    const char *download = string_of(config, "download_path");
    char        uploaded[1024], data[1024], link[1024];
    text        report   = { 0 };
    char        buffer[CHUNK];
    ssize_t     n;

    snprintf(uploaded, sizeof uploaded, "%s/upload.bin", dir);
    snprintf(data,     sizeof data,     "%s/data.bin",   dir);
    snprintf(link,     sizeof link,     "%s/link.bin",   dir);
    text_append(&report, "", 0);

    set_stage("sftp-open");
    sftp_session sftp = sftp_new(session);
    if (sftp == NULL || sftp_init(sftp) != SSH_OK)
        return fail("SftpError", ssh_get_error(session));

    text_printf(&report, "sftp_version=%lld\n", sftp_server_version(sftp));

    set_stage("sftp-mkdir");
    if (sftp_mkdir(sftp, dir, 0755) != SSH_OK)
        return sftp_fail(sftp, "mkdir");

    /* Upload. The close is checked: it is where a server may still refuse what it was sent. */
    set_stage("sftp-put");
    int local = open(upload, O_RDONLY);
    if (local < 0)
        return fail("HarnessError", strerror(errno));

    sftp_file file = sftp_open(sftp, uploaded, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (file == NULL)
        return sftp_fail(sftp, "open for writing");

    while ((n = read(local, buffer, sizeof buffer)) > 0)
        if (sftp_write(file, buffer, (size_t) n) != n)
            return sftp_fail(sftp, "write");
    close(local);

    if (sftp_close(file) != SSH_OK)
        return sftp_fail(sftp, "close after writing");

    set_stage("sftp-rename");
    if (sftp_rename(sftp, uploaded, data) != SSH_OK)
        return sftp_fail(sftp, "rename");

    set_stage("sftp-stat");
    sftp_attributes attributes = sftp_stat(sftp, data);
    if (attributes == NULL)
        return sftp_fail(sftp, "stat");
    text_printf(&report, "stat_size=%lld\n", (long long) attributes->size);
    sftp_attributes_free(attributes);

    /* libssh sends SSH_FXP_SYMLINK in the draft's order (link path, then target) to every server
     * that does not call itself OpenSSH - the order OpenSSH itself reverses. */
    set_stage("sftp-symlink");
    if (sftp_symlink(sftp, "data.bin", link) != SSH_OK)
        return sftp_fail(sftp, "symlink");

    char *target = sftp_readlink(sftp, link);
    if (target == NULL)
        return sftp_fail(sftp, "readlink");
    text_append(&report, "readlink=", 9);
    text_append(&report, target, strlen(target));
    text_append(&report, "\n", 1);
    ssh_string_free_char(target);

    attributes = sftp_lstat(sftp, link);
    if (attributes == NULL)
        return sftp_fail(sftp, "lstat");
    text_printf(&report, "lstat_symlink=%lld\n", attributes->type == SSH_FILEXFER_TYPE_SYMLINK);
    sftp_attributes_free(attributes);

    set_stage("sftp-get");
    file = sftp_open(sftp, link, O_RDONLY, 0);
    if (file == NULL)
        return sftp_fail(sftp, "open for reading");

    local = open(download, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (local < 0)
        return fail("HarnessError", strerror(errno));

    while ((n = sftp_read(file, buffer, sizeof buffer)) > 0)
        if (write(local, buffer, (size_t) n) != n)
            return fail("HarnessError", strerror(errno));
    close(local);

    if (n < 0)
        return sftp_fail(sftp, "read");
    if (sftp_close(file) != SSH_OK)
        return sftp_fail(sftp, "close after reading");

    set_stage("sftp-list");
    sftp_dir directory = sftp_opendir(sftp, dir);
    if (directory == NULL)
        return sftp_fail(sftp, "opendir");

    json_t *listing = json_array();
    while ((attributes = sftp_readdir(sftp, directory)) != NULL) {
        if (strcmp(attributes->name, ".") != 0 && strcmp(attributes->name, "..") != 0)
            json_array_append_new(listing, json_string(attributes->name));
        sftp_attributes_free(attributes);
    }
    if (!sftp_dir_eof(directory))
        return sftp_fail(sftp, "readdir");
    sftp_closedir(directory);
    json_object_set_new(result, "listing", listing);

    set_stage("sftp-remove");
    if (sftp_unlink(sftp, link) != SSH_OK)
        return sftp_fail(sftp, "remove the link");

    json_object_set_new(result, "stdout", json_string(report.data));
    free(report.data);
    sftp_free(sftp);
    return 0;
}

static int run_client(json_t *config)
{
    const char *action = string_of(config, "action");
    int         port   = (int) json_integer_value(json_object_get(config, "port"));
    long        wait   = 30;
    int         level  = SSH_LOG_PROTOCOL;
    bool        no     = false;

    set_stage("configuring");

    ssh_set_log_callback(log_callback);

    ssh_session session = ssh_new();
    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY,  &level);
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &no);           /* no ~/.ssh/config, no /etc/ssh */
    ssh_options_set(session, SSH_OPTIONS_HOST,           string_of(config, "host"));
    ssh_options_set(session, SSH_OPTIONS_PORT,           &port);
    ssh_options_set(session, SSH_OPTIONS_USER,           string_of(config, "username"));
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT,        &wait);
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS,     "/dev/null");   /* the pin below is the whole check */

    if (restrict_algorithms(session, config, "kex_algs",      SSH_OPTIONS_KEY_EXCHANGE, -1)                    != 0 ||
        restrict_algorithms(session, config, "ciphers",       SSH_OPTIONS_CIPHERS_C_S,  SSH_OPTIONS_CIPHERS_S_C) != 0 ||
        restrict_algorithms(session, config, "macs",          SSH_OPTIONS_HMAC_C_S,     SSH_OPTIONS_HMAC_S_C)    != 0 ||
        restrict_algorithms(session, config, "host_key_algs", SSH_OPTIONS_HOSTKEYS,     -1)                    != 0)
        return 0;

    set_stage("connecting");
    if (ssh_connect(session) != SSH_OK)
        return fail("ConnectError", ssh_get_error(session)), 0;

    set_stage("connected");
    json_object_set_new(result, "server_version", json_string(ssh_get_serverbanner(session)));

    json_t *algorithms = json_object();
    json_object_set_new(algorithms, "kex",        json_string(ssh_get_kex_algo(session)));
    json_object_set_new(algorithms, "cipher_out", json_string(ssh_get_cipher_out(session)));
    json_object_set_new(algorithms, "cipher_in",  json_string(ssh_get_cipher_in(session)));
    json_object_set_new(algorithms, "mac_out",    json_string(ssh_get_hmac_out(session)));
    json_object_set_new(algorithms, "mac_in",     json_string(ssh_get_hmac_in(session)));
    json_object_set_new(result, "algorithms", algorithms);

    set_stage("host-key");
    ssh_key server_key = NULL;
    char   *server_b64 = NULL;
    if (ssh_get_server_publickey(session, &server_key) != SSH_OK ||
        ssh_pki_export_pubkey_base64(server_key, &server_b64) != SSH_OK)
        return fail("HostKeyError", ssh_get_error(session)), 0;

    json_object_set_new(algorithms, "host_key", json_string(ssh_key_type_to_char(ssh_key_type(server_key))));

    if (strcmp(server_b64, string_of(config, "host_key_b64")) != 0) {
        ssh_disconnect(session);
        return fail("HostKeyMismatch", "the server presented a host key other than the pinned one"), 0;
    }
    ssh_string_free_char(server_b64);
    ssh_key_free(server_key);

    /* No conversion: libssh reads the openssh-key-v1 file our generator wrote. */
    set_stage("authenticating");
    ssh_key key = NULL;
    if (ssh_pki_import_privkey_file(string_of(config, "key_path"), NULL, NULL, NULL, &key) != SSH_OK)
        return fail("KeyImportError", "libssh could not read the private key file"), 0;

    if (ssh_userauth_publickey(session, NULL, key) != SSH_AUTH_SUCCESS)
        return fail("AuthenticationFailed", ssh_get_error(session)), 0;
    ssh_key_free(key);

    set_stage("authenticated");

    int rc = 0;
    if (strcmp(action, "exec") == 0)
        rc = run_exec(session, config);
    else if (strcmp(action, "sftp") == 0)
        rc = run_sftp(session, config);
    else if (strcmp(action, "connect") != 0)
        return fail("HarnessError", "unknown action"), 0;

    if (rc == 0) {
        json_object_set_new(result, "ok", json_true());
        set_stage("done");
    }

    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}


/* ------------------------------------------------------------------------------------------------
 * server
 * ---------------------------------------------------------------------------------------------- */

struct connection {
    sftp_session  sftp;            /* what libssh's default SFTP callbacks keep their session in */
    ssh_key       authorized;
    ssh_channel   channel;
    char         *command;
    bool          exec_pending;
    bool          eof_received;
};

static struct ssh_channel_callbacks_struct channel_callbacks;

static int on_auth_publickey(ssh_session session, const char *user, struct ssh_key_struct *key, char signature_state, void *userdata)
{
    struct connection *c = userdata;
    (void) session; (void) user;

    if (ssh_key_cmp(key, c->authorized, SSH_KEY_CMP_PUBLIC) != 0)
        return SSH_AUTH_DENIED;

    /* NONE is the query "would you take this key?"; VALID is a verified signature with it. */
    return signature_state == SSH_PUBLICKEY_STATE_NONE || signature_state == SSH_PUBLICKEY_STATE_VALID
               ? SSH_AUTH_SUCCESS
               : SSH_AUTH_DENIED;
}

static ssh_channel on_channel_open(ssh_session session, void *userdata)
{
    struct connection *c = userdata;
    if (c->channel != NULL)
        return NULL;

    c->channel = ssh_channel_new(session);
    ssh_set_channel_callbacks(c->channel, &channel_callbacks);
    return c->channel;
}

static int on_exec(ssh_session session, ssh_channel channel, const char *command, void *userdata)
{
    struct connection *c = userdata;
    (void) session; (void) channel;
    c->command      = strdup(command);
    c->exec_pending = true;
    return SSH_OK;
}

static int on_subsystem(ssh_session session, ssh_channel channel, const char *subsystem, void *userdata)
{
    struct connection *c = userdata;
    return sftp_channel_default_subsystem_request(session, channel, subsystem, &c->sftp);
}

static int on_data(ssh_session session, ssh_channel channel, void *data, uint32_t length, int is_stderr, void *userdata)
{
    struct connection *c = userdata;
    if (c->sftp == NULL)
        return (int) length;     /* an exec session's stdin: nothing to do with it */
    return sftp_channel_default_data_callback(session, channel, data, length, is_stderr, &c->sftp);
}

static void on_eof(ssh_session session, ssh_channel channel, void *userdata)
{
    struct connection *c = userdata;
    (void) session; (void) channel;
    c->eof_received = true;
}

static void serve_connection(ssh_session session, ssh_key authorized)
{
    struct connection c = { .authorized = authorized };

    struct ssh_server_callbacks_struct server_callbacks = {
        .userdata                              = &c,
        .auth_pubkey_function                  = on_auth_publickey,
        .channel_open_request_session_function = on_channel_open,
    };
    ssh_callbacks_init(&server_callbacks);

    channel_callbacks = (struct ssh_channel_callbacks_struct) {
        .userdata                           = &c,
        .channel_exec_request_function      = on_exec,
        .channel_subsystem_request_function = on_subsystem,
        .channel_data_function              = on_data,
        .channel_eof_function               = on_eof,
    };
    ssh_callbacks_init(&channel_callbacks);

    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY);
    ssh_set_server_callbacks(session, &server_callbacks);

    if (ssh_handle_key_exchange(session) != SSH_OK) {
        fprintf(stderr, "libssh-peer: key exchange failed: %s\n", ssh_get_error(session));
        return;
    }

    ssh_event event = ssh_event_new();
    ssh_event_add_session(event, session);

    /* Polled in 100 ms steps for at most five minutes - the harness kills the whole process group
     * long before that, this only keeps a forgotten child from living forever. */
    for (int i = 0; i < 3000; i++) {

        if (ssh_event_dopoll(event, 100) == SSH_ERROR)
            break;

        if (c.exec_pending) {
            c.exec_pending = false;
            char output[4096];
            int  n = snprintf(output, sizeof output, "libssh ran: %s\n", c.command);
            ssh_channel_write(c.channel, output, (uint32_t) n);
            ssh_channel_request_send_exit_status(c.channel, strcmp(c.command, "fail") == 0 ? 42 : 0);
            ssh_channel_send_eof(c.channel);
            ssh_channel_close(c.channel);
        }

        /* The client's EOF ends an SFTP session, as it ends sshd's sftp-server: answer it with
         * ours and close the channel, or the client waits for the close forever. */
        if (c.eof_received && c.sftp != NULL && !ssh_channel_is_closed(c.channel)) {
            ssh_channel_send_eof(c.channel);
            ssh_channel_close(c.channel);
        }

        if ((ssh_get_status(session) & (SSH_CLOSED | SSH_CLOSED_ERROR)) != 0)
            break;

    }

    ssh_event_free(event);
}

static int run_server(const char *port, const char *host_key, const char *authorized_key)
{
    ssh_key authorized = NULL;
    if (ssh_pki_import_pubkey_file(authorized_key, &authorized) != SSH_OK) {
        fprintf(stderr, "libssh-peer: cannot read the authorized key '%s'\n", authorized_key);
        return 2;
    }

    bool     no   = false;
    ssh_bind bind = ssh_bind_new();
    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no);
    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR,       "127.0.0.1");
    ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT_STR,   port);

    /* LIBSSH_PEER_TRACE=4 puts libssh's own packet trace into the server's output. */
    const char *trace = getenv("LIBSSH_PEER_TRACE");
    if (trace != NULL) {
        int verbosity = atoi(trace);
        ssh_bind_options_set(bind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
    }

    /* No conversion here either: libssh reads the host key our generator wrote. */
    if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_HOSTKEY, host_key) != SSH_OK) {
        fprintf(stderr, "libssh-peer: cannot use the host key '%s': %s\n", host_key, ssh_get_error(bind));
        return 2;
    }

    if (ssh_bind_listen(bind) != SSH_OK) {
        fprintf(stderr, "libssh-peer: cannot listen on port %s: %s\n", port, ssh_get_error(bind));
        return 2;
    }

    fprintf(stderr, "libssh-peer: libssh %s listening on 127.0.0.1:%s\n", ssh_version(0), port);
    signal(SIGCHLD, SIG_IGN);    /* no zombies: nobody waits for the children */

    for (;;) {

        ssh_session session = ssh_new();
        if (ssh_bind_accept(bind, session) != SSH_OK) {
            fprintf(stderr, "libssh-peer: accept failed: %s\n", ssh_get_error(bind));
            ssh_free(session);
            continue;
        }

        pid_t child = fork();
        if (child == 0) {
            ssh_bind_free(bind);
            serve_connection(session, authorized);
            ssh_disconnect(session);
            ssh_free(session);
            _exit(0);
        }

        ssh_free(session);

    }
}


/* ------------------------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "server") == 0)
        return run_server(argv[2], argv[3], argv[4]);

    if (argc != 3 || strcmp(argv[1], "client") != 0) {
        fprintf(stderr, "usage: %s client <config.json>\n       %s server <port> <host-key> <authorized-key>\n", argv[0], argv[0]);
        return 2;
    }

    json_error_t error;
    json_t      *config = json_load_file(argv[2], 0, &error);
    if (config == NULL) {
        fprintf(stderr, "libssh-peer: cannot read %s: %s\n", argv[2], error.text);
        return 2;
    }

    result    = json_object();
    debug_log = json_array();
    json_object_set_new(result, "ok",           json_false());
    json_object_set_new(result, "peer_version", json_string(ssh_version(0)));

    run_client(config);

    json_object_set_new(result, "debug_log", debug_log);
    json_dumpf(result, stdout, JSON_COMPACT);
    putchar('\n');
    return 0;
}
