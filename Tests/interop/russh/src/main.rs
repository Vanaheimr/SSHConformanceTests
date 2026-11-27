/*
 * russh-peer - drive HermodSSH from Russh and serve it with Russh, for the NUnit interop suite.
 *
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 * Licensed under the Apache License, Version 2.0.
 *
 * Russh is the Rust lineage: Warpgate and a growing number of Rust services
 * embed it, as client and as server, with russh-sftp on top. It shares no code with any C, Go or Java
 * implementation, and it ships no command-line tool, so this program is both. Cargo.lock pins every
 * crate, rust-toolchain.toml the compiler.
 *
 *   russh-peer client <config.json>
 *
 *     The contract of WslInterop.RunPeerAsync: exactly one JSON object is printed to stdout. A failed
 *     SSH operation is {"ok": false, ...} with exit code 0; a non-zero exit means the harness broke.
 *
 *     action           "connect" | "exec" | "sftp"
 *     host, port, username, key_path
 *     host_key_b64     the only host key accepted (the base64 key blob)
 *     command          for "exec"
 *     kex_algs, ciphers, macs, host_key_algs
 *                      restrict what Russh offers; a name Russh does not know is reported as
 *                      error_type "Unsupported", which is a statement about Russh, not about us
 *     upload_path, download_path, remote_dir
 *                      for "sftp": the local file to upload, where to download it back to, and the
 *                      remote directory to work in (created)
 *
 *   russh-peer server <port> <host-key-file> <authorized-public-key-file>
 *
 *     A Russh server on 127.0.0.1:<port>. It accepts exactly the given public key, answers "exec" with
 *     "russh ran: <command>\n" and exit status 0 (42 for the command "fail"), and serves the "sftp"
 *     subsystem through russh-sftp - the real file system, as the account running it sees it.
 */

use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKeyWithHashAlg, PublicKey, load_public_key, load_secret_key};
use russh::server::Server as _;
use russh::{ChannelId, ChannelMsg, Disconnect, Preferred, SshId, cipher, client, kex, mac, server};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, SftpHandle, Status, StatusCode, Version};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(30);


/* ------------------------------------------------------------------------------------------------
 * debug log - Russh's own log records and ours, returned as "debug_log"
 * ---------------------------------------------------------------------------------------------- */

static DEBUG_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

const DEBUG_LOG_LIMIT: usize = 400;

fn note(line: impl Into<String>) {
    let mut log = DEBUG_LOG.lock().unwrap();
    if log.len() < DEBUG_LOG_LIMIT {
        log.push(line.into());
    }
}

/// Collects Russh's debug records for the client's JSON, and passes them to stderr for the server,
/// whose stderr the harness keeps as the peer's output.
struct Logger {
    to_stderr: bool,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug && metadata.target().starts_with("russh")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let line = format!("{} {}: {}", record.level(), record.target(), record.args());
            if self.to_stderr {
                eprintln!("{line}");
            } else {
                note(line);
            }
        }
    }

    fn flush(&self) {}
}


/* ------------------------------------------------------------------------------------------------
 * result helpers
 * ---------------------------------------------------------------------------------------------- */

#[derive(Default)]
struct Outcome {
    fields: Map<String, Value>,
}

impl Outcome {
    fn stage(&mut self, stage: &str) {
        self.fields.insert("stage".into(), json!(stage));
    }

    fn set(&mut self, key: &str, value: Value) {
        self.fields.insert(key.into(), value);
    }
}

/// Ends the run with {"ok": false}; the stage is whatever was set last.
struct Failure {
    error_type: &'static str,
    message: String,
}

fn failure(error_type: &'static str, message: impl std::fmt::Display) -> Failure {
    Failure { error_type, message: message.to_string() }
}

type Step<T> = Result<T, Failure>;

fn text<'a>(config: &'a Value, key: &str) -> Step<&'a str> {
    config[key].as_str().ok_or_else(|| failure("HarnessError", format!("'{key}' is missing from the configuration")))
}

fn names(config: &Value, key: &str) -> Option<Vec<String>> {
    config[key].as_array().map(|list| list.iter().filter_map(|name| name.as_str().map(String::from)).collect())
}

/// Map each requested name to Russh's own, refusing any Russh does not know.
fn restrict<T>(config: &Value, key: &str, lookup: impl Fn(&str) -> Option<T>) -> Step<Option<Vec<T>>> {
    let Some(requested) = names(config, key) else {
        return Ok(None);
    };

    let mut mapped = Vec::new();
    for name in requested {
        match lookup(&name) {
            Some(value) => mapped.push(value),
            None => return Err(failure("Unsupported", format!("Russh does not support {key}='{name}'"))),
        }
    }
    Ok(Some(mapped))
}


/* ------------------------------------------------------------------------------------------------
 * client
 * ---------------------------------------------------------------------------------------------- */

/// What the handler saw during the key exchange, for the result.
#[derive(Default)]
struct Seen {
    host_key_type: Option<String>,
    host_key_matched: Option<bool>,
    algorithms: Option<Map<String, Value>>,
}

struct Client {
    pinned: String,
    seen: Arc<Mutex<Seen>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, presented: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } = presented else {
            note("the server presented a certificate, which no test asks for");
            return Ok(false);
        };

        // The base64 blob is the second field of the OpenSSH public-key line. The pin below is the
        // whole check: no known_hosts file is read or written.
        let blob = key.to_openssh().ok().and_then(|line| line.split(' ').nth(1).map(String::from)).unwrap_or_default();
        let matched = blob == self.pinned;

        note(format!("host key {}: {}", key.algorithm().as_str(), if matched { "the pinned one" } else { "NOT the pinned one" }));

        let mut seen = self.seen.lock().unwrap();
        seen.host_key_type = Some(key.algorithm().as_str().to_string());
        seen.host_key_matched = Some(matched);
        Ok(matched)
    }

    async fn kex_done(&mut self,
                      _shared_secret: Option<&[u8]>,
                      names: &russh::Names,
                      _session: &mut client::Session) -> Result<(), Self::Error> {
        let mut algorithms = Map::new();
        algorithms.insert("kex".into(), json!(names.kex.as_ref()));
        algorithms.insert("cipher_out".into(), json!(names.cipher.as_ref()));
        algorithms.insert("cipher_in".into(), json!(names.cipher.as_ref()));
        algorithms.insert("mac_out".into(), json!(names.client_mac.as_ref()));
        algorithms.insert("mac_in".into(), json!(names.server_mac.as_ref()));
        algorithms.insert("host_key_algorithm".into(), json!(names.key.as_str()));
        // A string like every other entry: the harness reads the map as names.
        algorithms.insert("strict_kex".into(), json!(names.strict_kex().to_string()));

        note(format!("negotiated: {}", Value::Object(algorithms.clone())));

        let mut seen = self.seen.lock().unwrap();
        if seen.algorithms.is_none() {
            seen.algorithms = Some(algorithms);
        }
        Ok(())
    }
}

/// The TCP stream, with the first bytes the server sends kept aside: Russh does not hand out the
/// server's identification string, and the result wants it.
struct Tap {
    inner: TcpStream,
    received: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let mut received = this.received.lock().unwrap();
            let fresh = &buf.filled()[before..];
            let room = 1024usize.saturating_sub(received.len()).min(fresh.len());
            received.extend_from_slice(&fresh[..room]);
        }
        poll
    }
}

impl AsyncWrite for Tap {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn server_version(received: &Mutex<Vec<u8>>) -> Option<String> {
    let received = received.lock().unwrap();
    String::from_utf8_lossy(&received)
        .split('\n')
        .find(|line| line.starts_with("SSH-"))
        .map(|line| line.trim_end_matches('\r').to_string())
}

async fn run_client(config: &Value, out: &mut Outcome) -> Step<()> {
    out.stage("configuring");

    let action = text(config, "action")?;
    let username = text(config, "username")?;
    let host = text(config, "host")?;
    let port = config["port"].as_u64().ok_or_else(|| failure("HarnessError", "'port' is missing from the configuration"))? as u16;

    let mut preferred = Preferred::default();

    if let Some(mut kexes) = restrict(config, "kex_algs", |name| kex::Name::try_from(name).ok())? {
        // The extension markers ride in the same list, and must stay: without them there is no
        // ext-info and no strict key exchange.
        kexes.extend([kex::EXTENSION_SUPPORT_AS_CLIENT,
                      kex::EXTENSION_SUPPORT_AS_SERVER,
                      kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                      kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER]);
        preferred.kex = Cow::Owned(kexes);
    }
    if let Some(ciphers) = restrict(config, "ciphers", |name| cipher::Name::try_from(name).ok())? {
        preferred.cipher = Cow::Owned(ciphers);
    }
    if let Some(macs) = restrict(config, "macs", |name| mac::Name::try_from(name).ok())? {
        preferred.mac = Cow::Owned(macs);
    }
    if let Some(keys) = restrict(config, "host_key_algs", |name| {
        Algorithm::from_str(name).ok().filter(|algorithm| Preferred::DEFAULT.key.contains(algorithm))
    })? {
        preferred.key = Cow::Owned(keys);
    }

    let settings = client::Config { preferred, inactivity_timeout: Some(TIMEOUT), ..Default::default() };

    if let SshId::Standard(id) = &settings.client_id {
        out.set("peer_version", json!(id));
    }

    out.stage("connecting");

    let stream = match timeout(TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(failure("ConnectError", error)),
        Err(_) => return Err(failure("ConnectError", "timed out")),
    };

    let received = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let handler = Client { pinned: text(config, "host_key_b64")?.to_string(), seen: seen.clone() };

    let connected = timeout(TIMEOUT, client::connect_stream(Arc::new(settings), Tap { inner: stream, received: received.clone() }, handler)).await;

    if let Some(version) = server_version(&received) {
        out.set("server_version", json!(version));
    }

    let mut handle = match connected {
        Ok(Ok(handle)) => handle,
        Ok(Err(error)) => {
            if seen.lock().unwrap().host_key_matched == Some(false) {
                out.stage("host-key");
                return Err(failure("HostKeyMismatch", "the server presented a host key other than the pinned one"));
            }
            return Err(failure("KexError", format!("{error:?}")));
        }
        Err(_) => return Err(failure("KexError", "the key exchange timed out")),
    };

    out.stage("connected");

    {
        let seen = seen.lock().unwrap();
        let mut algorithms = seen.algorithms.clone().unwrap_or_default();
        algorithms.insert("host_key".into(), json!(seen.host_key_type));
        out.set("algorithms", Value::Object(algorithms));
    }

    // Russh's handler already refused a mismatch above; this is the record of the check.
    out.stage("host-key");

    // No conversion: Russh reads the openssh-key-v1 file our generator wrote.
    out.stage("authenticating");

    let key = load_secret_key(text(config, "key_path")?, None).map_err(|error| failure("KeyImportError", error))?;

    // For an RSA key the signature algorithm is the server's to name, through server-sig-algs.
    let hash = if key.algorithm().is_rsa() {
        handle.best_supported_rsa_hash().await.map_err(|error| failure("AuthenticationFailed", format!("{error:?}")))?.flatten()
    } else {
        None
    };

    let authenticated = handle
        .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
        .await
        .map_err(|error| failure("AuthenticationFailed", format!("{error:?}")))?;

    if !authenticated.success() {
        return Err(failure("AuthenticationFailed", format!("the server refused the key: {authenticated:?}")));
    }

    out.stage("authenticated");

    match action {
        "connect" => {}
        "exec" => run_exec(&handle, text(config, "command")?, out).await?,
        "sftp" => run_sftp(&handle, config, out).await?,
        other => return Err(failure("HarnessError", format!("unknown action '{other}'"))),
    }

    out.set("ok", json!(true));
    out.stage("done");

    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    Ok(())
}

async fn run_exec(handle: &client::Handle<Client>, command: &str, out: &mut Outcome) -> Step<()> {
    out.stage("exec");

    let channel_error = |error: russh::Error| failure("ChannelError", format!("{error:?}"));

    let mut channel = handle.channel_open_session().await.map_err(channel_error)?;
    channel.exec(true, command).await.map_err(channel_error)?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;

    loop {
        match timeout(TIMEOUT, channel.wait()).await {
            Err(_) => return Err(failure("ChannelError", "the command did not finish in time")),
            Ok(None) => break,
            Ok(Some(ChannelMsg::Data { data })) => stdout.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExtendedData { data, ext: 1 })) => stderr.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExitStatus { exit_status: status })) => exit_status = Some(status),
            Ok(Some(_)) => {}
        }
    }

    out.set("stdout", json!(String::from_utf8_lossy(&stdout)));
    out.set("stderr", json!(String::from_utf8_lossy(&stderr)));
    if let Some(status) = exit_status {
        out.set("exit_status", json!(status));
    }
    Ok(())
}

async fn run_sftp(handle: &client::Handle<Client>, config: &Value, out: &mut Outcome) -> Step<()> {
    let directory = text(config, "remote_dir")?;
    let upload = format!("{directory}/upload.bin");
    let data = format!("{directory}/data.bin");
    let link = format!("{directory}/link.bin");
    let mut report = String::new();

    let sftp_error = |error: russh_sftp::client::error::Error| failure("SftpError", error);
    let io_error = |error: io::Error| failure("SftpError", error);

    out.stage("sftp-open");

    let channel = handle.channel_open_session().await.map_err(|error| failure("ChannelError", format!("{error:?}")))?;
    channel.request_subsystem(true, "sftp").await.map_err(|error| failure("ChannelError", format!("{error:?}")))?;
    let sftp = SftpSession::new(channel.into_stream()).await.map_err(sftp_error)?;

    out.stage("sftp-mkdir");
    sftp.create_dir(directory).await.map_err(sftp_error)?;

    // Written through a file whose shutdown sends the CLOSE and waits for its status: a server may
    // still refuse the file there.
    out.stage("sftp-put");
    let content = std::fs::read(text(config, "upload_path")?).map_err(|error| failure("HarnessError", error))?;
    let mut file = sftp
        .open_with_flags(upload.as_str(), OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE)
        .await
        .map_err(sftp_error)?;
    file.write_all(&content).await.map_err(io_error)?;
    file.shutdown().await.map_err(io_error)?;

    out.stage("sftp-rename");
    sftp.rename(upload.as_str(), data.as_str()).await.map_err(sftp_error)?;

    out.stage("sftp-stat");
    report.push_str(&format!("stat_size={}\n", sftp.metadata(data.as_str()).await.map_err(sftp_error)?.len()));

    // A relative target, as a link is usually made: it must be stored as given. The existing file
    // first and the new link second, the way russh-sftp's own example calls it; which of the two
    // ends up where is checked on the server's disk.
    out.stage("sftp-symlink");
    sftp.symlink("data.bin", link.as_str()).await.map_err(sftp_error)?;
    report.push_str(&format!("readlink={}\n", sftp.read_link(link.as_str()).await.map_err(sftp_error)?));
    if sftp.symlink_metadata(link.as_str()).await.map_err(sftp_error)?.is_symlink() {
        report.push_str("lstat_symlink=1\n");
    }

    out.stage("sftp-get");
    let downloaded = sftp.read(link.as_str()).await.map_err(sftp_error)?;
    std::fs::write(text(config, "download_path")?, downloaded).map_err(|error| failure("HarnessError", error))?;

    out.stage("sftp-list");
    let listing: Vec<String> = sftp
        .read_dir(directory)
        .await
        .map_err(sftp_error)?
        .map(|entry| entry.file_name())
        .filter(|name| name != "." && name != "..")
        .collect();
    out.set("listing", json!(listing));

    out.stage("sftp-remove");
    sftp.remove_file(link.as_str()).await.map_err(sftp_error)?;

    out.set("stdout", json!(report));
    let _ = sftp.close().await;
    Ok(())
}

async fn client_main(config_path: &str) -> i32 {
    let _ = log::set_boxed_logger(Box::new(Logger { to_stderr: false })).map(|()| log::set_max_level(log::LevelFilter::Debug));

    let config: Value = match std::fs::read_to_string(config_path).map_err(|error| error.to_string())
                                                                   .and_then(|json| serde_json::from_str(&json).map_err(|error| error.to_string())) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("cannot read the configuration '{config_path}': {error}");
            return 2;
        }
    };

    let mut out = Outcome::default();
    out.set("ok", json!(false));

    if let Err(Failure { error_type, message }) = run_client(&config, &mut out).await {
        out.set("ok", json!(false));
        out.set("error_type", json!(error_type));
        out.set("error", json!(message));
    }

    out.set("debug_log", json!(*DEBUG_LOG.lock().unwrap()));
    println!("{}", Value::Object(out.fields));
    0
}


/* ------------------------------------------------------------------------------------------------
 * server
 * ---------------------------------------------------------------------------------------------- */

#[derive(Clone)]
struct PeerServer {
    authorized: Arc<PublicKey>,
}

impl server::Server for PeerServer {
    type Handler = Connection;

    fn new_client(&mut self, peer: Option<SocketAddr>) -> Connection {
        eprintln!("connection from {peer:?}");
        Connection { authorized: self.authorized.clone(), channels: HashMap::new() }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        eprintln!("session error: {error:?}");
    }
}

struct Connection {
    authorized: Arc<PublicKey>,
    channels: HashMap<ChannelId, russh::Channel<server::Msg>>,
}

impl server::Handler for Connection {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, key: server::VerifiedPublicKey<'_>) -> Result<server::Auth, Self::Error> {
        let accepted = key.public_key.key_data() == self.authorized.key_data();
        eprintln!("publickey for '{user}' signed with {}: {}", key.algorithm.as_str(), if accepted { "accepted" } else { "refused" });
        Ok(if accepted { server::Auth::Accept } else { server::Auth::reject() })
    }

    async fn channel_open_session(&mut self,
                                  channel: russh::Channel<server::Msg>,
                                  reply: server::ChannelOpenHandle,
                                  _session: &mut server::Session) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut server::Session) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        eprintln!("exec '{command}'");

        session.channel_success(channel)?;
        session.data(channel, format!("russh ran: {command}\n").into_bytes())?;
        session.exit_status_request(channel, if command == "fail" { 42 } else { 0 })?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut server::Session) -> Result<(), Self::Error> {
        eprintln!("subsystem '{name}'");

        match (name, self.channels.remove(&channel)) {
            ("sftp", Some(open)) => {
                session.channel_success(channel)?;
                russh_sftp::server::run(open.into_stream(), SftpFileSystem::default()).await;
            }
            _ => session.channel_failure(channel)?,
        }
        Ok(())
    }
}

/// russh-sftp parses and frames the protocol and leaves the file system to the application; this
/// is the plain one, as the account running the peer sees it.
#[derive(Default)]
struct SftpFileSystem {
    handles: HashMap<SftpHandle, Opened>,
    next_handle: u64,
}

enum Opened {
    File(std::fs::File),
    Directory(Option<Vec<File>>),
}

fn ok(id: u32) -> Status {
    Status { id, status_code: StatusCode::Ok, error_message: "Ok".into(), language_tag: "en-US".into() }
}

// The file-system calls the SFTP server makes that are spelled differently on Unix and on Windows. The
// peer runs natively on both: on Linux as the Debian CI leg builds it, on Windows as the windows-latest
// leg does (PeerPlatform.cs).

/// pread(2): read at an offset, without a shared cursor.
#[cfg(unix)]
fn read_at(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

/// Windows' positioned read. It moves the file's cursor as a side effect, which nothing here relies on:
/// every read and write names its own offset.
#[cfg(windows)]
fn read_at(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

/// pwrite(2) until every byte is written.
#[cfg(unix)]
fn write_all_at(file: &std::fs::File, data: &[u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, data, offset)
}

/// Windows' positioned write, which may write less than it was given, until every byte is written.
#[cfg(windows)]
fn write_all_at(file: &std::fs::File, mut data: &[u8], mut offset: u64) -> io::Result<()> {
    while !data.is_empty() {
        let written = std::os::windows::fs::FileExt::seek_write(file, data, offset)?;
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        data = &data[written..];
        offset += written as u64;
    }
    Ok(())
}

/// The permissions an SSH_FXP_SETSTAT asks for.
#[cfg(unix)]
fn permissions_for(_current: std::fs::Permissions, mode: u32) -> std::fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    std::fs::Permissions::from_mode(mode & 0o7777)
}

/// Windows keeps one bit of what a mode says - whether the file may be written - so that is what is set.
#[cfg(windows)]
fn permissions_for(mut current: std::fs::Permissions, mode: u32) -> std::fs::Permissions {
    current.set_readonly(mode & 0o222 == 0);
    current
}

/// symlink(2). Relative targets stay relative to the link's directory.
#[cfg(unix)]
fn make_symlink(target: &str, link: &str) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

/// A file symbolic link, as SFTP has no notion of the directory links Windows tells apart. Creating one
/// takes the symbolic-link privilege or Developer Mode.
#[cfg(windows)]
fn make_symlink(target: &str, link: &str) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

fn status_of(error: io::Error) -> StatusCode {
    eprintln!("sftp: {error}");
    match error.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl SftpFileSystem {
    fn keep(&mut self, opened: Opened) -> SftpHandle {
        self.next_handle += 1;
        let handle = SftpHandle::from(self.next_handle.to_string());
        self.handles.insert(handle.clone(), opened);
        handle
    }

    fn file(&self, handle: &SftpHandle) -> Result<&std::fs::File, StatusCode> {
        match self.handles.get(handle) {
            Some(Opened::File(file)) => Ok(file),
            _ => Err(StatusCode::Failure),
        }
    }

    fn apply(path_or_file: Result<&std::fs::File, &str>, attrs: &FileAttributes) -> Result<(), StatusCode> {
        if let Some(size) = attrs.size {
            match path_or_file {
                Ok(file) => file.set_len(size).map_err(status_of)?,
                Err(path) => std::fs::OpenOptions::new().write(true).open(path).and_then(|file| file.set_len(size)).map_err(status_of)?,
            }
        }
        if let Some(permissions) = attrs.permissions {
            match path_or_file {
                Ok(file) => file.set_permissions(permissions_for(file.metadata().map_err(status_of)?.permissions(), permissions)).map_err(status_of)?,
                Err(path) => std::fs::set_permissions(path, permissions_for(std::fs::metadata(path).map_err(status_of)?.permissions(), permissions)).map_err(status_of)?,
            }
        }
        Ok(())
    }
}

impl russh_sftp::server::Handler for SftpFileSystem {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(&mut self, version: u32, extensions: HashMap<String, String>) -> Result<Version, Self::Error> {
        eprintln!("sftp: client version {version}, extensions {extensions:?}");
        Ok(Version::new())
    }

    async fn open(&mut self, id: u32, filename: String, pflags: OpenFlags, _attrs: FileAttributes) -> Result<Handle, Self::Error> {
        let file = std::fs::OpenOptions::new()
            .read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE))
            .append(pflags.contains(OpenFlags::APPEND))
            .create(pflags.contains(OpenFlags::CREATE) && !pflags.contains(OpenFlags::EXCLUDE))
            .create_new(pflags.contains(OpenFlags::CREATE) && pflags.contains(OpenFlags::EXCLUDE))
            .truncate(pflags.contains(OpenFlags::TRUNCATE))
            .open(&filename)
            .map_err(status_of)?;
        Ok(Handle { id, handle: self.keep(Opened::File(file)) })
    }

    async fn close(&mut self, id: u32, handle: SftpHandle) -> Result<Status, Self::Error> {
        self.handles.remove(&handle).ok_or(StatusCode::Failure)?;
        Ok(ok(id))
    }

    async fn read(&mut self, id: u32, handle: SftpHandle, offset: u64, len: u32) -> Result<Data, Self::Error> {
        let mut data = vec![0; len.min(256 * 1024) as usize];
        let read = read_at(self.file(&handle)?, &mut data, offset).map_err(status_of)?;
        if read == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(read);
        Ok(Data { id, data })
    }

    async fn write(&mut self, id: u32, handle: SftpHandle, offset: u64, data: Vec<u8>) -> Result<Status, Self::Error> {
        write_all_at(self.file(&handle)?, &data, offset).map_err(status_of)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: FileAttributes::from(&std::fs::symlink_metadata(&path).map_err(status_of)?) })
    }

    async fn fstat(&mut self, id: u32, handle: SftpHandle) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: FileAttributes::from(&self.file(&handle)?.metadata().map_err(status_of)?) })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        Ok(Attrs { id, attrs: FileAttributes::from(&std::fs::metadata(&path).map_err(status_of)?) })
    }

    async fn setstat(&mut self, id: u32, path: String, attrs: FileAttributes) -> Result<Status, Self::Error> {
        Self::apply(Err(&path), &attrs)?;
        Ok(ok(id))
    }

    async fn fsetstat(&mut self, id: u32, handle: SftpHandle, attrs: FileAttributes) -> Result<Status, Self::Error> {
        Self::apply(Ok(self.file(&handle)?), &attrs)?;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&path).map_err(status_of)? {
            let entry = entry.map_err(status_of)?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(status_of)?;
            entries.push(File::new(entry.file_name().to_string_lossy().into_owned(), FileAttributes::from(&metadata)));
        }
        Ok(Handle { id, handle: self.keep(Opened::Directory(Some(entries))) })
    }

    async fn readdir(&mut self, id: u32, handle: SftpHandle) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(Opened::Directory(entries)) => match entries.take() {
                Some(files) if !files.is_empty() => Ok(Name { id, files }),
                _ => Err(StatusCode::Eof),
            },
            _ => Err(StatusCode::Failure),
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        std::fs::remove_file(&filename).map_err(status_of)?;
        Ok(ok(id))
    }

    async fn mkdir(&mut self, id: u32, path: String, _attrs: FileAttributes) -> Result<Status, Self::Error> {
        std::fs::create_dir(&path).map_err(status_of)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(&path).map_err(status_of)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let path = if path.is_empty() { ".".to_string() } else { path };
        let resolved = std::fs::canonicalize(&path).map(|path| path.to_string_lossy().into_owned()).unwrap_or(path);
        Ok(Name { id, files: vec![File::dummy(resolved)] })
    }

    async fn rename(&mut self, id: u32, oldpath: String, newpath: String) -> Result<Status, Self::Error> {
        // SFTP version 3 renames refuse an existing target, unlike rename(2).
        if std::fs::symlink_metadata(&newpath).is_ok() {
            return Err(StatusCode::Failure);
        }
        std::fs::rename(&oldpath, &newpath).map_err(status_of)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = std::fs::read_link(&path).map_err(status_of)?;
        Ok(Name { id, files: vec![File::dummy(target.to_string_lossy().into_owned())] })
    }

    /// russh-sftp hands the two strings over in wire order under the draft's names, linkpath first;
    /// what they mean is the application's call. They are read in OpenSSH's order here, the target
    /// first - which is also the order russh-sftp's own client sends them in, its example calling
    /// symlink(existing, new).
    async fn symlink(&mut self, id: u32, linkpath: String, targetpath: String) -> Result<Status, Self::Error> {
        let (target, link) = (linkpath, targetpath);
        eprintln!("sftp: symlink '{link}' -> '{target}'");
        make_symlink(&target, &link).map_err(status_of)?;
        Ok(ok(id))
    }
}

async fn server_main(port: &str, host_key_path: &str, authorized_path: &str) -> i32 {
    let _ = log::set_boxed_logger(Box::new(Logger { to_stderr: true })).map(|()| log::set_max_level(log::LevelFilter::Debug));

    let Ok(port) = port.parse::<u16>() else {
        eprintln!("not a port: '{port}'");
        return 2;
    };
    let host_key = match load_secret_key(host_key_path, None) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("cannot read the host key '{host_key_path}': {error}");
            return 2;
        }
    };
    let authorized = match load_public_key(authorized_path) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("cannot read the authorized key '{authorized_path}': {error}");
            return 2;
        }
    };

    // Everything Russh implements that a modern client may ask for, so a client restricted to any
    // one of them finds it here: the defaults leave out the NIST curves and aes128-gcm.
    let mut preferred = Preferred::default();
    preferred.kex = Cow::Owned(vec![kex::MLKEM768X25519_SHA256,
                                    kex::CURVE25519,
                                    kex::CURVE25519_PRE_RFC_8731,
                                    kex::ECDH_SHA2_NISTP256,
                                    kex::ECDH_SHA2_NISTP384,
                                    kex::ECDH_SHA2_NISTP521,
                                    kex::DH_GEX_SHA256,
                                    kex::DH_G18_SHA512,
                                    kex::DH_G16_SHA512,
                                    kex::DH_G14_SHA256,
                                    kex::EXTENSION_SUPPORT_AS_CLIENT,
                                    kex::EXTENSION_SUPPORT_AS_SERVER,
                                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                                    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER]);
    preferred.cipher = Cow::Owned(vec![cipher::CHACHA20_POLY1305,
                                       cipher::AES_256_GCM,
                                       cipher::AES_128_GCM,
                                       cipher::AES_256_CTR,
                                       cipher::AES_192_CTR,
                                       cipher::AES_128_CTR]);

    let settings = server::Config {
        keys: vec![host_key],
        preferred,
        auth_rejection_time: Duration::from_millis(100),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    };

    eprintln!("russh server on 127.0.0.1:{port}");

    let mut peer = PeerServer { authorized: Arc::new(authorized) };
    match peer.run_on_address(Arc::new(settings), ("127.0.0.1", port)).await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("server failed: {error}");
            1
        }
    }
}


#[tokio::main]
async fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();

    let code = match arguments.as_slice() {
        [_, "client", config] => client_main(config).await,
        [_, "server", port, host_key, authorized] => server_main(port, host_key, authorized).await,
        _ => {
            eprintln!("usage: russh-peer client <config.json>\n       russh-peer server <port> <host-key> <authorized-key>");
            2
        }
    };

    std::process::exit(code);
}
