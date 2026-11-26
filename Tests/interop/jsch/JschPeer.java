/*
 * JschPeer - drive HermodSSH from JSch, for the NUnit interop suite.
 *
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 * Licensed under the Apache License, Version 2.0.
 *
 * JSch is the other Java lineage beside Apache MINA SSHD, and the older and more widely embedded one:
 * Ant's sshexec and scp tasks, Maven wagons, Eclipse, Jenkins plugins, Spring Integration, Talend and a
 * long tail of Java tools carry it. JCraft stopped at 0.1.55; the maintained line is Matthias Wiede's
 * fork, 0.2.x, which is what Debian 13 ships (0.2.19) under the old package name. It shares no code
 * with MINA. It is a client only, so this program is too, compiled against the distribution's jars.
 *
 *   JschPeer client <config.json>
 *
 *     The contract of WslInterop.RunPeerAsync: exactly one JSON object is printed to stdout. A failed
 *     SSH operation is {"ok": false, ...} with exit code 0; a non-zero exit means the harness broke.
 *
 *     action           "connect" | "exec" | "sftp"
 *     host, port, username, key_path
 *     host_key_b64     the only host key accepted (the base64 key blob)
 *     command          for "exec"
 *     kex_algs, ciphers, macs, host_key_algs
 *                      restrict what JSch offers; a name JSch does not know is reported as error_type
 *                      "Unsupported", which is a statement about JSch, not about us
 *     upload_path, download_path, remote_dir
 *                      for "sftp": the local file to upload, where to download it back to, and the
 *                      remote directory to work in (created)
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.HostKey;
import com.jcraft.jsch.HostKeyRepository;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Logger;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;
import com.jcraft.jsch.UserInfo;

public final class JschPeer
{

    private static final int                 TIMEOUT_MS = 30_000;
    private static final Map<String, Object> result     = new LinkedHashMap<>();
    private static final List<Object>        debugLog   = new ArrayList<>();

    /** What JSch's log said it negotiated, and how far the session got - JSch exposes neither otherwise. */
    private static final Map<String, Object> negotiated = new LinkedHashMap<>();
    private static volatile boolean          keysTaken;
    private static volatile boolean          authenticating;


    /* --------------------------------------------------------------------------------------------
     * result helpers
     * ------------------------------------------------------------------------------------------ */

    private static void stage(String stage)
    {
        result.put("stage", stage);
    }

    /** Thrown to end the run with {"ok": false}; the stage is whatever was set last. */
    private static final class Failure extends Exception
    {
        private static final long serialVersionUID = 1L;

        Failure(String type, String message)
        {
            super(message);
            result.put("ok",         false);
            result.put("error_type", type);
            result.put("error",      message != null ? message : "(no message)");
        }
    }

    private static String describe(Throwable error)
    {
        var text = new StringBuilder();
        for (var cause = error; cause != null; cause = cause.getCause())
        {
            if (text.length() > 0)
                text.append(" <- ");
            text.append(cause.getClass().getSimpleName()).append(": ").append(cause.getMessage());
        }
        return text.toString();
    }

    private static void log(String line)
    {
        synchronized (debugLog)
        {
            if (debugLog.size() < 400)
                debugLog.add(line);
        }
    }


    /* --------------------------------------------------------------------------------------------
     * JSch's log: the record of the negotiation
     * ------------------------------------------------------------------------------------------ */

    private static String after(String message, String prefix)
    {
        return message.startsWith(prefix) ? message.substring(prefix.length()).trim() : null;
    }

    /** "kex: server->client cipher: aes128-ctr MAC: hmac-sha2-256-etm@openssh.com compression: none" */
    private static void direction(String rest, String cipherKey, String macKey)
    {
        var words = rest.split("\\s+");
        for (var i = 0; i + 1 < words.length; i++)
        {
            if (words[i].equals("cipher:")) negotiated.put(cipherKey, words[i + 1]);
            if (words[i].equals("MAC:"))    negotiated.put(macKey,    words[i + 1]);
        }
    }

    private static final class Collector implements Logger
    {

        @Override
        public boolean isEnabled(int level)
        {
            return true;
        }

        @Override
        public void log(int level, String message)
        {

            JschPeer.log(message);

            String rest;
            if      ((rest = after(message, "kex: algorithm:"))               != null) negotiated.put("kex", rest);
            else if ((rest = after(message, "kex: host key algorithm:"))      != null) negotiated.put("host_key_algorithm", rest);
            else if ((rest = after(message, "kex: client->server"))           != null) direction(rest, "cipher_out", "mac_out");
            else if ((rest = after(message, "kex: server->client"))           != null) direction(rest, "cipher_in",  "mac_in");
            else if (message.startsWith("SSH_MSG_NEWKEYS received"))                    keysTaken      = true;
            else if (message.startsWith("SSH_MSG_SERVICE_ACCEPT received"))             authenticating = true;

        }

    }


    /* --------------------------------------------------------------------------------------------
     * the host-key pin
     * ------------------------------------------------------------------------------------------ */

    /** A known-hosts store that knows exactly one key, and records the one the server presented. */
    private static final class Pin implements HostKeyRepository
    {

        private final String pinned;
        String               presented;

        Pin(String pinned)
        {
            this.pinned = pinned;
        }

        @Override
        public int check(String host, byte[] key)
        {
            presented = Base64.getEncoder().encodeToString(key);
            return presented.equals(pinned) ? OK : NOT_INCLUDED;
        }

        @Override public void      add(HostKey hostkey, UserInfo ui)                        { }
        @Override public void      remove(String host, String type)                         { }
        @Override public void      remove(String host, String type, byte[] key)             { }
        @Override public String    getKnownHostsRepositoryID()                              { return "pin"; }
        @Override public HostKey[] getHostKey()                                             { return new HostKey[0]; }
        @Override public HostKey[] getHostKey(String host, String type)                     { return new HostKey[0]; }

    }


    /* --------------------------------------------------------------------------------------------
     * algorithm restrictions
     * ------------------------------------------------------------------------------------------ */

    @SuppressWarnings("unchecked")
    private static List<String> names(Map<String, Object> config, String key)
    {
        var value = config.get(key);
        return value instanceof List<?> list ? (List<String>) list : null;
    }

    /** JSch names every algorithm it implements in its config, mapped to the class that does it. */
    private static String restrict(Map<String, Object> config, String key) throws Failure
    {
        var requested = names(config, key);
        if (requested == null)
            return null;

        for (var name : requested)
            if (JSch.getConfig(name) == null)
                throw new Failure("Unsupported", "JSch does not support " + key + "='" + name + "'");

        return String.join(",", requested);
    }


    /* --------------------------------------------------------------------------------------------
     * client
     * ------------------------------------------------------------------------------------------ */

    private static void runClient(Map<String, Object> config) throws Exception
    {

        stage("configuring");

        var action = (String) config.get("action");
        var jsch   = new JSch();
        var pin    = new Pin((String) config.get("host_key_b64"));

        JSch.setLogger(new Collector());

        var kex      = restrict(config, "kex_algs");
        var ciphers  = restrict(config, "ciphers");
        var macs     = restrict(config, "macs");
        var hostKeys = restrict(config, "host_key_algs");

        // No conversion: JSch reads the openssh-key-v1 file our generator wrote.
        try
        {
            jsch.addIdentity((String) config.get("key_path"));
        }
        catch (JSchException error)
        {
            throw new Failure("KeyImportError", describe(error));
        }

        // The pin is the whole check: no known_hosts file is read or written.
        jsch.setHostKeyRepository(pin);

        var session = jsch.getSession((String) config.get("username"),
                                      (String) config.get("host"),
                                      ((Number) config.get("port")).intValue());

        session.setConfig("StrictHostKeyChecking", "yes");
        session.setConfig("PreferredAuthentications", "publickey");

        // JSch's CheckKexes/CheckCiphers would quietly drop what it cannot run here; a restriction
        // to one algorithm must instead fail loudly, so only the requested name is offered.
        if (kex      != null) { session.setConfig("kex", kex); session.setConfig("CheckKexes", ""); }
        if (ciphers  != null) { session.setConfig("cipher.c2s", ciphers); session.setConfig("cipher.s2c", ciphers); session.setConfig("CheckCiphers", ""); }
        if (macs     != null) { session.setConfig("mac.c2s", macs); session.setConfig("mac.s2c", macs); session.setConfig("CheckMacs", ""); }
        if (hostKeys != null) { session.setConfig("server_host_key", hostKeys); session.setConfig("CheckSignatures", ""); }

        stage("connecting");

        try
        {
            session.connect(TIMEOUT_MS);
        }
        catch (JSchException error)
        {

            if (session.getServerVersion() != null)
                result.put("server_version", session.getServerVersion());

            if (pin.presented != null && !pin.presented.equals(pin.pinned))
            {
                stage("host-key");
                throw new Failure("HostKeyMismatch", "the server presented a host key other than the pinned one: " + describe(error));
            }

            if (authenticating)
            {
                stage("authenticating");
                throw new Failure("AuthenticationFailed", describe(error));
            }

            if (keysTaken || session.getServerVersion() != null)
            {
                stage("connected");
                throw new Failure("KexError", describe(error));
            }

            throw new Failure("ConnectError", describe(error));

        }

        try
        {

            stage("authenticated");

            result.put("peer_version",   session.getClientVersion());
            result.put("server_version", session.getServerVersion());

            var algorithms = new LinkedHashMap<String, Object>(negotiated);
            algorithms.put("host_key", session.getHostKey() != null ? session.getHostKey().getType() : null);
            result.put("algorithms", algorithms);

            switch (action)
            {
                case "connect" -> { }
                case "exec"    -> runExec(session, (String) config.get("command"));
                case "sftp"    -> runSftp(session, config);
                default        -> throw new Failure("HarnessError", "unknown action '" + action + "'");
            }

            result.put("ok", true);
            stage("done");

        }
        finally
        {
            session.disconnect();
        }

    }

    private static void runExec(Session session, String command) throws Failure
    {

        stage("exec");

        var out = new ByteArrayOutputStream();
        var err = new ByteArrayOutputStream();

        try
        {

            var channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            channel.setInputStream(null);
            channel.setOutputStream(out);
            channel.setErrStream(err);
            channel.connect(TIMEOUT_MS);

            var deadline = System.currentTimeMillis() + TIMEOUT_MS;
            while (!channel.isClosed())
            {
                if (System.currentTimeMillis() > deadline)
                    throw new Failure("ChannelError", "the channel did not close within " + TIMEOUT_MS + " ms");
                Thread.sleep(10);
            }

            result.put("stdout", out.toString(StandardCharsets.UTF_8));
            result.put("stderr", err.toString(StandardCharsets.UTF_8));
            if (channel.getExitStatus() >= 0)
                result.put("exit_status", channel.getExitStatus());

            channel.disconnect();

        }
        catch (JSchException | InterruptedException error)
        {
            throw new Failure("ChannelError", describe(error));
        }

    }

    private static void runSftp(Session session, Map<String, Object> config) throws Failure
    {

        var directory = (String) config.get("remote_dir");
        var upload    = directory + "/upload.bin";
        var data      = directory + "/data.bin";
        var link      = directory + "/link.bin";
        var report    = new StringBuilder();

        stage("sftp-open");

        ChannelSftp sftp = null;
        try
        {

            sftp = (ChannelSftp) session.openChannel("sftp");
            sftp.connect(TIMEOUT_MS);

            report.append("sftp_version=").append(sftp.version()).append('\n');

            stage("sftp-mkdir");
            sftp.mkdir(directory);

            // put() writes through its own handle and checks the status of the CLOSE: a server may
            // still refuse the file there.
            stage("sftp-put");
            var content = Files.readAllBytes(Paths.get((String) config.get("upload_path")));
            sftp.put(new ByteArrayInputStream(content), upload, ChannelSftp.OVERWRITE);

            stage("sftp-rename");
            sftp.rename(upload, data);

            stage("sftp-stat");
            report.append("stat_size=").append(sftp.stat(data).getSize()).append('\n');

            // A relative target, as a link is usually made: it must be stored as given. JSch makes a
            // relative target relative to its working directory, hence the cd.
            stage("sftp-symlink");
            sftp.cd(directory);
            sftp.symlink("data.bin", link);
            report.append("readlink=").append(sftp.readlink(link)).append('\n');
            if (sftp.lstat(link).isLink())
                report.append("lstat_symlink=1\n");

            stage("sftp-get");
            try (OutputStream out = new FileOutputStream((String) config.get("download_path")))
            {
                sftp.get(link, out);
            }

            stage("sftp-list");
            var listing = new ArrayList<Object>();
            for (var entry : sftp.ls(directory))
                if (!entry.getFilename().equals(".") && !entry.getFilename().equals(".."))
                    listing.add(entry.getFilename());
            result.put("listing", listing);

            stage("sftp-remove");
            sftp.rm(link);

        }
        catch (SftpException error)
        {
            throw new Failure("SftpError", "status " + error.id + ": " + describe(error));
        }
        catch (Exception error)
        {
            throw new Failure("SftpError", describe(error));
        }
        finally
        {
            result.put("stdout", report.toString());
            if (sftp != null)
                sftp.disconnect();
        }

    }


    /* --------------------------------------------------------------------------------------------
     * a minimal JSON reader and writer - the JDK has none, and the peer takes no dependency for it
     * ------------------------------------------------------------------------------------------ */

    private static final class Json
    {

        private final String text;
        private       int    at;

        private Json(String text)
        {
            this.text = text;
        }

        static Object parse(String text)
        {
            var json  = new Json(text);
            var value = json.value();
            json.space();
            if (json.at != text.length())
                throw new IllegalArgumentException("trailing characters at " + json.at);
            return value;
        }

        private void space()
        {
            while (at < text.length() && Character.isWhitespace(text.charAt(at)))
                at++;
        }

        private boolean take(char c)
        {
            space();
            if (at < text.length() && text.charAt(at) == c) { at++; return true; }
            return false;
        }

        private void expect(char c)
        {
            if (!take(c))
                throw new IllegalArgumentException("expected '" + c + "' at " + at);
        }

        private Object value()
        {
            space();
            if (at >= text.length())
                throw new IllegalArgumentException("unexpected end");
            var c = text.charAt(at);
            if (c == '{')  return object();
            if (c == '[')  return array();
            if (c == '"')  return string();
            if (text.startsWith("true",  at)) { at += 4; return true;  }
            if (text.startsWith("false", at)) { at += 5; return false; }
            if (text.startsWith("null",  at)) { at += 4; return null;  }
            return number();
        }

        private Map<String, Object> object()
        {
            var map = new LinkedHashMap<String, Object>();
            expect('{');
            if (take('}'))
                return map;
            do
            {
                space();
                var key = string();
                expect(':');
                map.put(key, value());
            }
            while (take(','));
            expect('}');
            return map;
        }

        private List<Object> array()
        {
            var list = new ArrayList<Object>();
            expect('[');
            if (take(']'))
                return list;
            do list.add(value()); while (take(','));
            expect(']');
            return list;
        }

        private String string()
        {
            if (text.charAt(at) != '"')
                throw new IllegalArgumentException("expected a string at " + at);
            at++;
            var out = new StringBuilder();
            while (true)
            {
                var c = text.charAt(at++);
                if (c == '"')
                    return out.toString();
                if (c != '\\') { out.append(c); continue; }
                var e = text.charAt(at++);
                switch (e)
                {
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'u' -> { out.append((char) Integer.parseInt(text.substring(at, at + 4), 16)); at += 4; }
                    default  -> out.append(e);
                }
            }
        }

        private Number number()
        {
            var start = at;
            while (at < text.length() && "+-0123456789.eE".indexOf(text.charAt(at)) >= 0)
                at++;
            var literal = text.substring(start, at);
            if (literal.isEmpty())
                throw new IllegalArgumentException("unexpected character at " + start);
            return literal.matches("-?\\d+") ? (Number) Long.parseLong(literal) : (Number) Double.parseDouble(literal);
        }

        static String write(Object value)
        {
            var out = new StringBuilder();
            write(out, value);
            return out.toString();
        }

        private static void write(StringBuilder out, Object value)
        {
            if (value == null)
                out.append("null");
            else if (value instanceof Boolean || value instanceof Number)
                out.append(value);
            else if (value instanceof Map<?, ?> map)
            {
                out.append('{');
                var first = true;
                for (var entry : map.entrySet())
                {
                    if (!first) out.append(',');
                    first = false;
                    write(out, String.valueOf(entry.getKey()));
                    out.append(':');
                    write(out, entry.getValue());
                }
                out.append('}');
            }
            else if (value instanceof List<?> list)
            {
                out.append('[');
                for (var i = 0; i < list.size(); i++)
                {
                    if (i > 0) out.append(',');
                    write(out, list.get(i));
                }
                out.append(']');
            }
            else
            {
                out.append('"');
                for (var c : value.toString().toCharArray())
                {
                    switch (c)
                    {
                        case '"'  -> out.append("\\\"");
                        case '\\' -> out.append("\\\\");
                        case '\n' -> out.append("\\n");
                        case '\r' -> out.append("\\r");
                        case '\t' -> out.append("\\t");
                        default   -> {
                            if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                            else          out.append(c);
                        }
                    }
                }
                out.append('"');
            }
        }

    }


    /* ------------------------------------------------------------------------------------------ */

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception
    {

        if (args.length != 2 || !args[0].equals("client"))
        {
            System.err.println("usage: JschPeer client <config.json>");
            System.exit(2);
        }

        // Only the JSON object may reach stdout; whatever a library prints goes to stderr.
        var stdout = System.out;
        System.setOut(new PrintStream(System.err, true, StandardCharsets.UTF_8));

        var config = (Map<String, Object>) Json.parse(Files.readString(Paths.get(args[1])));

        result.put("ok",           false);
        result.put("peer_version", "JSch");

        try
        {
            runClient(config);
        }
        catch (Failure failure)
        {
            // already recorded
        }
        catch (Exception error)
        {
            result.put("ok",         false);
            result.put("error_type", "PeerError");
            result.put("error",      describe(error));
        }

        result.put("debug_log", debugLog);
        stdout.println(Json.write(result));
        stdout.flush();
        System.exit(0);

    }

}
