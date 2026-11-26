/*
 * MinaPeer - drive HermodSSH from Apache MINA SSHD and serve it with MINA SSHD, for the NUnit interop suite.
 *
 * Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
 * Licensed under the Apache License, Version 2.0.
 *
 * Apache MINA SSHD is the Java lineage: Jenkins, Gerrit, Eclipse's JGit and countless Java servers
 * embed it, as client and as server. It ships no command-line tool worth driving, so this program is
 * both, compiled against the distribution's jars (Debian 13: 2.13.2).
 *
 *   MinaPeer client <config.json>
 *
 *     The contract of WslInterop.RunPeerAsync: exactly one JSON object is printed to stdout. A failed
 *     SSH operation is {"ok": false, ...} with exit code 0; a non-zero exit means the harness broke.
 *
 *     action           "connect" | "exec" | "sftp"
 *     host, port, username, key_path
 *     host_key_b64     the only host key accepted (the base64 key blob)
 *     command          for "exec"
 *     kex_algs, ciphers, macs, host_key_algs
 *                      restrict what MINA offers; a name MINA does not know or cannot run here is
 *                      reported as error_type "Unsupported", which is a statement about MINA, not about us
 *     upload_path, download_path, remote_dir
 *                      for "sftp": the local file to upload, where to download it back to, and the
 *                      remote directory to work in (created)
 *
 *   MinaPeer server <port> <host-key-file> <authorized-public-key-file>
 *
 *     A MINA SSHD server on 127.0.0.1:<port>. It accepts exactly the given public key, answers "exec"
 *     with "mina ran: <command>\n" and exit status 0 (42 for the command "fail"), and serves the "sftp"
 *     subsystem with MINA's own SFTP server - the real file system, as the account running it sees it.
 */

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import org.apache.sshd.client.ClientBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.cipher.Cipher;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.file.nativefs.NativeFileSystemFactory;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.kex.KexProposalOption;
import org.apache.sshd.common.kex.KeyExchangeFactory;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.mac.Mac;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.AbstractCommandSupport;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.common.SftpException;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;

public final class MinaPeer
{

    private static final Duration            TIMEOUT   = Duration.ofSeconds(30);
    private static final Map<String, Object> result    = new LinkedHashMap<>();
    private static final List<Object>        debugLog  = new ArrayList<>();


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
        synchronized (debugLog) { debugLog.add(line); }
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

    /** Map each requested name to MINA's factory, refusing any MINA does not know or cannot run. */
    private static <T> List<T> restrict(Map<String, Object> config, String key, Function<String, T> lookup) throws Failure
    {
        var requested = names(config, key);
        if (requested == null)
            return null;

        var factories = new ArrayList<T>();
        for (var name : requested)
        {
            var factory = lookup.apply(name);
            if (factory == null)
                throw new Failure("Unsupported", "MINA SSHD does not support " + key + "='" + name + "'");
            factories.add(factory);
        }
        return factories;
    }

    private static KeyExchangeFactory keyExchange(String name)
    {
        var factory = BuiltinDHFactories.fromFactoryName(name);
        return factory != null && factory.isSupported() ? ClientBuilder.DH2KEX.apply(factory) : null;
    }

    private static NamedFactory<Cipher> cipher(String name)
    {
        var factory = BuiltinCiphers.fromFactoryName(name);
        return factory != null && factory.isSupported() ? factory : null;
    }

    private static NamedFactory<Mac> mac(String name)
    {
        var factory = BuiltinMacs.fromFactoryName(name);
        return factory != null && factory.isSupported() ? factory : null;
    }

    private static NamedFactory<Signature> signature(String name)
    {
        var factory = BuiltinSignatures.fromFactoryName(name);
        return factory != null && factory.isSupported() ? factory : null;
    }


    /* --------------------------------------------------------------------------------------------
     * client
     * ------------------------------------------------------------------------------------------ */

    private static String blobOf(PublicKey key)
    {
        var buffer = new ByteArrayBuffer();
        buffer.putRawPublicKey(key);
        return Base64.getEncoder().encodeToString(buffer.getCompactData());
    }

    private static void runClient(Map<String, Object> config) throws Exception
    {

        stage("configuring");

        var action   = (String) config.get("action");
        var pinned   = (String) config.get("host_key_b64");
        var client   = SshClient.setUpDefaultClient();

        // MINA signs its own login from the same list it offers for the host key, so the defaults
        // are kept aside: a restriction to the host-key algorithm under test must not also take away
        // the signature our user key needs.
        var signatures = new ArrayList<>(client.getSignatureFactories());

        var kex      = restrict(config, "kex_algs",      MinaPeer::keyExchange);
        var ciphers  = restrict(config, "ciphers",       MinaPeer::cipher);
        var macs     = restrict(config, "macs",          MinaPeer::mac);
        var hostKeys = restrict(config, "host_key_algs", MinaPeer::signature);

        if (kex      != null) client.setKeyExchangeFactories(kex);
        if (ciphers  != null) client.setCipherFactories(ciphers);
        if (macs     != null) client.setMacFactories(macs);
        if (hostKeys != null) client.setSignatureFactories(hostKeys);

        // The pin below is the whole check: no known_hosts file is read or written.
        var presented = new PublicKey[1];
        client.setServerKeyVerifier((session, address, key) -> {
            presented[0] = key;
            return blobOf(key).equals(pinned);
        });

        var established = new CompletableFuture<Void>();
        client.addSessionListener(new SessionListener() {

            @Override
            public void sessionPeerIdentificationReceived(Session session, String version, List<String> extraLines)
            {
                log("peer identification: " + version);
            }

            @Override
            public void sessionNegotiationEnd(Session session,
                                              Map<KexProposalOption, String> clientProposal,
                                              Map<KexProposalOption, String> serverProposal,
                                              Map<KexProposalOption, String> negotiatedOptions,
                                              Throwable reason)
            {
                log("client proposal: " + clientProposal);
                log("server proposal: " + serverProposal);
                log("negotiated: " + negotiatedOptions + (reason != null ? " - failed: " + describe(reason) : ""));
            }

            @Override
            public void sessionEvent(Session session, Event event)
            {
                log("event: " + event);
                if (event == Event.KeyEstablished)
                    established.complete(null);
            }

            @Override
            public void sessionException(Session session, Throwable error)
            {
                log("exception: " + describe(error));
                established.completeExceptionally(error);
            }

            @Override
            public void sessionClosed(Session session)
            {
                log("closed");
                established.completeExceptionally(new IOException("the session closed before the key exchange completed"));
            }

        });

        client.start();

        try
        {

            stage("connecting");

            ClientSession session;
            try
            {
                session = client.connect((String) config.get("username"),
                                         (String) config.get("host"),
                                         ((Number) config.get("port")).intValue())
                                .verify(TIMEOUT)
                                .getSession();
            }
            catch (IOException error)
            {
                throw new Failure("ConnectError", describe(error));
            }

            result.put("peer_version", session.getClientVersion());

            try
            {
                established.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
            }
            catch (Exception error)
            {
                if (presented[0] != null && !blobOf(presented[0]).equals(pinned))
                {
                    stage("host-key");
                    result.put("server_version", session.getServerVersion());
                    throw new Failure("HostKeyMismatch", "the server presented a host key other than the pinned one");
                }
                throw new Failure("KexError", describe(error));
            }

            stage("connected");
            result.put("server_version", session.getServerVersion());

            var algorithms = new LinkedHashMap<String, Object>();
            algorithms.put("kex",        session.getNegotiatedKexParameter(KexProposalOption.ALGORITHMS));
            algorithms.put("cipher_out", session.getNegotiatedKexParameter(KexProposalOption.C2SENC));
            algorithms.put("cipher_in",  session.getNegotiatedKexParameter(KexProposalOption.S2CENC));
            algorithms.put("mac_out",    session.getNegotiatedKexParameter(KexProposalOption.C2SMAC));
            algorithms.put("mac_in",     session.getNegotiatedKexParameter(KexProposalOption.S2CMAC));
            algorithms.put("host_key",   presented[0] != null ? KeyUtils.getKeyType(presented[0]) : null);
            algorithms.put("host_key_algorithm", session.getNegotiatedKexParameter(KexProposalOption.SERVERKEYS));
            result.put("algorithms", algorithms);

            // MINA's verifier already refused a mismatch above; this is the record of the check.
            stage("host-key");

            // No conversion: MINA reads the openssh-key-v1 file our generator wrote.
            stage("authenticating");
            Iterable<KeyPair> keys;
            try
            {
                keys = new FileKeyPairProvider(Paths.get((String) config.get("key_path"))).loadKeys(null);
            }
            catch (Exception error)
            {
                throw new Failure("KeyImportError", describe(error));
            }

            for (var key : keys)
                session.addPublicKeyIdentity(key);

            session.setSignatureFactories(signatures);

            try
            {
                session.auth().verify(TIMEOUT);
            }
            catch (IOException error)
            {
                throw new Failure("AuthenticationFailed", describe(error));
            }

            stage("authenticated");

            switch (action)
            {
                case "connect" -> { }
                case "exec"    -> runExec(session, (String) config.get("command"));
                case "sftp"    -> runSftp(session, config);
                default        -> throw new Failure("HarnessError", "unknown action '" + action + "'");
            }

            result.put("ok", true);
            stage("done");

            session.close(false).await(TIMEOUT);

        }
        finally
        {
            client.stop();
        }

    }

    private static void runExec(ClientSession session, String command) throws Failure
    {

        stage("exec");

        var out = new ByteArrayOutputStream();
        var err = new ByteArrayOutputStream();

        try (ChannelExec channel = session.createExecChannel(command))
        {
            channel.setOut(out);
            channel.setErr(err);
            channel.open().verify(TIMEOUT);
            channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED), TIMEOUT);

            result.put("stdout", out.toString(StandardCharsets.UTF_8));
            result.put("stderr", err.toString(StandardCharsets.UTF_8));
            if (channel.getExitStatus() != null)
                result.put("exit_status", channel.getExitStatus());
        }
        catch (IOException error)
        {
            throw new Failure("ChannelError", describe(error));
        }

    }

    private static void runSftp(ClientSession session, Map<String, Object> config) throws Failure
    {

        var directory = (String) config.get("remote_dir");
        var upload    = directory + "/upload.bin";
        var data      = directory + "/data.bin";
        var link      = directory + "/link.bin";
        var report    = new StringBuilder();

        stage("sftp-open");

        try (SftpClient sftp = SftpClientFactory.instance().createSftpClient(session))
        {

            report.append("sftp_version=").append(sftp.getVersion()).append('\n');

            stage("sftp-mkdir");
            sftp.mkdir(directory);

            // Written through an explicit handle, so the status of the CLOSE is checked: a server may
            // still refuse the file there.
            stage("sftp-put");
            var content = Files.readAllBytes(Paths.get((String) config.get("upload_path")));
            var handle  = sftp.open(upload, EnumSet.of(SftpClient.OpenMode.Write, SftpClient.OpenMode.Create, SftpClient.OpenMode.Truncate));
            for (var offset = 0; offset < content.length; offset += 32768)
                sftp.write(handle, offset, content, offset, Math.min(32768, content.length - offset));
            sftp.close(handle);

            stage("sftp-rename");
            sftp.rename(upload, data);

            stage("sftp-stat");
            report.append("stat_size=").append(sftp.stat(data).getSize()).append('\n');

            // A relative target, as a link is usually made: it must be stored as given.
            stage("sftp-symlink");
            sftp.symLink(link, "data.bin");
            report.append("readlink=").append(sftp.readLink(link)).append('\n');
            if (sftp.lstat(link).isSymbolicLink())
                report.append("lstat_symlink=1\n");

            stage("sftp-get");
            try (InputStream in = sftp.read(link))
            {
                Files.copy(in, Paths.get((String) config.get("download_path")), StandardCopyOption.REPLACE_EXISTING);
            }

            stage("sftp-list");
            var listing = new ArrayList<Object>();
            for (var entry : sftp.readDir(directory))
                if (!entry.getFilename().equals(".") && !entry.getFilename().equals(".."))
                    listing.add(entry.getFilename());
            result.put("listing", listing);

            stage("sftp-remove");
            sftp.remove(link);

        }
        catch (SftpException error)
        {
            throw new Failure("SftpError", "status " + error.getStatus() + ": " + describe(error));
        }
        catch (IOException error)
        {
            throw new Failure("SftpError", describe(error));
        }
        finally
        {
            result.put("stdout", report.toString());
        }

    }


    /* --------------------------------------------------------------------------------------------
     * server
     * ------------------------------------------------------------------------------------------ */

    /** "exec": the command is echoed, never run. */
    private static final class Echo extends AbstractCommandSupport
    {

        Echo(String command)
        {
            super(command, null);
        }

        @Override
        public void run()
        {
            try
            {
                var out = getOutputStream();
                out.write(("mina ran: " + getCommand() + "\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
                onExit("fail".equals(getCommand()) ? 42 : 0);
            }
            catch (IOException error)
            {
                onExit(-1, describe(error));
            }
        }

    }

    private static void runServer(int port, String hostKeyFile, String authorizedKeyFile) throws Exception
    {

        var authorized = new ArrayList<PublicKey>();
        for (var entry : AuthorizedKeyEntry.readAuthorizedKeys(Paths.get(authorizedKeyFile)))
            authorized.add(entry.resolvePublicKey(null, null, PublicKeyEntryResolver.FAILING));

        var server = SshServer.setUpDefaultServer();
        server.setHost("127.0.0.1");
        server.setPort(port);
        server.setKeyPairProvider(new FileKeyPairProvider(Paths.get(hostKeyFile)));
        server.setPasswordAuthenticator(null);
        server.setKeyboardInteractiveAuthenticator(null);
        server.setPublickeyAuthenticator((username, key, session) ->
            authorized.stream().anyMatch(known -> KeyUtils.compareKeys(known, key)));
        server.setCommandFactory((channel, command) -> new Echo(command));
        server.setSubsystemFactories(List.of(new SftpSubsystemFactory.Builder().build()));
        server.setFileSystemFactory(NativeFileSystemFactory.INSTANCE);

        server.start();

        System.out.println("MinaPeer listening on 127.0.0.1:" + port);
        System.out.flush();

        new CountDownLatch(1).await();

    }


    /* --------------------------------------------------------------------------------------------
     * a minimal JSON reader and writer - the peer contract is flat, and the distribution's MINA
     * brings no JSON library along
     * ------------------------------------------------------------------------------------------ */

    private static final class Json
    {

        private final String text;
        private int          at;

        private Json(String text) { this.text = text; }

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

        if (args.length == 4 && args[0].equals("server"))
        {
            runServer(Integer.parseInt(args[1]), args[2], args[3]);
            return;
        }

        if (args.length != 2 || !args[0].equals("client"))
        {
            System.err.println("usage: MinaPeer client <config.json>\n       MinaPeer server <port> <host-key> <authorized-key>");
            System.exit(2);
        }

        // Only the JSON object may reach stdout; whatever a library prints goes to stderr.
        var stdout = System.out;
        System.setOut(new PrintStream(System.err, true, StandardCharsets.UTF_8));

        var config = (Map<String, Object>) Json.parse(Files.readString(Paths.get(args[1])));

        result.put("ok",           false);
        result.put("peer_version", "Apache MINA SSHD");

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
