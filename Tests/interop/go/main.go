// hermod-interop — drive HermodSSH's server from golang.org/x/crypto/ssh, for the NUnit interop suite.
//
// Copyright (c) 2010-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
// This file is part of Vanaheimr Hermod <https://www.github.com/Vanaheimr/Hermod>
// Licensed under the Apache License, Version 2.0.
//
// Contract with the C# side (WslInterop.RunPeerDriverAsync):
//
//	os.Args[1] is a JSON configuration file; exactly one JSON object is printed to stdout.
//	A failed SSH operation is reported as {"ok": false, ...} with exit code 0 — a non-zero exit
//	means the harness itself broke, which the test surfaces as a harness bug.
//
// Go is the strictest peer in the suite: x/crypto/ssh is a spec-literal implementation with a
// deliberately small algorithm set, and it reads our openssh-key-v1 private key with no conversion
// step at all — unlike Dropbear and PuTTY, which each need their own format.
//
// Certificates, both ways (all optional):
//
//	cert_path           log in with this OpenSSH certificate for the key (one we issued)
//	issue_with_ca_path  issue a user certificate for the key with this CA private key, as Go does, and log in with it
//	principals          the principals of that certificate
//	host_ca_b64         instead of pinning host_key_b64, accept a host certificate signed by this CA for the dialled host
//
// SFTP (action "sftp", github.com/pkg/sftp with concurrent reads and writes):
//
//	upload_path         the local file to upload
//	download_path       where to download it back to, through a symbolic link
//	remote_dir          the remote directory to work in (created)
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type config struct {
	Action         string   `json:"action"`
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	Username       string   `json:"username"`
	KeyPath        string   `json:"key_path"`
	HostKeyBase64  string   `json:"host_key_b64"`
	Command        string   `json:"command"`
	KexAlgs        []string `json:"kex_algs"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	CertPath       string   `json:"cert_path"`
	IssueWithCA    string   `json:"issue_with_ca_path"`
	Principals     []string `json:"principals"`
	HostCABase64   string   `json:"host_ca_b64"`
	UploadPath     string   `json:"upload_path"`
	DownloadPath   string   `json:"download_path"`
	RemoteDir      string   `json:"remote_dir"`
}

type result struct {
	OK            bool    `json:"ok"`
	Error         *string `json:"error"`
	ErrorType     *string `json:"error_type"`
	Stage         string  `json:"stage"`
	StdOut        *string `json:"stdout"`
	StdErr        *string `json:"stderr"`
	ExitStatus    *int    `json:"exit_status"`
	PeerVersion   string   `json:"peer_version"`
	ServerVersion *string  `json:"server_version"`
	Listing       []string `json:"listing"`
}

func text(value string) *string { return &value }

func run(cfg config, out *result) error {

	key, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return err
	}

	// No conversion: x/crypto reads the openssh-key-v1 container our generator writes.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return err
	}

	signer, err = certify(cfg, signer)
	if err != nil {
		return err
	}

	hostKeyCallback, err := hostKeyCheck(cfg)
	if err != nil {
		return err
	}

	timeout := 30 * time.Second
	if cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}

	clientConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         timeout,
	}

	// Constraining the offer is how the tests prove a specific algorithm was used: if the client may
	// only offer one key exchange, a completed handshake is proof that both sides agreed on it.
	if len(cfg.KexAlgs) > 0 {
		clientConfig.Config.KeyExchanges = cfg.KexAlgs
	}

	out.Stage = "connecting"

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), clientConfig)
	if err != nil {
		return err
	}
	defer client.Close()

	out.Stage = "connected"
	out.ServerVersion = text(string(client.ServerVersion()))

	switch cfg.Action {

	case "connect":
		// The handshake and the host-key check were the subject; nothing more to do.

	case "exec":
		out.Stage = "exec"

		session, err := client.NewSession()
		if err != nil {
			return err
		}
		defer session.Close()

		stdout, err := session.Output(cfg.Command)
		out.StdOut = text(string(stdout))

		if err != nil {
			// A non-zero remote exit is a result, not a harness failure.
			var exitError *ssh.ExitError
			if ok := asExitError(err, &exitError); ok {
				status := exitError.ExitStatus()
				out.ExitStatus = &status
				out.Stage = "exec-done"
				return nil
			}
			return err
		}

		zero := 0
		out.ExitStatus = &zero

	case "sftp":
		if err := runSftp(cfg, client, out); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown action %q", cfg.Action)
	}

	out.Stage = "done"
	return nil
}

// runSftp drives pkg/sftp the way it is used in practice: many requests in flight on one file, their
// answers taken in whatever order they come. The upload is renamed, linked to, read back through the
// link and listed; the link is removed again. What pkg/sftp saw goes to stdout as key=value lines.
func runSftp(cfg config, client *ssh.Client, out *result) error {

	out.Stage = "sftp-open"

	sc, err := sftp.NewClient(client,
		sftp.UseConcurrentWrites(true),
		sftp.UseConcurrentReads(true),
		sftp.MaxConcurrentRequestsPerFile(64))
	if err != nil {
		return err
	}
	defer sc.Close()

	dir := cfg.RemoteDir

	out.Stage = "sftp-mkdir"
	if err := sc.Mkdir(dir); err != nil {
		return err
	}

	out.Stage = "sftp-put"
	if err := upload(sc, cfg.UploadPath, dir+"/upload.bin"); err != nil {
		return err
	}

	out.Stage = "sftp-rename"
	if err := sc.Rename(dir+"/upload.bin", dir+"/data.bin"); err != nil {
		return err
	}

	out.Stage = "sftp-symlink"
	if err := sc.Symlink("data.bin", dir+"/link.bin"); err != nil {
		return err
	}

	target, err := sc.ReadLink(dir + "/link.bin")
	if err != nil {
		return err
	}

	linkInfo, err := sc.Lstat(dir + "/link.bin")
	if err != nil {
		return err
	}

	dataInfo, err := sc.Stat(dir + "/link.bin")
	if err != nil {
		return err
	}

	out.Stage = "sftp-get"
	if err := download(sc, dir+"/link.bin", cfg.DownloadPath); err != nil {
		return err
	}

	out.Stage = "sftp-list"
	entries, err := sc.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		out.Listing = append(out.Listing, entry.Name())
	}

	out.Stage = "sftp-remove"
	if err := sc.Remove(dir + "/link.bin"); err != nil {
		return err
	}

	out.StdOut = text(fmt.Sprintf("readlink=%s\nlstat_symlink=%t\nstat_size=%d\n",
		target, linkInfo.Mode()&os.ModeSymlink != 0, dataInfo.Size()))

	return nil
}

// upload goes through ReadFrom, which writes concurrently when it knows the size.
func upload(sc *sftp.Client, local, remote string) error {
	src, err := os.Open(local)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := sc.Create(remote)
	if err != nil {
		return err
	}
	if _, err := dst.ReadFrom(src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

// download goes through WriteTo, which reads concurrently.
func download(sc *sftp.Client, remote, local string) error {
	src, err := sc.Open(remote)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(local)
	if err != nil {
		return err
	}
	if _, err := src.WriteTo(dst); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

// certify pairs the key with a user certificate: one we issued (cert_path), or one Go issues itself
// with a CA key (issue_with_ca_path). Without either, the key logs in as it is.
func certify(cfg config, signer ssh.Signer) (ssh.Signer, error) {

	switch {

	case cfg.CertPath != "":
		raw, err := os.ReadFile(cfg.CertPath)
		if err != nil {
			return nil, err
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			return nil, err
		}
		cert, ok := parsed.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("%s holds no certificate", cfg.CertPath)
		}
		return ssh.NewCertSigner(cert, signer)

	case cfg.IssueWithCA != "":
		raw, err := os.ReadFile(cfg.IssueWithCA)
		if err != nil {
			return nil, err
		}
		ca, err := ssh.ParsePrivateKey(raw)
		if err != nil {
			return nil, err
		}
		cert := &ssh.Certificate{
			Key:             signer.PublicKey(),
			Serial:          4711,
			CertType:        ssh.UserCert,
			KeyId:           "issued-by-go",
			ValidPrincipals: cfg.Principals,
			ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
			ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
			Permissions:     ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
		}
		if err := cert.SignCert(rand.Reader, ca); err != nil {
			return nil, err
		}
		return ssh.NewCertSigner(cert, signer)

	default:
		return signer, nil
	}
}

// hostKeyCheck pins host_key_b64, or - with host_ca_b64 - accepts a host certificate that CA signed for
// the dialled host, and nothing else.
func hostKeyCheck(cfg config) (ssh.HostKeyCallback, error) {

	if cfg.HostCABase64 != "" {
		caBlob, err := base64.StdEncoding.DecodeString(cfg.HostCABase64)
		if err != nil {
			return nil, err
		}
		checker := &ssh.CertChecker{
			IsHostAuthority: func(authority ssh.PublicKey, address string) bool {
				return bytes.Equal(authority.Marshal(), caBlob)
			},
		}
		return checker.CheckHostKey, nil
	}

	hostKeyBlob, err := base64.StdEncoding.DecodeString(cfg.HostKeyBase64)
	if err != nil {
		return nil, err
	}

	hostKey, err := ssh.ParsePublicKey(hostKeyBlob)
	if err != nil {
		return nil, err
	}

	return ssh.FixedHostKey(hostKey), nil
}

func asExitError(err error, target **ssh.ExitError) bool {
	if exitError, ok := err.(*ssh.ExitError); ok {
		*target = exitError
		return true
	}
	return false
}

func main() {

	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hermod-interop <configuration.json>")
		os.Exit(2)
	}

	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	out := result{Stage: "starting", PeerVersion: "golang.org/x/crypto/ssh"}

	if err := run(cfg, &out); err != nil {
		out.Error = text(err.Error())
		out.ErrorType = text(fmt.Sprintf("%T", err))
	} else {
		out.OK = true
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	fmt.Println(string(encoded))

}
