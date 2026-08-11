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
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

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
}

type result struct {
	OK            bool    `json:"ok"`
	Error         *string `json:"error"`
	ErrorType     *string `json:"error_type"`
	Stage         string  `json:"stage"`
	StdOut        *string `json:"stdout"`
	StdErr        *string `json:"stderr"`
	ExitStatus    *int    `json:"exit_status"`
	PeerVersion   string  `json:"peer_version"`
	ServerVersion *string `json:"server_version"`
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

	hostKeyBlob, err := base64.StdEncoding.DecodeString(cfg.HostKeyBase64)
	if err != nil {
		return err
	}

	hostKey, err := ssh.ParsePublicKey(hostKeyBlob)
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
		HostKeyCallback: ssh.FixedHostKey(hostKey),
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

	default:
		return fmt.Errorf("unknown action %q", cfg.Action)
	}

	out.Stage = "done"
	return nil
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
