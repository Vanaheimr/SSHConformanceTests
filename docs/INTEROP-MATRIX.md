# HermodSSH — interoperability matrix

Generated from the interop test run — do not edit by hand.
Run at 2026-08-11 19:31:40 UTC.

## Summary

**49 passed · 1 failed · 1 not exercised** across 4 peer(s).

> ⚠ 1 interop test(s) failed — see the detail below.

## Capability × peer

| Capability | AsyncSSH | OpenSSH | Paramiko | SSH.NET |
|---|---|---|---|---|
| Algorithm negotiation | – | – | ✅ 1 | ✅ 1 |
| Authentication | – | ✅ 3 | – | – |
| Certificates | – | ✅ 2 | – | – |
| Host-key rotation (hostkeys-00) | – | ❌ 1/1 | – | – |
| Host-key verification | ✅ 1 | – | ✅ 1 | ✅ 1 |
| Key formats (openssh-key-v1, PEM) | – | ✅ 8 | – | – |
| Remote command execution | ✅ 2 | ✅ 2 | ✅ 2 | ✅ 3 |
| SFTP | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 1 |
| SSHFP DNS records | – | ✅ 3 | – | – |
| Transport & key exchange | ✅ 1 | ✅ 12 | ✅ 2 | – |
| ssh-agent | – | ⚪ | – | – |

## Detail

### AsyncSSH

- ✅ `AsyncSsh_RejectsAWrongHostKey` — Host-key verification
- ✅ `AsyncSsh_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `AsyncSsh_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `AsyncSsh_TransfersFiles_OverOurSftpSubsystem` — SFTP
- ✅ `AsyncSsh_CompletesPostQuantumTransport` — Transport & key exchange

### OpenSSH

- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("ecdsa")` — Authentication
- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("ed25519")` — Authentication
- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("rsa")` — Authentication
- ✅ `SshKeygenReads_OurCertificate` — Certificates
- ✅ `WeValidate_SshKeygenSignedCertificate` — Certificates
- ❌ `RealOpenSshClient_LearnsOurRotatedInHostKey` — Host-key rotation (hostkeys-00) — OpenSSH host-key rotation interop failed.
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ecdsa-sha2-nistp256")` — Key formats (openssh-key-v1, PEM)
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ssh-ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ssh-rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_BcryptEncrypted("ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_BcryptEncrypted("rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("ecdsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `RealOpenSshClient_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `RealOpenSshClient_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `RealSftpClient_PutsAndGets_AgainstOurServer` — SFTP
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("ecdsa")` — SSHFP DNS records
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("ed25519")` — SSHFP DNS records
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("rsa")` — SSHFP DNS records
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("curve25519-sha256","ecdsa-sha2-nistp256","aes256-gcm@openssh.com","hmac-sha2-256","aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("curve25519-sha256","rsa-sha2-512","aes256-gcm@openssh.com","hmac-sha2-256","aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("curve25519-sha256","ssh-ed25519","aes256-ctr","hmac-sha2-256-etm@openssh.com","aes256-ctr")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("curve25519-sha256","ssh-ed25519","aes256-gcm@openssh.com","hmac-sha2-256","aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("curve25519-sha256","ssh-ed25519","chacha20-poly1305@openssh.com","hmac-sha2-256","chacha20-poly1305@openssh.com")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("diffie-hellman-group14-sha256","ssh-ed25519","aes256-gcm@openssh.com","hmac-sha2-256","aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("diffie-hellman-group16-sha512","ssh-ed25519","aes256-ctr","hmac-sha2-512-etm@openssh.com","aes256-ctr")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("ecdh-sha2-nistp256","ssh-ed25519","aes256-gcm@openssh.com","hmac-sha2-256","aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("ecdh-sha2-nistp521","ssh-ed25519","aes256-ctr","hmac-sha2-512-etm@openssh.com","aes256-ctr")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("mlkem768x25519-sha256","ssh-ed25519","aes256-gcm@openssh.com","hmac-sha2-256","aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurServer_CompletesTransport_WithRealOpenSshClient("sntrup761x25519-sha512","ssh-ed25519","chacha20-poly1305@openssh.com","hmac-sha2-256","chacha20-poly1305@openssh.com")` — Transport & key exchange
- ✅ `OurServer_SendsExtInfo_RealOpenSshClientReceivesServerSigAlgs` — Transport & key exchange
- ⚪ `RealAgent_ListsAndSigns` — ssh-agent — No ssh-agent reachable: The operation was canceled.

### Paramiko

- ✅ `Paramiko_NegotiatesModernAlgorithms_WithoutPostQuantum` — Algorithm negotiation
- ✅ `Paramiko_RejectsAWrongHostKey` — Host-key verification
- ✅ `Paramiko_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `Paramiko_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `Paramiko_TransfersFiles_OverOurSftpSubsystem` — SFTP
- ✅ `Paramiko_CompletesClassicalTransport` — Transport & key exchange
- ✅ `Paramiko_FailsCleanly_WhenNoKeyExchangeIsShared` — Transport & key exchange

### SSH.NET

- ✅ `SshNet_NegotiatesModernAlgorithms` — Algorithm negotiation
- ✅ `SshNet_RejectsAWrongHostKey` — Host-key verification
- ✅ `SshNet_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `SshNet_RunsCommand_OnOurServer("uname -a",0)` — Remote command execution
- ✅ `SshNet_RunsSeveralCommandsOnOneConnection` — Remote command execution
- ✅ `SshNet_TransfersFiles_OverOurSftpSubsystem` — SFTP

## Legend

| Mark | Meaning |
|---|---|
| ✅ | The peer and HermodSSH agreed. |
| ❌ | The test ran and disagreed — a genuine interop defect. |
| ⚪ | Not exercised: the peer or a tool it needs was unavailable on this machine. **No evidence either way.** |
| – | No test covers this capability for this peer yet. |
