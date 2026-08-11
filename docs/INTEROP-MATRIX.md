# HermodSSH — interoperability matrix

Generated from the interop test run — do not edit by hand.
Run at 2026-08-11 21:57:16 UTC.

## Summary

**91 passed · 0 failed · 1 not exercised** across 9 peer(s).

> All exercised tests agreed. Some peers were unavailable on the machine that produced this run, so their rows record no evidence rather than success.

## Capability × peer

| Capability | AsyncSSH | Dropbear | Go x/crypto/ssh | OpenSSH | Paramiko | PuTTY | SSH.NET | TinySSH | curl / libssh |
|---|---|---|---|---|---|---|---|---|---|
| Algorithm negotiation | – | – | – | – | ✅ 1 | – | ✅ 1 | – | – |
| Authentication | – | – | – | ✅ 3 | – | – | – | – | – |
| Certificates | – | – | – | ✅ 2 | – | – | – | – | – |
| Channel requests & flow control | – | – | – | – | – | ✅ 1 | – | – | – |
| Host-key rotation (hostkeys-00) | – | – | – | ✅ 1 | – | – | – | – | – |
| Host-key verification | ✅ 1 | ✅ 2 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 1 |
| Key formats (openssh-key-v1, PEM) | – | ✅ 1 | – | ✅ 8 | – | ✅ 1 | – | – | – |
| Remote command execution | ✅ 2 | ✅ 3 | ✅ 2 | ✅ 4 | ✅ 2 | ✅ 2 | ✅ 3 | – | – |
| SFTP | ✅ 1 | – | – | ✅ 2 | ✅ 1 | – | ✅ 1 | – | ✅ 1 |
| SSHFP DNS records | – | – | – | ✅ 3 | – | – | – | – | – |
| Transport & key exchange | ✅ 1 | ✅ 6 | ✅ 1 | ✅ 17 | ✅ 2 | ✅ 6 | – | ✅ 2 | – |
| ssh-agent | – | – | – | ⚪ | – | – | – | – | – |

## Detail

### AsyncSSH

- ✅ `AsyncSsh_RejectsAWrongHostKey` — Host-key verification
- ✅ `AsyncSsh_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `AsyncSsh_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `AsyncSsh_TransfersFiles_OverOurSftpSubsystem` — SFTP
- ✅ `AsyncSsh_CompletesPostQuantumTransport` — Transport & key exchange

### Dropbear

- ✅ `Dropbear_RejectsAWrongHostKey` — Host-key verification
- ✅ `OurClient_RejectsAWrongDropbearHostKey` — Host-key verification
- ✅ `DropbearConvert_ReadsOurPrivateKey` — Key formats (openssh-key-v1, PEM)
- ✅ `Dropbear_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `Dropbear_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `OurClient_RunsCommand_OnDropbearServer` — Remote command execution
- ✅ `Dropbear_CompletesTransport_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("mlkem768x25519-sha256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("sntrup761x25519-sha512")` — Transport & key exchange

### Go x/crypto/ssh

- ✅ `GoCrypto_RejectsAWrongHostKey` — Host-key verification
- ✅ `GoCrypto_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `GoCrypto_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `GoCrypto_CompletesPostQuantumTransport` — Transport & key exchange

### OpenSSH

- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("ecdsa")` — Authentication
- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("ed25519")` — Authentication
- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("rsa")` — Authentication
- ✅ `SshKeygenReads_OurCertificate` — Certificates
- ✅ `WeValidate_SshKeygenSignedCertificate` — Certificates
- ✅ `RealOpenSshClient_LearnsOurRotatedInHostKey` — Host-key rotation (hostkeys-00)
- ✅ `OurClient_RejectsAWrongOpenSshHostKey` — Host-key verification
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ecdsa-sha2-nistp256")` — Key formats (openssh-key-v1, PEM)
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ssh-ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ssh-rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_BcryptEncrypted("ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_BcryptEncrypted("rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("ecdsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `OurClient_RunsCommand_OnRealOpenSshServer` — Remote command execution
- ✅ `OurClient_SeesRemoteExitStatus_FromRealOpenSshServer` — Remote command execution
- ✅ `RealOpenSshClient_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `RealOpenSshClient_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `OurSftpClient_TransfersFiles_WithRealSftpServer` — SFTP
- ✅ `RealSftpClient_PutsAndGets_AgainstOurServer` — SFTP
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("ecdsa")` — SSHFP DNS records
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("ed25519")` — SSHFP DNS records
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("rsa")` — SSHFP DNS records
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("curve25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("mlkem768x25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("sntrup761x25519-sha512@openssh.com")` — Transport & key exchange
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

### PuTTY

- ✅ `Plink_TransfersLargeOutput_AndAnyWinadjIsAnswered` — Channel requests & flow control
- ✅ `Plink_RejectsAWrongHostKey` — Host-key verification
- ✅ `PuttyGen_ReadsOurPrivateKey` — Key formats (openssh-key-v1, PEM)
- ✅ `Plink_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `Plink_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `Plink_CompletesTransport_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("mlkem768x25519-sha256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("sntrup761x25519-sha512")` — Transport & key exchange

### SSH.NET

- ✅ `SshNet_NegotiatesModernAlgorithms` — Algorithm negotiation
- ✅ `SshNet_RejectsAWrongHostKey` — Host-key verification
- ✅ `SshNet_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `SshNet_RunsCommand_OnOurServer("uname -a",0)` — Remote command execution
- ✅ `SshNet_RunsSeveralCommandsOnOneConnection` — Remote command execution
- ✅ `SshNet_TransfersFiles_OverOurSftpSubsystem` — SFTP

### TinySSH

- ✅ `OurClient_RejectsAWrongTinySshHostKey` — Host-key verification
- ✅ `OurClient_CompletesTransport_WithTinySshServer("curve25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithTinySshServer("sntrup761x25519-sha512@openssh.com")` — Transport & key exchange

### curl / libssh

- ✅ `Curl_RejectsAWrongHostKey` — Host-key verification
- ✅ `Curl_UploadsAndDownloads_OverOurSftpSubsystem` — SFTP

## Legend

| Mark | Meaning |
|---|---|
| ✅ | The peer and HermodSSH agreed. |
| ❌ | The test ran and disagreed — a genuine interop defect. |
| ⚪ | Not exercised: the peer or a tool it needs was unavailable on this machine. **No evidence either way.** |
| – | No test covers this capability for this peer yet. |
