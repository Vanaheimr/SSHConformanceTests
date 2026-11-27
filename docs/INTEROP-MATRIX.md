# HermodSSH — interoperability matrix

Generated from the interop test run — do not edit by hand.
Run at 2026-11-27 19:22:03 UTC.

## Summary

**382 passed · 0 failed · 0 not exercised** across 16 peer(s).

> Every interop test passed.

## Capability × peer

| Capability | Apache MINA SSHD | AsyncSSH | Dropbear | Go x/crypto/ssh | JSch | OpenSSH | OpenSSL | Paramiko | PuTTY | Russh | SSH.NET | TinySSH | curl / libssh | libssh | ncclient | wolfSSH |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Algorithm negotiation | – | – | – | – | – | – | – | ✅ 1 | – | – | ✅ 1 | – | – | – | – | – |
| Authentication | ✅ 10 | ✅ 3 | – | – | ✅ 5 | ✅ 4 | – | – | – | ✅ 10 | – | – | – | ✅ 10 | – | ✅ 10 |
| Certificates | – | ✅ 9 | – | ✅ 5 | – | ✅ 7 | – | – | – | – | – | – | – | – | – | – |
| Channel requests & flow control | – | – | – | – | – | ✅ 1 | – | – | ✅ 1 | – | – | – | – | – | – | – |
| Host-key rotation (hostkeys-00) | – | – | – | – | – | ✅ 1 | – | – | – | – | – | – | – | – | – | – |
| Host-key verification | ✅ 8 | ✅ 1 | ✅ 2 | ✅ 1 | ✅ 7 | ✅ 3 | – | ✅ 1 | ✅ 1 | ✅ 8 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 8 | – | ✅ 8 |
| Key formats (openssh-key-v1, PEM) | – | – | ✅ 1 | – | – | ✅ 18 | ✅ 2 | – | ✅ 1 | – | – | – | – | – | – | – |
| NETCONF (RFC 6242) | – | – | – | – | – | – | – | – | – | – | – | – | – | – | ✅ 2 | – |
| Port forwarding | – | – | – | – | – | ✅ 13 | – | – | – | – | – | – | – | – | – | – |
| Remote command execution | ✅ 4 | ✅ 2 | ✅ 4 | ✅ 2 | ✅ 2 | ✅ 4 | – | ✅ 2 | ✅ 2 | ✅ 4 | ✅ 3 | – | – | ✅ 4 | – | ✅ 4 |
| SFTP | ✅ 2 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 1 | ✅ 6 | – | ✅ 1 | ✅ 1 | ✅ 2 | ✅ 1 | – | ✅ 1 | ✅ 2 | – | ✅ 2 |
| SSHFP DNS records | – | – | – | – | – | ✅ 3 | – | – | – | – | – | – | – | – | – | – |
| Subsystems of one's own | – | – | ✅ 1 | – | – | ✅ 9 | – | – | – | – | – | – | – | – | – | – |
| Transport & key exchange | ✅ 27 | ✅ 1 | ✅ 6 | ✅ 1 | ✅ 13 | ✅ 21 | – | ✅ 2 | ✅ 6 | ✅ 27 | – | ✅ 2 | – | ✅ 19 | – | ✅ 18 |
| ssh-agent | – | – | – | – | – | ✅ 1 | – | – | – | – | – | – | – | – | – | – |

## Detail

### Apache MINA SSHD

- ✅ `Mina_LogsInWithOurKey("ecdsa-sha2-nistp256")` — Authentication
- ✅ `Mina_LogsInWithOurKey("ecdsa-sha2-nistp384")` — Authentication
- ✅ `Mina_LogsInWithOurKey("ecdsa-sha2-nistp521")` — Authentication
- ✅ `Mina_LogsInWithOurKey("ssh-ed25519")` — Authentication
- ✅ `Mina_LogsInWithOurKey("ssh-rsa")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithMinaServer("ecdsa-sha2-nistp256")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithMinaServer("ecdsa-sha2-nistp384")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithMinaServer("ecdsa-sha2-nistp521")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithMinaServer("ssh-ed25519")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithMinaServer("ssh-rsa")` — Authentication
- ✅ `Mina_RejectsAWrongHostKey` — Host-key verification
- ✅ `Mina_VerifiesOurHostKey("ecdsa-sha2-nistp256","ecdsa-sha2-nistp256")` — Host-key verification
- ✅ `Mina_VerifiesOurHostKey("ecdsa-sha2-nistp384","ecdsa-sha2-nistp384")` — Host-key verification
- ✅ `Mina_VerifiesOurHostKey("ecdsa-sha2-nistp521","ecdsa-sha2-nistp521")` — Host-key verification
- ✅ `Mina_VerifiesOurHostKey("rsa-sha2-256","ssh-rsa")` — Host-key verification
- ✅ `Mina_VerifiesOurHostKey("rsa-sha2-512","ssh-rsa")` — Host-key verification
- ✅ `Mina_VerifiesOurHostKey("ssh-ed25519","ssh-ed25519")` — Host-key verification
- ✅ `OurClient_RejectsAWrongMinaHostKey` — Host-key verification
- ✅ `Mina_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `Mina_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `OurClient_RunsCommand_OnMinaServer("fail",42)` — Remote command execution
- ✅ `OurClient_RunsCommand_OnMinaServer("hello",0)` — Remote command execution
- ✅ `Mina_TransfersFiles_OnOurServer` — SFTP
- ✅ `OurClient_TransfersFiles_WithMinaSftpServer` — SFTP
- ✅ `Mina_CompletesCipher_WithOurServer("aes128-ctr","hmac-sha2-512-etm@openssh.com")` — Transport & key exchange
- ✅ `Mina_CompletesCipher_WithOurServer("aes128-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `Mina_CompletesCipher_WithOurServer("aes256-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `Mina_CompletesCipher_WithOurServer("aes256-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `Mina_CompletesCipher_WithOurServer("chacha20-poly1305@openssh.com",null)` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Mina_CompletesKeyExchange_WithOurServer("sntrup761x25519-sha512@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithMinaServer("aes128-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithMinaServer("aes128-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithMinaServer("aes192-ctr","hmac-sha2-512-etm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithMinaServer("aes256-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithMinaServer("aes256-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithMinaServer("chacha20-poly1305@openssh.com",null)` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("curve25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithMinaServer("sntrup761x25519-sha512@openssh.com")` — Transport & key exchange

### AsyncSSH

- ✅ `OurClient_AWrongPassword_IsAnAuthenticationError_OnAsyncSshServer` — Authentication
- ✅ `OurClient_AuthenticatesWithAPassword_OnAsyncSshServer` — Authentication
- ✅ `OurClient_AuthenticatesWithKeyboardInteractive_OnAsyncSshServer` — Authentication
- ✅ `AsyncSsh_LogsInWithACertificateItIssued("hermoduser",True)` — Certificates
- ✅ `AsyncSsh_LogsInWithACertificateItIssued("someone-else",False)` — Certificates
- ✅ `AsyncSsh_LogsInWithOurUserCertificate` — Certificates
- ✅ `AsyncSsh_VerifiesOurHostCertificate(False)` — Certificates
- ✅ `AsyncSsh_VerifiesOurHostCertificate(True)` — Certificates
- ✅ `OurClient_LogsInWithAUserCertificate_OnAsyncSshServer("hermoduser",True)` — Certificates
- ✅ `OurClient_LogsInWithAUserCertificate_OnAsyncSshServer("someone-else",False)` — Certificates
- ✅ `OurClient_VerifiesAsyncSshHostCertificate(False)` — Certificates
- ✅ `OurClient_VerifiesAsyncSshHostCertificate(True)` — Certificates
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
- ✅ `OurClient_ReachesAForcedCommand_ThroughExec` — Remote command execution
- ✅ `OurClient_RunsCommand_OnDropbearServer` — Remote command execution
- ✅ `OurClient_ReachesAForcedCommand_ThroughTheSftpSubsystem` — SFTP
- ✅ `OurClient_IsRefusedASubsystemOfItsOwn_EvenUnderAForcedCommand` — Subsystems of one's own
- ✅ `Dropbear_CompletesTransport_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("mlkem768x25519-sha256")` — Transport & key exchange
- ✅ `Dropbear_CompletesTransport_WithOurServer("sntrup761x25519-sha512")` — Transport & key exchange

### Go x/crypto/ssh

- ✅ `GoCrypto_LogsInWithACertificateItIssued("hermoduser",True)` — Certificates
- ✅ `GoCrypto_LogsInWithACertificateItIssued("someone-else",False)` — Certificates
- ✅ `GoCrypto_LogsInWithOurUserCertificate` — Certificates
- ✅ `GoCrypto_VerifiesOurHostCertificate(False)` — Certificates
- ✅ `GoCrypto_VerifiesOurHostCertificate(True)` — Certificates
- ✅ `GoCrypto_RejectsAWrongHostKey` — Host-key verification
- ✅ `GoCrypto_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `GoCrypto_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `GoCrypto_TransfersFiles_WithPkgSftp_OnOurServer` — SFTP
- ✅ `GoCrypto_CompletesPostQuantumTransport` — Transport & key exchange

### JSch

- ✅ `Jsch_LogsInWithOurKey("ecdsa-sha2-nistp256")` — Authentication
- ✅ `Jsch_LogsInWithOurKey("ecdsa-sha2-nistp384")` — Authentication
- ✅ `Jsch_LogsInWithOurKey("ecdsa-sha2-nistp521")` — Authentication
- ✅ `Jsch_LogsInWithOurKey("ssh-ed25519")` — Authentication
- ✅ `Jsch_LogsInWithOurKey("ssh-rsa")` — Authentication
- ✅ `Jsch_RejectsAWrongHostKey` — Host-key verification
- ✅ `Jsch_VerifiesOurHostKey("ecdsa-sha2-nistp256","ecdsa-sha2-nistp256")` — Host-key verification
- ✅ `Jsch_VerifiesOurHostKey("ecdsa-sha2-nistp384","ecdsa-sha2-nistp384")` — Host-key verification
- ✅ `Jsch_VerifiesOurHostKey("ecdsa-sha2-nistp521","ecdsa-sha2-nistp521")` — Host-key verification
- ✅ `Jsch_VerifiesOurHostKey("rsa-sha2-256","ssh-rsa")` — Host-key verification
- ✅ `Jsch_VerifiesOurHostKey("rsa-sha2-512","ssh-rsa")` — Host-key verification
- ✅ `Jsch_VerifiesOurHostKey("ssh-ed25519","ssh-ed25519")` — Host-key verification
- ✅ `Jsch_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `Jsch_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `Jsch_TransfersFiles_OnOurServer` — SFTP
- ✅ `Jsch_CompletesCipher_WithOurServer("aes128-ctr","hmac-sha2-512-etm@openssh.com")` — Transport & key exchange
- ✅ `Jsch_CompletesCipher_WithOurServer("aes128-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `Jsch_CompletesCipher_WithOurServer("aes256-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `Jsch_CompletesCipher_WithOurServer("aes256-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `Jsch_CompletesCipher_WithOurServer("chacha20-poly1305@openssh.com",null)` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Jsch_CompletesKeyExchange_WithOurServer("sntrup761x25519-sha512@openssh.com")` — Transport & key exchange

### OpenSSH

- ✅ `OurClient_AuthenticatesWithTwoKeys_AgainstRealOpenSshServer` — Authentication
- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("ecdsa")` — Authentication
- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("ed25519")` — Authentication
- ✅ `OurServer_AuthenticatesRealOpenSshClient_WithPublicKey("rsa")` — Authentication
- ✅ `OpenSsh_EmptyCertPrincipals_MatchNothingFrom_10_3` — Certificates
- ✅ `OurClient_VerifiesAnRsaHostCertificate_FromRealOpenSshServer("rsa-sha2-256-cert-v01@openssh.com")` — Certificates
- ✅ `OurClient_VerifiesAnRsaHostCertificate_FromRealOpenSshServer("rsa-sha2-512-cert-v01@openssh.com")` — Certificates
- ✅ `RealOpenSshClient_TrustingOurCa_AcceptsOurRsaHostCertificate("rsa-sha2-256-cert-v01@openssh.com")` — Certificates
- ✅ `RealOpenSshClient_TrustingOurCa_AcceptsOurRsaHostCertificate("rsa-sha2-512-cert-v01@openssh.com")` — Certificates
- ✅ `SshKeygenReads_OurCertificate` — Certificates
- ✅ `WeValidate_SshKeygenSignedCertificate` — Certificates
- ✅ `OurClient_KeepAlive_IsAnsweredByRealOpenSshServer` — Channel requests & flow control
- ✅ `RealOpenSshClient_LearnsOurRotatedInHostKey` — Host-key rotation (hostkeys-00)
- ✅ `OurClient_RejectsAWrongOpenSshHostKey` — Host-key verification
- ✅ `RealOpenSshClient_KnowingOnlyOurRsaHostKey_LogsIn` — Host-key verification
- ✅ `RealSshKeyscan_GetsEveryHostKey` — Host-key verification
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ecdsa-sha2-nistp256")` — Key formats (openssh-key-v1, PEM)
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ssh-ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `SshKeygenReads_OurOpenSshPrivateKey("ssh-rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_BcryptEncrypted("ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_BcryptEncrypted("rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("3des-cbc")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes128-cbc")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes128-ctr")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes128-gcm@openssh.com")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes192-cbc")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes192-ctr")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes256-cbc")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes256-ctr")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("aes256-gcm@openssh.com")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_InEveryCipher("chacha20-poly1305@openssh.com")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("ecdsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("ed25519")` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_SshKeygenKeys_Unencrypted("rsa")` — Key formats (openssh-key-v1, PEM)
- ✅ `OurClient_JumpsThroughRealOpenSshServer(1)` — Port forwarding
- ✅ `OurClient_JumpsThroughRealOpenSshServer(2)` — Port forwarding
- ✅ `OurClient_LocalForwards_ThroughRealOpenSshServer_HalfCloseIncluded` — Port forwarding
- ✅ `OurClient_RemoteForward_HalfCloses_ThroughRealOpenSshServer` — Port forwarding
- ✅ `OurClient_RemoteForwards_OnAnAllocatedPort_ThroughRealOpenSshServer("127.0.0.1")` — Port forwarding
- ✅ `OurClient_RemoteForwards_OnAnAllocatedPort_ThroughRealOpenSshServer("localhost")` — Port forwarding
- ✅ `RealOpenSshClient_HalfCloses_ThroughOurServer("-L")` — Port forwarding
- ✅ `RealOpenSshClient_HalfCloses_ThroughOurServer("-R")` — Port forwarding
- ✅ `RealOpenSshClient_LocalForwards_ThroughOurServer` — Port forwarding
- ✅ `RealOpenSshClient_RemoteForwards_OnAnAllocatedPort` — Port forwarding
- ✅ `RealOpenSshClient_RemoteForwards_ThroughOurServer(127.0.0.1)` — Port forwarding
- ✅ `RealOpenSshClient_RemoteForwards_ThroughOurServer(localhost)` — Port forwarding
- ✅ `RealOpenSshClient_RemoteForwards_ThroughOurServer(no bind address)` — Port forwarding
- ✅ `OurClient_RunsCommand_OnRealOpenSshServer` — Remote command execution
- ✅ `OurClient_SeesRemoteExitStatus_FromRealOpenSshServer` — Remote command execution
- ✅ `RealOpenSshClient_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `RealOpenSshClient_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `OurSftpClient_MakesSymlinksAndTruncates_WithRealSftpServer` — SFTP
- ✅ `OurSftpClient_TransfersFiles_WithRealSftpServer` — SFTP
- ✅ `RealSftpClient_CopiesServerSide_AgainstOurServer` — SFTP
- ✅ `RealSftpClient_MakesAndFollowsSymlinks_OnOurServer` — SFTP
- ✅ `RealSftpClient_PreservesTimesAndSetsPermissions_OnOurServer` — SFTP
- ✅ `RealSftpClient_PutsAndGets_AgainstOurServer` — SFTP
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("ecdsa")` — SSHFP DNS records
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("ed25519")` — SSHFP DNS records
- ✅ `OurSshfpRecords_MatchSshKeygenDashR("rsa")` — SSHFP DNS records
- ✅ `OurClient_IsRefused_ASubsystemRealOpenSshServerDoesNotServe` — Subsystems of one's own
- ✅ `OurClient_SeesASubsystemsExitStatus_FromRealOpenSshServer` — Subsystems of one's own
- ✅ `OurClient_SpeaksToASubsystem_OfRealOpenSshServer` — Subsystems of one's own
- ✅ `RealSshClient_IsRefused_ASubsystemItsKeyIsNotConfinedTo` — Subsystems of one's own
- ✅ `RealSshClient_IsRefused_ASubsystemNotServed` — Subsystems of one's own
- ✅ `RealSshClient_ReachesOurSubsystem_WithItsExitStatus("echo@test.open.charging.cloud","one\ntwo\n","one\ntwo\n",0)` — Subsystems of one's own
- ✅ `RealSshClient_ReachesOurSubsystem_WithItsExitStatus("fails@test.open.charging.cloud","","bye\n",1)` — Subsystems of one's own
- ✅ `RealSshClient_ReachesOurSubsystem_WithItsExitStatus("hi@test.open.charging.cloud","","hi\n",0)` — Subsystems of one's own
- ✅ `RealSshClient_ReachesOurSubsystem_WithItsExitStatus("own@test.open.charging.cloud","","",7)` — Subsystems of one's own
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("curve25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("mlkem768x25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesTransport_WithRealOpenSshServer("sntrup761x25519-sha512@openssh.com")` — Transport & key exchange
- ✅ `OurClient_Rekeys_AgainstRealOpenSshServer(sshd starts the rekeys)` — Transport & key exchange
- ✅ `OurClient_Rekeys_AgainstRealOpenSshServer(we start the rekeys)` — Transport & key exchange
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
- ✅ `RealOpenSshClient_Rekeys_WithOurServer(our server starts the rekeys)` — Transport & key exchange
- ✅ `RealOpenSshClient_Rekeys_WithOurServer(ssh starts the rekeys)` — Transport & key exchange
- ✅ `RealAgent_ListsAndSigns` — ssh-agent

### OpenSSL

- ✅ `WeLoad_OpenSslEd25519Pkcs8Keys(False)` — Key formats (openssh-key-v1, PEM)
- ✅ `WeLoad_OpenSslEd25519Pkcs8Keys(True)` — Key formats (openssh-key-v1, PEM)

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
- ✅ `Psftp_TransfersAndManagesFiles_OnOurServer` — SFTP
- ✅ `Plink_CompletesTransport_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("mlkem768x25519-sha256")` — Transport & key exchange
- ✅ `Plink_CompletesTransport_WithOurServer("sntrup761x25519-sha512")` — Transport & key exchange

### Russh

- ✅ `OurClient_UsesEachKeyType_WithRusshServer("ecdsa-sha2-nistp256")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithRusshServer("ecdsa-sha2-nistp384")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithRusshServer("ecdsa-sha2-nistp521")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithRusshServer("ssh-ed25519")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithRusshServer("ssh-rsa")` — Authentication
- ✅ `Russh_LogsInWithOurKey("ecdsa-sha2-nistp256")` — Authentication
- ✅ `Russh_LogsInWithOurKey("ecdsa-sha2-nistp384")` — Authentication
- ✅ `Russh_LogsInWithOurKey("ecdsa-sha2-nistp521")` — Authentication
- ✅ `Russh_LogsInWithOurKey("ssh-ed25519")` — Authentication
- ✅ `Russh_LogsInWithOurKey("ssh-rsa")` — Authentication
- ✅ `OurClient_RejectsAWrongRusshHostKey` — Host-key verification
- ✅ `Russh_RejectsAWrongHostKey` — Host-key verification
- ✅ `Russh_VerifiesOurHostKey("ecdsa-sha2-nistp256","ecdsa-sha2-nistp256")` — Host-key verification
- ✅ `Russh_VerifiesOurHostKey("ecdsa-sha2-nistp384","ecdsa-sha2-nistp384")` — Host-key verification
- ✅ `Russh_VerifiesOurHostKey("ecdsa-sha2-nistp521","ecdsa-sha2-nistp521")` — Host-key verification
- ✅ `Russh_VerifiesOurHostKey("rsa-sha2-256","ssh-rsa")` — Host-key verification
- ✅ `Russh_VerifiesOurHostKey("rsa-sha2-512","ssh-rsa")` — Host-key verification
- ✅ `Russh_VerifiesOurHostKey("ssh-ed25519","ssh-ed25519")` — Host-key verification
- ✅ `OurClient_RunsCommand_OnRusshServer("fail",42)` — Remote command execution
- ✅ `OurClient_RunsCommand_OnRusshServer("hello",0)` — Remote command execution
- ✅ `Russh_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `Russh_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `OurClient_TransfersFiles_WithRusshSftpServer` — SFTP
- ✅ `Russh_TransfersFiles_OnOurServer` — SFTP
- ✅ `OurClient_CompletesCipher_WithRusshServer("aes128-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithRusshServer("aes128-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithRusshServer("aes192-ctr","hmac-sha2-512-etm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithRusshServer("aes256-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithRusshServer("aes256-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithRusshServer("chacha20-poly1305@openssh.com",null)` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("curve25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithRusshServer("mlkem768x25519-sha256")` — Transport & key exchange
- ✅ `Russh_CompletesCipher_WithOurServer("aes128-ctr","hmac-sha2-512-etm@openssh.com")` — Transport & key exchange
- ✅ `Russh_CompletesCipher_WithOurServer("aes128-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `Russh_CompletesCipher_WithOurServer("aes256-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `Russh_CompletesCipher_WithOurServer("aes256-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `Russh_CompletesCipher_WithOurServer("chacha20-poly1305@openssh.com",null)` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Russh_CompletesKeyExchange_WithOurServer("mlkem768x25519-sha256")` — Transport & key exchange

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

### libssh

- ✅ `LibSsh_LogsInWithOurKey("ecdsa-sha2-nistp256")` — Authentication
- ✅ `LibSsh_LogsInWithOurKey("ecdsa-sha2-nistp384")` — Authentication
- ✅ `LibSsh_LogsInWithOurKey("ecdsa-sha2-nistp521")` — Authentication
- ✅ `LibSsh_LogsInWithOurKey("ssh-ed25519")` — Authentication
- ✅ `LibSsh_LogsInWithOurKey("ssh-rsa")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithLibSshServer("ecdsa-sha2-nistp256")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithLibSshServer("ecdsa-sha2-nistp384")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithLibSshServer("ecdsa-sha2-nistp521")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithLibSshServer("ssh-ed25519")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithLibSshServer("ssh-rsa")` — Authentication
- ✅ `LibSsh_RejectsAWrongHostKey` — Host-key verification
- ✅ `LibSsh_VerifiesOurHostKey("ecdsa-sha2-nistp256","ecdsa-sha2-nistp256")` — Host-key verification
- ✅ `LibSsh_VerifiesOurHostKey("ecdsa-sha2-nistp384","ecdsa-sha2-nistp384")` — Host-key verification
- ✅ `LibSsh_VerifiesOurHostKey("ecdsa-sha2-nistp521","ecdsa-sha2-nistp521")` — Host-key verification
- ✅ `LibSsh_VerifiesOurHostKey("rsa-sha2-256","ssh-rsa")` — Host-key verification
- ✅ `LibSsh_VerifiesOurHostKey("rsa-sha2-512","ssh-rsa")` — Host-key verification
- ✅ `LibSsh_VerifiesOurHostKey("ssh-ed25519","ssh-ed25519")` — Host-key verification
- ✅ `OurClient_RejectsAWrongLibSshHostKey` — Host-key verification
- ✅ `LibSsh_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `LibSsh_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `OurClient_RunsCommand_OnLibSshServer("fail",42)` — Remote command execution
- ✅ `OurClient_RunsCommand_OnLibSshServer("hello",0)` — Remote command execution
- ✅ `LibSsh_TransfersFiles_OnOurServer` — SFTP
- ✅ `OurClient_TransfersFiles_WithLibSshSftpServer` — SFTP
- ✅ `LibSsh_CompletesCipher_WithOurServer("aes128-ctr","hmac-sha2-512-etm@openssh.com")` — Transport & key exchange
- ✅ `LibSsh_CompletesCipher_WithOurServer("aes128-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `LibSsh_CompletesCipher_WithOurServer("aes256-ctr","hmac-sha2-256-etm@openssh.com")` — Transport & key exchange
- ✅ `LibSsh_CompletesCipher_WithOurServer("aes256-gcm@openssh.com",null)` — Transport & key exchange
- ✅ `LibSsh_CompletesCipher_WithOurServer("chacha20-poly1305@openssh.com",null)` — Transport & key exchange
- ✅ `LibSsh_CompletesKeyExchange_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `LibSsh_CompletesKeyExchange_WithOurServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `LibSsh_CompletesKeyExchange_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `LibSsh_CompletesKeyExchange_WithOurServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `LibSsh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `LibSsh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `LibSsh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithLibSshServer("curve25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithLibSshServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithLibSshServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithLibSshServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithLibSshServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithLibSshServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithLibSshServer("ecdh-sha2-nistp521")` — Transport & key exchange

### ncclient

- ✅ `Ncclient_HoldsANetconfSession_OnOurSubsystem(base 1.0, end-of-message)` — NETCONF (RFC 6242)
- ✅ `Ncclient_HoldsANetconfSession_OnOurSubsystem(base 1.1, chunked)` — NETCONF (RFC 6242)

### wolfSSH

- ✅ `OurClient_UsesEachKeyType_WithWolfsshServer("ecdsa-sha2-nistp256")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithWolfsshServer("ecdsa-sha2-nistp384")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithWolfsshServer("ecdsa-sha2-nistp521")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithWolfsshServer("ssh-ed25519")` — Authentication
- ✅ `OurClient_UsesEachKeyType_WithWolfsshServer("ssh-rsa")` — Authentication
- ✅ `Wolfssh_LogsInWithOurKey("ecdsa-sha2-nistp256")` — Authentication
- ✅ `Wolfssh_LogsInWithOurKey("ecdsa-sha2-nistp384")` — Authentication
- ✅ `Wolfssh_LogsInWithOurKey("ecdsa-sha2-nistp521")` — Authentication
- ✅ `Wolfssh_LogsInWithOurKey("ssh-ed25519")` — Authentication
- ✅ `Wolfssh_LogsInWithOurKey("ssh-rsa")` — Authentication
- ✅ `OurClient_RejectsAWrongWolfsshHostKey` — Host-key verification
- ✅ `Wolfssh_RejectsAWrongHostKey` — Host-key verification
- ✅ `Wolfssh_VerifiesOurHostKey("ecdsa-sha2-nistp256","ecdsa-sha2-nistp256")` — Host-key verification
- ✅ `Wolfssh_VerifiesOurHostKey("ecdsa-sha2-nistp384","ecdsa-sha2-nistp384")` — Host-key verification
- ✅ `Wolfssh_VerifiesOurHostKey("ecdsa-sha2-nistp521","ecdsa-sha2-nistp521")` — Host-key verification
- ✅ `Wolfssh_VerifiesOurHostKey("rsa-sha2-256","ssh-rsa")` — Host-key verification
- ✅ `Wolfssh_VerifiesOurHostKey("rsa-sha2-512","ssh-rsa")` — Host-key verification
- ✅ `Wolfssh_VerifiesOurHostKey("ssh-ed25519","ssh-ed25519")` — Host-key verification
- ✅ `OurClient_RunsCommand_OnWolfsshServer("fail",42)` — Remote command execution
- ✅ `OurClient_RunsCommand_OnWolfsshServer("hello",0)` — Remote command execution
- ✅ `Wolfssh_RunsCommand_OnOurServer("fail",42)` — Remote command execution
- ✅ `Wolfssh_RunsCommand_OnOurServer("hello",0)` — Remote command execution
- ✅ `OurClient_TransfersFiles_WithWolfsshSftpServer` — SFTP
- ✅ `Wolfssh_TransfersFiles_OnOurServer` — SFTP
- ✅ `OurClient_CompletesCipher_WithWolfsshServer("aes128-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesCipher_WithWolfsshServer("aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithWolfsshServer("curve25519-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithWolfsshServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithWolfsshServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithWolfsshServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithWolfsshServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithWolfsshServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `OurClient_CompletesKeyExchange_WithWolfsshServer("ecdh-sha2-nistp521")` — Transport & key exchange
- ✅ `Wolfssh_CompletesCipher_WithOurServer("aes128-gcm@openssh.com")` — Transport & key exchange
- ✅ `Wolfssh_CompletesCipher_WithOurServer("aes256-gcm@openssh.com")` — Transport & key exchange
- ✅ `Wolfssh_CompletesKeyExchange_WithOurServer("curve25519-sha256")` — Transport & key exchange
- ✅ `Wolfssh_CompletesKeyExchange_WithOurServer("curve25519-sha256@libssh.org")` — Transport & key exchange
- ✅ `Wolfssh_CompletesKeyExchange_WithOurServer("diffie-hellman-group14-sha256")` — Transport & key exchange
- ✅ `Wolfssh_CompletesKeyExchange_WithOurServer("diffie-hellman-group16-sha512")` — Transport & key exchange
- ✅ `Wolfssh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp256")` — Transport & key exchange
- ✅ `Wolfssh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp384")` — Transport & key exchange
- ✅ `Wolfssh_CompletesKeyExchange_WithOurServer("ecdh-sha2-nistp521")` — Transport & key exchange

## Legend

| Mark | Meaning |
|---|---|
| ✅ | The peer and HermodSSH agreed. |
| ❌ | The test ran and disagreed — a genuine interop defect. |
| ⚪ | Not exercised: the peer or a tool it needs was unavailable on this machine. **No evidence either way.** |
| – | No test covers this capability for this peer yet. |
