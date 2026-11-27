#
# setup-windows.ps1 - provision the interop peers that run natively on Windows.
#
# None of these peers needs Linux, so on Windows they run as ordinary processes on the same loopback as
# our server - no WSL, no firewall rule, no address to probe (PeerPlatform.cs):
#
#   - AsyncSSH, Paramiko and ncclient go into a virtual environment of their own at .venv-interop-win.
#   - Apache MINA SSHD and JSch are built with any JDK on the PATH, against the jars this script fetches
#     from Maven Central into .java-interop-win: the releases Debian 13 ships, each checked against a
#     pinned SHA-256 and stored under the name Debian gives it.
#   - Russh is built with any cargo on the PATH; this script installs the toolchain
#     russh/rust-toolchain.toml pins, as setup-wsl.sh does in Linux.
#   - The Go harness needs nothing from here: GoCryptoSshInteropTests builds it with any go.exe on the PATH.
#
# The Linux build of the same peers (setup-wsl.sh) stays what the Debian CI leg runs. Where both exist
# on a Windows machine, the native one is used.
#
# Written for Windows PowerShell 5.1 as well as PowerShell 7. Idempotent: safe to re-run.
#
# Usage:   .\setup-windows.ps1                      # the newest Python the py launcher knows
#          .\setup-windows.ps1 -Python C:\Python312\python.exe
#

param(
    [string] $Python
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'     # Invoke-WebRequest in 5.1 is slow while it draws a progress bar

$venv       = Join-Path $PSScriptRoot '.venv-interop-win'
$venvPython = Join-Path $venv 'Scripts\python.exe'
$jars       = Join-Path $PSScriptRoot '.java-interop-win'

function Invoke-Checked {
    param([string] $What, [string] $Program, [string[]] $Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE."
    }
}


# ---- Python: AsyncSSH, Paramiko, ncclient -------------------------------------------------------------

if (-not (Test-Path $venvPython)) {

    # The py launcher is what a python.org install puts on the PATH; 'python' alone may be the
    # Microsoft Store alias, which opens the Store instead of running anything.
    if (-not $Python) {
        if (Get-Command py.exe -ErrorAction SilentlyContinue) {
            Write-Host '[setup] Creating .venv-interop-win with the py launcher ...'
            Invoke-Checked 'Creating the virtual environment' 'py.exe' @('-3', '-m', 'venv', $venv)
        }
        elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
            Write-Host '[setup] Creating .venv-interop-win with python.exe ...'
            Invoke-Checked 'Creating the virtual environment' 'python.exe' @('-m', 'venv', $venv)
        }
        else {
            throw 'No Python found: install one from python.org, or pass -Python <path to python.exe>.'
        }
    }
    else {
        Write-Host "[setup] Creating .venv-interop-win with $Python ..."
        Invoke-Checked 'Creating the virtual environment' $Python @('-m', 'venv', $venv)
    }

}

# --prefer-binary for the same reason as in setup-wsl.sh: a release whose wheels are still being
# uploaded must not make pip build lxml or cryptography from source.
Write-Host '[setup] Installing AsyncSSH, Paramiko and ncclient ...'
Invoke-Checked 'Upgrading pip'          $venvPython @('-m', 'pip', 'install', '--quiet', '--upgrade', 'pip')
Invoke-Checked 'Installing the peers'   $venvPython @('-m', 'pip', 'install', '--quiet', '--prefer-binary', 'asyncssh', 'paramiko', 'ncclient')


# ---- Java: the jars of Apache MINA SSHD and JSch -------------------------------------------------------

# The releases Debian 13 ships (MINA SSHD 2.13.2, JSch 0.2.19 - Matthias Wiede's fork), with the
# logging facade and the providers they find Ed25519 and friends through. Name = Debian's file name in
# /usr/share/java, which is what JavaToolchain.Jar looks for.
$javaJars = @(
    @{ Name = 'sshd-common';  Path = 'org/apache/sshd/sshd-common/2.13.2/sshd-common-2.13.2.jar';             Sha256 = 'c86d499b2c77ce8e76e5fc5e4a1deb9944303ba951b166d30bbaefbcd74d5702' },
    @{ Name = 'sshd-core';    Path = 'org/apache/sshd/sshd-core/2.13.2/sshd-core-2.13.2.jar';                 Sha256 = '1368fe3685a6def97e7a13187041296d58c08c9c6c1346cb08d8d7fb4ac37353' },
    @{ Name = 'sshd-sftp';    Path = 'org/apache/sshd/sshd-sftp/2.13.2/sshd-sftp-2.13.2.jar';                 Sha256 = '1f47db3d930a7fd78f9f38b97cf007382cacd360968ac0a6eee4fc5a4aff1311' },
    @{ Name = 'slf4j-api';    Path = 'org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar';                       Sha256 = 'd3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0' },
    @{ Name = 'slf4j-nop';    Path = 'org/slf4j/slf4j-nop/1.7.36/slf4j-nop-1.7.36.jar';                       Sha256 = 'c214958b07816cb4412b30c7bdbd4308ffdc6ba2a83767b8f3a9229cbd9274d6' },
    @{ Name = 'slf4j-simple'; Path = 'org/slf4j/slf4j-simple/1.7.36/slf4j-simple-1.7.36.jar';                 Sha256 = '2f39bed943d624dfa8f4102d0571283a10870b6aa36f197a8a506f147010c10f' },
    @{ Name = 'eddsa';        Path = 'net/i2p/crypto/eddsa/0.3.0/eddsa-0.3.0.jar';                            Sha256 = '4dda1120db856640dbec04140ed23242215a075fe127bdefa0dcfa29fb31267d' },
    @{ Name = 'bcprov';       Path = 'org/bouncycastle/bcprov-jdk18on/1.80/bcprov-jdk18on-1.80.jar';          Sha256 = 'e8ad209f8c58d291a37ca9750e9e9fac60596956c983e49dd8282381dd8b3249' },
    @{ Name = 'bcpkix';       Path = 'org/bouncycastle/bcpkix-jdk18on/1.80/bcpkix-jdk18on-1.80.jar';          Sha256 = '4f4ba6a92617ea19dc183f0fa5db492eee426fdde2a0a2d6c94777ffd1af6413' },
    @{ Name = 'bcutil';       Path = 'org/bouncycastle/bcutil-jdk18on/1.80/bcutil-jdk18on-1.80.jar';          Sha256 = '22eca687f7955411f456af33e6ea8e68fc73cd80cb8b32aa5f7a8b1827d7c678' },
    @{ Name = 'jsch';         Path = 'com/github/mwiede/jsch/0.2.19/jsch-0.2.19.jar';                         Sha256 = '259e5ddba9790df5a1f4a54348205284fe043da2e934c68daca86e325126f79a' }
)

# Windows PowerShell 5.1 may still offer TLS 1.0 first, which Maven Central refuses.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

New-Item -ItemType Directory -Force -Path $jars | Out-Null
Write-Host '[setup] Fetching the jars of MINA SSHD and JSch ...'

foreach ($jar in $javaJars) {

    $target = Join-Path $jars ($jar.Name + '.jar')

    if ((Test-Path $target) -and ((Get-FileHash -Algorithm SHA256 $target).Hash -eq $jar.Sha256)) {
        continue
    }

    $download = "$target.download"
    Invoke-WebRequest -UseBasicParsing -Uri ('https://repo1.maven.org/maven2/' + $jar.Path) -OutFile $download

    $actual = (Get-FileHash -Algorithm SHA256 $download).Hash
    if ($actual -ne $jar.Sha256) {
        Remove-Item $download
        throw "$($jar.Path) has SHA-256 $actual, not the pinned $($jar.Sha256)."
    }

    Move-Item -Force $download $target

}


# ---- Rust: the toolchain Russh is built with -----------------------------------------------------------

$rustup = Get-Command rustup.exe -ErrorAction SilentlyContinue
if ($rustup) {
    $channel = (Select-String -Path (Join-Path $PSScriptRoot 'russh\rust-toolchain.toml') -Pattern '^channel\s*=\s*"(.+)"').Matches[0].Groups[1].Value
    Write-Host "[setup] Installing Rust $channel for the Russh peer ..."
    Invoke-Checked 'Installing the Rust toolchain' $rustup.Source @('toolchain', 'install', $channel, '--profile', 'minimal', '--no-self-update')
}


# ---- What is there now ---------------------------------------------------------------------------------

# No double quotes in the snippet: Windows PowerShell 5.1 does not escape them for a native program.
Invoke-Checked 'Reporting the versions' $venvPython @('-c', @'
import sys, asyncssh, paramiko, ncclient
print('  Python       ' + sys.version.split()[0])
print('  AsyncSSH     ' + asyncssh.__version__)
print('  Paramiko     ' + paramiko.__version__)
print('  ncclient     ' + ncclient.__version__)
'@)

Write-Host '  MINA SSHD    2.13.2, JSch 0.2.19 (in .java-interop-win)'

$javac = Get-Command javac.exe -ErrorAction SilentlyContinue
if ($javac) {
    # No 2>&1: under 5.1 and 'Stop' a redirected stderr line is a terminating error. javac writes its
    # version to stdout anyway.
    Write-Host "  Java         $(& $javac.Source -version)"
}
else {
    Write-Host '  Java         no javac.exe on the PATH - MinaSshd and Jsch will use WSL or skip'
}

if ($rustup) {
    Write-Host "  Rust         $channel (rustup)"
}
else {
    Write-Host '  Rust         no rustup.exe on the PATH - Russh will use WSL or skip'
}

$go = Get-Command go.exe -ErrorAction SilentlyContinue
if ($go) {
    Write-Host "  Go           $(& $go.Source version)"
}
else {
    Write-Host '  Go           not on the PATH - GoCryptoSsh will use WSL or skip'
}
