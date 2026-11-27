#
# setup-windows.ps1 - provision the interop peers that run natively on Windows.
#
# AsyncSSH, Paramiko and ncclient are Python and need no Linux. This script puts them into a virtual
# environment of their own at .venv-interop-win next to this script, where PythonPeers finds them and
# runs them as Windows processes on the same loopback as our server - no WSL, no firewall rule, no
# address to probe. The Go harness needs nothing from here: GoCryptoSshInteropTests builds it with any
# go.exe on the PATH.
#
# The Linux build of the same peers (setup-wsl.sh, .venv-interop) stays what the Debian CI leg runs.
# Where both exist on a Windows machine, the native one is used.
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

$venv       = Join-Path $PSScriptRoot '.venv-interop-win'
$venvPython = Join-Path $venv 'Scripts\python.exe'

function Invoke-Checked {
    param([string] $What, [string] $Program, [string[]] $Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed with exit code $LASTEXITCODE."
    }
}

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

# No double quotes in the snippet: Windows PowerShell 5.1 does not escape them for a native program.
Invoke-Checked 'Reporting the versions' $venvPython @('-c', @'
import sys, asyncssh, paramiko, ncclient
print('  Python       ' + sys.version.split()[0])
print('  AsyncSSH     ' + asyncssh.__version__)
print('  Paramiko     ' + paramiko.__version__)
print('  ncclient     ' + ncclient.__version__)
'@)

$go = Get-Command go.exe -ErrorAction SilentlyContinue
if ($go) {
    Write-Host "  Go           $(& $go.Source version)"
}
else {
    Write-Host '  Go           not on the PATH - GoCryptoSshInteropTests will use WSL or skip'
}
