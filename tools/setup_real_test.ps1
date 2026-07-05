# Usage:
#   .\tools\setup_real_test.ps1 -PiIp 172.201.0.11 -Clean
#
# Generate runtime material and copy server-runtime/ to a remote server VM:
#   .\tools\setup_real_test.ps1 `
#     -PiIp 172.201.0.11 `
#     -ServerSshTarget user@SERVER_VM_IP `
#     -ServerRemotePath "~/matzpin" `
#     -Clean
#
# Run from the project root. Use the IP address that the remote server uses to
# reach this Pi/PC, such as the VPN IP.

param(
    [Parameter(Mandatory = $true)]
    [string]$PiIp,

    [string]$Python = ".\.venv\Scripts\python.exe",
    [string]$AuthorityRoot = "authority-dev",
    [string]$PiRoot = "pi-runtime",
    [string]$ServerRoot = "server-runtime",
    [int]$PiPort = 18443,
    [int]$ClientPort = 19443,
    [string]$SenderId = "server",
    [string]$KeyId = "k1",
    [string]$ServerSshTarget = "",
    [string]$ServerRemotePath = "~/matzpin",
    [string]$ServerVenvActivate = "./venv/bin/activate",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==> $Name"
    & $Command
}

if (-not (Test-Path $Python)) {
    throw "Python executable was not found: $Python"
}

if ($Clean) {
    foreach ($path in @($AuthorityRoot, $PiRoot, $ServerRoot)) {
        if (Test-Path $path) {
            Write-Host "Removing $path"
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
}

Invoke-Step "Generate authority" {
    & $Python tools/generate_dev_security.py `
        --component authority `
        --out $AuthorityRoot
}

Invoke-Step "Generate Pi runtime with IP SAN $PiIp" {
    & $Python tools/generate_dev_security.py `
        --component pi `
        --out $PiRoot `
        --authority-root $AuthorityRoot `
        --pi-ip $PiIp `
        --pi-port $PiPort `
        --client-port $ClientPort `
        --sender-id $SenderId `
        --key-id $KeyId
}

Invoke-Step "Generate server runtime for Pi $PiIp" {
    & $Python tools/generate_dev_security.py `
        --component server `
        --out $ServerRoot `
        --authority-root $AuthorityRoot `
        --pi-public-key "$PiRoot/exchange/pi_x25519.pub" `
        --pi-ip $PiIp `
        --pi-port $PiPort `
        --client-port $ClientPort `
        --sender-id $SenderId `
        --key-id $KeyId
}

Invoke-Step "Trust server signing key on Pi" {
    & $Python tools/generate_dev_security.py `
        --component trust-server `
        --out $PiRoot `
        --server-public-key "$ServerRoot/exchange/${SenderId}_${KeyId}.pem" `
        --sender-id $SenderId `
        --key-id $KeyId `
        --no-config
}

if ($ServerSshTarget) {
    Invoke-Step "Copy server runtime to remote server $ServerSshTarget" {
        ssh $ServerSshTarget "mkdir -p $ServerRemotePath"
        scp -r $ServerRoot "${ServerSshTarget}:$ServerRemotePath/"
    }
}

Write-Host ""
Write-Host "Setup complete."
Write-Host ""
Write-Host "Pi config:     $PiRoot/config/pi.local.json"
Write-Host "Server config: $ServerRoot/config/server.local.json"
Write-Host ""
Write-Host "Run downstream demi client on the Pi/PC:"
Write-Host "`$env:ENCRYPTOR_DEMI_CLIENT_CONFIG='$PiRoot/config/client.local.json'"
Write-Host "& $Python -m encryptor_demi_client.main --config $PiRoot/config/client.local.json"
Write-Host ""
Write-Host "Run Pi daemon on the Pi/PC:"
Write-Host "`$env:ENCRYPTOR_PI_CONFIG='$PiRoot/config/pi.local.json'"
Write-Host "& $Python -m encryptor_pi.main"
Write-Host ""
if ($ServerSshTarget) {
    Write-Host "Server runtime was copied to:"
    Write-Host "${ServerSshTarget}:$ServerRemotePath/$ServerRoot"
    Write-Host ""
    Write-Host "Run this on the remote server VM:"
    Write-Host "cd $ServerRemotePath"
    Write-Host "source $ServerVenvActivate"
    Write-Host "python -m encryptor_server.main `"hello from real server`" --config $ServerRoot/config/server.local.json"
} else {
    Write-Host "Copy $ServerRoot to the server VM project root, then run there:"
    Write-Host "source $ServerVenvActivate"
    Write-Host "python -m encryptor_server.main `"hello from real server`" --config $ServerRoot/config/server.local.json"
    Write-Host ""
    Write-Host "Or rerun this script with:"
    Write-Host "-ServerSshTarget user@server-ip"
}
