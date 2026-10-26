#requires -Version 5.1
# Real wg.exe key generation and NTFS permissions; never starts a VPN service.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this acceptance check on Windows with the official WireGuard app installed.' }
Import-Module (Join-Path $PSScriptRoot '..\windows\MyVPN.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\windows\MyVPN.Controller.psm1') -Force
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('myvpn-acceptance-' + [Guid]::NewGuid().ToString('N'))
$checks = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:checks++
}
function Read-Setting {
    param([string]$Text, [string]$Name)
    $pattern = '(?m)^' + [regex]::Escape($Name) + '\s*=\s*(\S+)\s*$'
    if ($Text -notmatch $pattern) { throw ('Missing test setting: ' + $Name) }
    return $Matches[1]
}
try {
    $installation = Get-WireGuardInstallation
    $result = New-MyVpnConfiguration -Endpoint '192.0.2.10:51821' -OutputDirectory $temporaryRoot
    $server = [IO.File]::ReadAllText($result.ServerConfigPath)
    $client = [IO.File]::ReadAllText($result.ClientConfigPath)
    Assert-True (Test-MyVpnClientConfiguration -Content $client) 'Generated client was rejected by the controller.'
    Assert-True ($server -match '(?m)^ListenPort = 51821$') 'Custom listener does not match the endpoint.'
    $serverPrivate = Read-Setting $server 'PrivateKey'
    $clientPrivate = Read-Setting $client 'PrivateKey'
    $serverPublicInClient = Read-Setting $client 'PublicKey'
    $clientPublicInServer = Read-Setting $server 'PublicKey'
    $actualServerPublic = ($serverPrivate | & $installation.WgExe pubkey 2>$null | Out-String).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $actualServerPublic -ceq $serverPublicInClient) 'Server key does not match client peer.'
    $actualClientPublic = ($clientPrivate | & $installation.WgExe pubkey 2>$null | Out-String).Trim()
    Assert-True ($LASTEXITCODE -eq 0 -and $actualClientPublic -ceq $clientPublicInServer) 'Client key does not match server peer.'
    Assert-True ($serverPrivate -cne $clientPrivate) 'Server and client private keys must differ.'
    $allowedSids = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
    foreach ($path in @($temporaryRoot, $result.ServerConfigPath, $result.ClientConfigPath)) {
        $acl = Get-Acl -LiteralPath $path
        foreach ($entry in $acl.Access) {
            if ($entry.AccessControlType -eq 'Allow') {
                $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                Assert-True ($allowedSids -contains $sid) 'Unexpected identity can read generated keys.'
            }
        }
    }
    $refused = $false
    try { $null = New-MyVpnConfiguration -Endpoint '192.0.2.10' -OutputDirectory $temporaryRoot } catch { $refused = $true }
    Assert-True $refused 'Existing generated files were not protected against overwrite.'
    Assert-True ([IO.File]::ReadAllText($result.ServerConfigPath) -ceq $server) 'Existing server keys changed.'
    Write-Output ('Windows native acceptance: {0} checks passed. No VPN service was started.' -f $checks)
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
