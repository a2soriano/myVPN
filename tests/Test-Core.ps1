# No Pester dependency, no administrator permissions, no WireGuard installation.
# Run: powershell.exe -NoProfile -File .\tests\Test-Core.ps1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '..\windows\MyVPN.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\windows\MyVPN.Controller.psm1') -Force
$script:Passed = 0
function Assert-Equal {
    param($Actual, $Expected, [string]$Label)
    if ($Actual -ne $Expected) { throw "$Label failed: expected '$Expected', got '$Actual'." }
    $script:Passed++
}

Assert-Equal (ConvertTo-MyVpnEndpoint 'vpn.example.com') 'vpn.example.com:51820' 'Default port'
Assert-Equal (ConvertTo-MyVpnEndpoint 'VPN.Example.COM:12345') 'vpn.example.com:12345' 'Explicit port'
Assert-Equal (ConvertTo-MyVpnEndpoint '192.168.1.20') '192.168.1.20:51820' 'LAN test endpoint'
Assert-Equal (ConvertTo-MyVpnEndpoint '[2001:db8::1]') '[2001:db8::1]:51820' 'IPv6 endpoint'
Assert-Equal (ConvertTo-MyVpnEndpoint '[::1]:65535') '[::1]:65535' 'Maximum port'
Assert-Equal (ConvertTo-MyVpnEndpoint '  localhost  ') 'localhost:51820' 'Outer spaces'
foreach ($invalid in @('', 'http://vpn.example.com', 'example.com/path', 'example.com:0',
    'example.com:65536', 'example.com:999999', 'example.com:-1', 'example.com:abc',
    '2001:db8::1', '[127.0.0.1]', '[fe80::1%1]', '999.1.1.1', '127.1', '0127.0.0.1',
    '-bad.example', 'bad-.example', 'bad..example', 'vpn.example.com # comment',
    "vpn.example.com`nPrivateKey = injected", "vpn.example.com`r", "vpn.example.com`t", 'vpn;whoami')) {
    Assert-Equal (Test-MyVpnEndpoint $invalid) $false 'Reject invalid endpoint'
}
foreach ($valid in @('1.1.1.1', '8.8.8.8', '192.168.1.1')) {
    Assert-Equal (Test-MyVpnDnsServer $valid) $true 'Accept IPv4 DNS'
}
foreach ($invalid in @('', 'localhost', 'https://dns.example.com', '1.1.1.1,8.8.8.8',
    '999.1.1.1', '1.1.1', '01.1.1.1', '::1', "1.1.1.1`nPostUp = cmd")) {
    Assert-Equal (Test-MyVpnDnsServer $invalid) $false 'Reject invalid DNS'
}

# Exercise real file generation with fixture key output and a temporary directory.
# Windows key generation and ACL enforcement are deliberately NOT simulated as
# verified OS behavior. Those require the Windows acceptance checks in README.
$module = Get-Module MyVPN.Core
& $module {
    $script:TestKeyCalls = 0
    function script:Get-WireGuardInstallation { return [pscustomobject]@{ WgExe = 'fixture-only'; WireGuardExe = 'fixture-only' } }
    function script:Invoke-MyVpnWgKey {
        param($WgExe, $Operation, $InputKey)
        $script:TestKeyCalls++
        $bytes = New-Object byte[] 32
        for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [byte]$script:TestKeyCalls }
        return [Convert]::ToBase64String($bytes)
    }
    function script:New-MyVpnPrivateDirectory {
        param($Path)
        return [System.IO.Directory]::CreateDirectory($Path).FullName
    }
}
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('myvpn-core-tests-' + [Guid]::NewGuid().ToString('N'))
try {
    $full = New-MyVpnConfiguration -Endpoint 'vpn.example.com:443' -OutputDirectory (Join-Path $temporaryRoot 'full')
    $server = [System.IO.File]::ReadAllText($full.ServerConfigPath)
    $client = [System.IO.File]::ReadAllText($full.ClientConfigPath)
    $metadata = [System.IO.File]::ReadAllText($full.MetadataPath) | ConvertFrom-Json
    Assert-Equal (Test-MyVpnClientConfiguration -Content $client) $true 'Generated full profile is accepted by controller'
    $serverRejected = $false
    try { $null = Test-MyVpnClientConfiguration -Content $server } catch { $serverRejected = $true }
    Assert-Equal $serverRejected $true 'Server profile cannot be mistaken for a usable PC profile'
    Assert-Equal ($server -match '(?m)^ListenPort = 443$') $true 'Server listener matches selected endpoint port'
    Assert-Equal ($client -match '(?m)^Endpoint = vpn\.example\.com:443$') $true 'Selected endpoint port'
    Assert-Equal ($client -match '(?m)^AllowedIPs = 0\.0\.0\.0/0, ::/0$') $true 'Full tunnel covers both IP families'
    Assert-Equal ($client -match '(?m)^DNS = 1\.1\.1\.1$') $true 'Full tunnel DNS'
    Assert-Equal ($server -match '(?m)^AllowedIPs = 10\.66\.66\.2/32, fd66:66:66::2/128$') $true 'Only this client is allowed'
    Assert-Equal $metadata.endpoint 'vpn.example.com:443' 'Metadata endpoint'
    Assert-Equal $metadata.serverListenPort 443 'Metadata port matches listener'
    Assert-Equal $metadata.splitTunnel $false 'Metadata full tunnel flag'
    Assert-Equal ($metadata.PSObject.Properties.Name -match '(?i)private|secret') $null 'No secrets in metadata schema'
    Assert-Equal ([System.IO.File]::ReadAllBytes($full.ClientConfigPath)[0]) 91 'Config is UTF8 without BOM'
    Assert-Equal ($full.PSObject.Properties.Name -match '(?i)private|secret') $null 'Return value contains paths rather than private keys'
    $originalClient = $client
    $existingRejected = $false
    try { $null = New-MyVpnConfiguration -Endpoint 'other.example.com' -OutputDirectory $full.OutputDirectory }
    catch { $existingRejected = $true }
    Assert-Equal $existingRejected $true 'Existing output directory refused'
    Assert-Equal ([System.IO.File]::ReadAllText($full.ClientConfigPath)) $originalClient 'Existing profile preserved'
    $split = New-MyVpnConfiguration -Endpoint '192.168.1.20' -OutputDirectory (Join-Path $temporaryRoot 'split') -SplitTunnel
    $splitClient = [System.IO.File]::ReadAllText($split.ClientConfigPath)
    Assert-Equal (Test-MyVpnClientConfiguration -Content $splitClient) $true 'Generated split profile is accepted by controller'
    Assert-Equal ($splitClient -match '(?m)^AllowedIPs = 10\.66\.66\.0/24, fd66:66:66::/64$') $true 'LAN lab uses split tunnel'
    Assert-Equal ([System.IO.File]::ReadAllText($split.ServerConfigPath) -match '(?m)^ListenPort = 51820$') $true 'Default server listener'
    Assert-Equal ($splitClient -match '(?m)^DNS\s*=') $false 'LAN lab preserves normal DNS'
    Assert-Equal ($splitClient -match '0\.0\.0\.0/0|::/0') $false 'LAN lab preserves internet routing'
    $badPath = Join-Path $temporaryRoot 'must-not-exist'
    $injectionRejected = $false
    try { $null = New-MyVpnConfiguration -Endpoint "vpn.example.com`nPostUp=bad" -OutputDirectory $badPath }
    catch { $injectionRejected = $true }
    Assert-Equal $injectionRejected $true 'Config injection refused by generation API'
    Assert-Equal (Test-Path -LiteralPath $badPath) $false 'Invalid input writes no files'
    Assert-Equal (& $module { $script:TestKeyCalls }) 8 'Invalid and duplicate requests generate no keys'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
Write-Host "$script:Passed core checks passed. Fixture configurations were removed; no network settings changed."
