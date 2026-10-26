# Windows PowerShell 5.1 compatible. Private keys stay on this computer.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-MyVpnEndpoint {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Endpoint)

    # Never let a pasted configuration line become part of another setting.
    if ($Endpoint -match '[\r\n\x00-\x1f\x7f]') {
        throw 'The server endpoint must be a single hostname or IP address, with an optional port.'
    }
    $value = $Endpoint.Trim()
    $hostName = ''
    $portNumber = 51820
    $isIpv6 = $false
    if ($value -match '^\[([^\]]+)\](?::([0-9]{1,5}))?$') {
        $hostName = $Matches[1]
        if ($Matches[2]) { $portNumber = [int]$Matches[2] }
        $address = $null
        if ($hostName.Contains('%') -or
            -not [System.Net.IPAddress]::TryParse($hostName, [ref]$address) -or
            $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            throw 'The bracketed endpoint must contain a valid IPv6 address without a zone identifier.'
        }
        $hostName = $address.ToString()
        $isIpv6 = $true
    } elseif ($value -match '^([^:]+)(?::([0-9]{1,5}))?$') {
        $hostName = $Matches[1]
        if ($Matches[2]) { $portNumber = [int]$Matches[2] }
        if ($hostName.Length -gt 253 -or $hostName -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$') {
            throw 'Use a hostname, an IPv4 address, or a bracketed IPv6 address; do not include http:// or a path.'
        }
        if ($hostName -match '^[0-9.]+$') {
            $address = $null
            if (-not [System.Net.IPAddress]::TryParse($hostName, [ref]$address) -or
                $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
                $address.ToString() -ne $hostName) {
                throw 'The IPv4 address must use four decimal octets, for example 192.168.1.20.'
            }
        }
        $hostName = $hostName.ToLowerInvariant()
    } else {
        throw 'Use a hostname or IP address, optionally followed by :51820. Put IPv6 addresses in brackets.'
    }
    if ($portNumber -lt 1 -or $portNumber -gt 65535) {
        throw 'The endpoint port must be between 1 and 65535.'
    }
    if ($isIpv6) { return ('[{0}]:{1}' -f $hostName, $portNumber) }
    return ('{0}:{1}' -f $hostName, $portNumber)
}

function Test-MyVpnEndpoint {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Endpoint)
    try {
        $null = ConvertTo-MyVpnEndpoint -Endpoint $Endpoint
        return $true
    } catch { return $false }
}

function Test-MyVpnDnsServer {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$DnsServer)
    $address = $null
    return ($DnsServer -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' -and
        [System.Net.IPAddress]::TryParse($DnsServer, [ref]$address) -and
        $address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
        $address.ToString() -eq $DnsServer)
}

function Get-WireGuardInstallation {
    [CmdletBinding()]
    param()
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'The Windows WireGuard application is required. Run this on your Windows PC.'
    }
    $candidates = @()
    foreach ($basePath in @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($basePath) { $candidates += (Join-Path $basePath 'WireGuard') }
    }
    foreach ($directory in ($candidates | Select-Object -Unique)) {
        $wireGuardExe = Join-Path $directory 'wireguard.exe'
        $wgExe = Join-Path $directory 'wg.exe'
        if ((Test-Path -LiteralPath $wireGuardExe -PathType Leaf) -and
            (Test-Path -LiteralPath $wgExe -PathType Leaf)) {
            return [pscustomobject]@{ WireGuardExe = $wireGuardExe; WgExe = $wgExe }
        }
    }
    throw 'Install the official WireGuard for Windows application from https://www.wireguard.com/install/ and launch MyVPN again.'
}

function Invoke-MyVpnWgKey {
    param(
        [Parameter(Mandatory = $true)][string]$WgExe,
        [Parameter(Mandatory = $true)][ValidateSet('genkey', 'pubkey')][string]$Operation,
        [string]$InputKey
    )
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $WgExe
    $startInfo.Arguments = $Operation
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        $null = $process.Start()
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        if ($Operation -eq 'pubkey') { $process.StandardInput.WriteLine($InputKey) }
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            throw 'WireGuard key generation timed out.'
        }
        $result = $outputTask.GetAwaiter().GetResult().Trim()
        $null = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw 'WireGuard could not generate the configuration keys.' }
        if ($result -notmatch '^[A-Za-z0-9+/]{43}=$' -or [Convert]::FromBase64String($result).Length -ne 32) {
            throw 'WireGuard returned an invalid key.'
        }
        return $result
    } finally { $process.Dispose() }
}

function New-MyVpnPrivateDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Configuration generation requires Windows filesystem permissions.'
    }
    if (Test-Path -LiteralPath $Path) {
        throw 'Choose a new output folder. Existing VPN files are never overwritten.'
    }
    $directory = New-Item -ItemType Directory -Path $Path -ErrorAction Stop
    # Break inherited access BEFORE any private key is written.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl.SetOwner($currentUser)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @($currentUser,
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')),
        (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inheritance, $propagation, $allow)
        $null = $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $directory.FullName -AclObject $acl -ErrorAction Stop
    return $directory.FullName
}

function Write-MyVpnNewFile {
    param([string]$Path, [string]$Content)
    $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $bytes = $encoding.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
    } finally { $stream.Dispose() }
}

function New-MyVpnConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Endpoint,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [ValidatePattern('^[A-Za-z0-9_-]{1,32}$')][string]$ClientName = 'windows-pc',
        [string]$DnsServer = '1.1.1.1',
        [switch]$SplitTunnel
    )
    $normalizedEndpoint = ConvertTo-MyVpnEndpoint -Endpoint $Endpoint
    $listenPort = [int]$normalizedEndpoint.Substring($normalizedEndpoint.LastIndexOf(':') + 1)
    if (-not (Test-MyVpnDnsServer -DnsServer $DnsServer)) {
        throw 'The DNS server must be a single IPv4 address, such as 1.1.1.1.'
    }
    $fullPath = [System.IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $fullPath) {
        throw 'Choose a new output folder. Existing VPN files are never overwritten.'
    }
    $installation = Get-WireGuardInstallation
    $serverPrivateKey = Invoke-MyVpnWgKey -WgExe $installation.WgExe -Operation genkey
    $serverPublicKey = Invoke-MyVpnWgKey -WgExe $installation.WgExe -Operation pubkey -InputKey $serverPrivateKey
    $clientPrivateKey = Invoke-MyVpnWgKey -WgExe $installation.WgExe -Operation genkey
    $clientPublicKey = Invoke-MyVpnWgKey -WgExe $installation.WgExe -Operation pubkey -InputKey $clientPrivateKey
    $directory = New-MyVpnPrivateDirectory -Path $fullPath
    $serverConfig = @"
[Interface]
Address = 10.66.66.1/24, fd66:66:66::1/64
ListenPort = $listenPort
PrivateKey = $serverPrivateKey

[Peer]
# $ClientName
PublicKey = $clientPublicKey
AllowedIPs = 10.66.66.2/32, fd66:66:66::2/128
"@
    $routes = '0.0.0.0/0, ::/0'
    $dnsLine = "DNS = $DnsServer`n"
    if ($SplitTunnel) {
        $routes = '10.66.66.0/24, fd66:66:66::/64'
        $dnsLine = ''
    }
    $clientConfig = @"
[Interface]
Address = 10.66.66.2/32, fd66:66:66::2/128
PrivateKey = $clientPrivateKey
$dnsLine
[Peer]
PublicKey = $serverPublicKey
Endpoint = $normalizedEndpoint
AllowedIPs = $routes
PersistentKeepalive = 25
"@
    $serverPath = Join-Path $directory 'wg0.conf'
    $clientPath = Join-Path $directory 'myvpn.conf'
    $metadataPath = Join-Path $directory 'setup.json'
    $metadata = [ordered]@{
        schemaVersion = 1
        createdUtc = [DateTime]::UtcNow.ToString('o')
        endpoint = $normalizedEndpoint
        serverListenPort = $listenPort
        clientName = $ClientName
        splitTunnel = [bool]$SplitTunnel
        ipv6Internet = $false
        serverConfig = 'wg0.conf'
        clientConfig = 'myvpn.conf'
    } | ConvertTo-Json
    Write-MyVpnNewFile -Path $serverPath -Content ($serverConfig.Replace("`r`n", "`n") + "`n")
    Write-MyVpnNewFile -Path $clientPath -Content ($clientConfig.Replace("`r`n", "`n") + "`n")
    Write-MyVpnNewFile -Path $metadataPath -Content ($metadata + "`n")
    return [pscustomobject]@{
        OutputDirectory = $directory
        ServerConfigPath = $serverPath
        ClientConfigPath = $clientPath
        MetadataPath = $metadataPath
        Endpoint = $normalizedEndpoint
        ClientName = $ClientName
    }
}

Export-ModuleMember -Function Get-WireGuardInstallation, New-MyVpnConfiguration, ConvertTo-MyVpnEndpoint, Test-MyVpnEndpoint, Test-MyVpnDnsServer
