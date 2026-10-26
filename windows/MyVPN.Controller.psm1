Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:TunnelName = 'myvpn-desktop'
$script:ServiceName = 'WireGuardTunnel$myvpn-desktop'

function Assert-MyVpnWindows {
    if ($env:OS -ne 'Windows_NT') { throw 'The VPN controls require Windows 10 or Windows 11.' }
}

function Set-MyVpnPrivateDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'The MyVPN data location must be a normal directory, not a link.'
        }
    } else {
        [void][IO.Directory]::CreateDirectory($Path)
    }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($sid in @($currentUser, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner($currentUser)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Initialize-MyVpnState {
    Assert-MyVpnWindows
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { throw 'Windows did not provide a local application data directory.' }
    $root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'MyVPN'))
    Set-MyVpnPrivateDirectory -Path $root
    $profile = Join-Path $root ($script:TunnelName + '.conf')
    foreach ($file in @($profile, (Join-Path $root 'ownership.json'))) {
        if (Test-Path -LiteralPath $file) {
            $item = Get-Item -LiteralPath $file -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'MyVPN data files must be normal files, not links or directories.'
            }
        }
    }
    [pscustomobject]@{
        RootDirectory = $root
        ProfilePath = $profile
        HasProfile = [IO.File]::Exists($profile)
    }
}

function Test-MyVpnIpAddress {
    param([string]$Value)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($Value -notmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$') { return $false }
    } elseif ($Value -notmatch ':' -or $Value -match '%') { return $false }
    return $true
}

function Test-MyVpnCidr {
    param([string]$Value)
    if ($Value -notmatch '^([^/]+)/([0-9]{1,3})$') { return $false }
    $address = $Matches[1]
    $prefix = [int]$Matches[2]
    if (-not (Test-MyVpnIpAddress $address)) { return $false }
    $ip = [Net.IPAddress]::Parse($address)
    $maximum = 128
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { $maximum = 32 }
    return ($prefix -le $maximum)
}

function Test-MyVpnProfileEndpoint {
    param([string]$Value)
    $hostPart = ''
    $portPart = ''
    if ($Value -match '^\[([0-9A-Fa-f:]+)\]:([0-9]{1,5})$') {
        $hostPart = $Matches[1]
        $portPart = $Matches[2]
        if (-not (Test-MyVpnIpAddress $hostPart) -or $hostPart -notmatch ':') { return $false }
    } elseif ($Value -match '^([^:\s]+):([0-9]{1,5})$') {
        $hostPart = $Matches[1]
        $portPart = $Matches[2]
        if ($hostPart -match '^[0-9.]+$') {
            if (-not (Test-MyVpnIpAddress $hostPart)) { return $false }
        } elseif ($hostPart.Length -gt 253 -or $hostPart -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$') { return $false }
    } else { return $false }
    return ([int]$portPart -ge 1 -and [int]$portPart -le 65535)
}

function Test-MyVpnKey {
    param([string]$Value)
    if ($Value -notmatch '^[A-Za-z0-9+/]{43}=$') { return $false }
    try {
        $bytes = [Convert]::FromBase64String($Value)
        if ($bytes.Length -ne 32 -or [Convert]::ToBase64String($bytes) -cne $Value) { return $false }
        foreach ($byte in $bytes) { if ($byte -ne 0) { return $true } }
        return $false
    } catch { return $false }
}

function Test-MyVpnClientConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content)
    if ([string]::IsNullOrWhiteSpace($Content) -or $Content.Length -gt 65536 -or $Content.IndexOf([char]0) -ge 0) {
        throw 'The profile is empty, too large, or contains invalid characters.'
    }
    $sections = @{}
    $section = ''
    foreach ($line in ($Content -split '\r?\n')) {
        $text = ($line -replace '#.*$', '').Trim()
        if ($text.Length -eq 0) { continue }
        if ($text -match '^\[(Interface|Peer)\]$') {
            $section = $Matches[1]
            if ($sections.ContainsKey($section)) { throw 'Only one Interface and one Peer are supported per profile.' }
            $sections[$section] = @{}
            continue
        }
        if ($section.Length -eq 0 -or $text -notmatch '^([A-Za-z][A-Za-z0-9]*)\s*=\s*(.+)$') {
            throw 'The profile contains an invalid line or unsupported section.'
        }
        $name = $Matches[1]
        $value = $Matches[2].Trim()
        $interfaceKeys = @('PrivateKey', 'Address', 'DNS', 'MTU', 'ListenPort')
        $peerKeys = @('PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive')
        $allowed = $interfaceKeys
        if ($section -eq 'Peer') { $allowed = $peerKeys }
        if ($allowed -notcontains $name) { throw 'The profile contains an unsupported setting. Script hooks are never imported.' }
        if ($sections[$section].ContainsKey($name)) { throw 'The profile contains a duplicate setting.' }
        $sections[$section][$name] = $value
        switch ($name) {
            { $_ -in @('PrivateKey', 'PublicKey', 'PresharedKey') } {
                if (-not (Test-MyVpnKey $value)) { throw 'The profile contains an invalid WireGuard key.' }
            }
            { $_ -in @('Address', 'AllowedIPs') } {
                foreach ($entry in ($value -split ',')) {
                    if (-not (Test-MyVpnCidr $entry.Trim())) { throw 'The profile contains an invalid address or route.' }
                }
            }
            'DNS' {
                foreach ($entry in ($value -split ',')) {
                    if (-not (Test-MyVpnIpAddress $entry.Trim())) { throw 'DNS must contain only IPv4 or IPv6 server addresses.' }
                }
            }
            'Endpoint' { if (-not (Test-MyVpnProfileEndpoint $value)) { throw 'The endpoint must be a hostname or IP address followed by a valid UDP port.' } }
            { $_ -in @('ListenPort', 'PersistentKeepalive') } {
                if ($value -notmatch '^[0-9]{1,5}$' -or [int]$value -gt 65535) { throw 'The profile contains an invalid port or keepalive interval.' }
            }
            'MTU' {
                if ($value -notmatch '^[0-9]{3,5}$' -or [int]$value -lt 576 -or [int]$value -gt 65535) { throw 'The profile contains an invalid MTU.' }
            }
        }
    }
    foreach ($requiredSection in @('Interface', 'Peer')) {
        if (-not $sections.ContainsKey($requiredSection)) { throw 'The profile needs one Interface section and one Peer section.' }
    }
    foreach ($required in @('PrivateKey', 'Address')) {
        if (-not $sections['Interface'].ContainsKey($required)) { throw 'The Interface section needs a private key and address.' }
    }
    foreach ($required in @('PublicKey', 'AllowedIPs', 'Endpoint')) {
        if (-not $sections['Peer'].ContainsKey($required)) { throw 'The Peer section needs a public key, allowed IP routes, and endpoint.' }
    }
    return $true
}

function Get-MyVpnService {
    Get-CimInstance -ClassName Win32_Service -Filter ('Name = ''' + $script:ServiceName + '''') -ErrorAction Stop
}

function Assert-MyVpnOwnedService {
    param([Parameter(Mandatory = $true)]$Service, [Parameter(Mandatory = $true)]$State)
    $markerPath = Join-Path $State.RootDirectory 'ownership.json'
    if (-not [IO.File]::Exists($markerPath)) { throw 'A different tunnel uses the MyVPN service name. MyVPN will not change it.' }
    try { $marker = [IO.File]::ReadAllText($markerPath) | ConvertFrom-Json } catch { throw 'The tunnel ownership record is unreadable. No service was changed.' }
    if ($marker.TunnelName -ne $script:TunnelName -or $marker.ProfilePath -ne $State.ProfilePath) {
        throw 'The tunnel ownership record does not match this profile. No service was changed.'
    }
    $installation = Get-WireGuardInstallation
    $exe = [regex]::Escape($installation.WireGuardExe)
    $profile = [regex]::Escape($State.ProfilePath)
    $expected = '^(?:"' + $exe + '"|' + $exe + ')\s+/tunnelservice\s+(?:"' + $profile + '"|' + $profile + ')$'
    if ($Service.PathName.Trim() -notmatch $expected -or $Service.StartName -notin @('LocalSystem', 'NT AUTHORITY\SYSTEM')) {
        throw 'A different tunnel uses the MyVPN service name. MyVPN will not change it.'
    }
}

function Import-MyVpnProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $state = Initialize-MyVpnState
    if (-not [IO.File]::Exists($Path) -or (Get-Item -LiteralPath $Path -Force).Length -gt 65536) { throw 'Choose a WireGuard .conf file smaller than 64 KB.' }
    $content = [IO.File]::ReadAllText([IO.Path]::GetFullPath($Path))
    [void](Test-MyVpnClientConfiguration -Content $content)
    $service = Get-MyVpnService
    if ($null -ne $service) {
        Assert-MyVpnOwnedService -Service $service -State $state
        throw 'Disconnect the existing MyVPN tunnel before replacing its profile.'
    }
    $temporaryPath = Join-Path $state.RootDirectory ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($temporaryPath, $content.Trim() + "`r`n", (New-Object Text.UTF8Encoding($false)))
        if ([IO.File]::Exists($state.ProfilePath)) {
            [IO.File]::Replace($temporaryPath, $state.ProfilePath, $null)
        } else { [IO.File]::Move($temporaryPath, $state.ProfilePath) }
    } finally {
        if ([IO.File]::Exists($temporaryPath)) { [IO.File]::Delete($temporaryPath) }
    }
    Initialize-MyVpnState
}

function ConvertFrom-MyVpnHandshakeOutput {
    param([AllowEmptyString()][string]$Output, [long]$Now = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()))
    $timestamps = @()
    foreach ($line in ($Output -split '\r?\n')) {
        if ($line -match '^\S+\s+([0-9]+)\s*$') {
            $timestamp = 0L
            if ([long]::TryParse($Matches[1], [ref]$timestamp) -and $timestamp -gt 0) { $timestamps += $timestamp }
        }
    }
    if ($timestamps.Count -eq 0) { return [pscustomobject]@{ HandshakeState = 'Waiting'; HandshakeAgeSeconds = $null } }
    $lastHandshake = ($timestamps | Measure-Object -Maximum).Maximum
    if ($lastHandshake -gt ($Now + 5)) { return [pscustomobject]@{ HandshakeState = 'Unknown'; HandshakeAgeSeconds = $null } }
    $age = [Math]::Max(0L, ($Now - [long]$lastHandshake))
    $handshakeState = 'Stale'
    if ($age -le 180) { $handshakeState = 'Recent' }
    [pscustomobject]@{ HandshakeState = $handshakeState; HandshakeAgeSeconds = $age }
}

function Get-MyVpnStatus {
    $state = Initialize-MyVpnState
    $service = Get-MyVpnService
    $serviceState = 'Missing'
    $handshakeState = 'Unknown'
    $handshakeAge = $null
    if ($null -ne $service) {
        Assert-MyVpnOwnedService -Service $service -State $state
        $serviceState = 'Stopped'
        if ($service.State -eq 'Running') {
            $serviceState = 'Running'
            try {
                $installation = Get-WireGuardInstallation
                $output = (& $installation.WgExe show $script:TunnelName latest-handshakes 2>$null) -join "`n"
                if ($LASTEXITCODE -eq 0) {
                    $handshake = ConvertFrom-MyVpnHandshakeOutput -Output $output
                    $handshakeState = $handshake.HandshakeState
                    $handshakeAge = $handshake.HandshakeAgeSeconds
                }
            } catch { $handshakeState = 'Unknown' }
        }
    }
    [pscustomobject]@{ ServiceState = $serviceState; HandshakeState = $handshakeState; HandshakeAgeSeconds = $handshakeAge; HasProfile = $state.HasProfile }
}

function Invoke-MyVpnWireGuard {
    param(
        [Parameter(Mandatory = $true)][string]$ExecutablePath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [ValidateRange(1, 60000)][int]$TimeoutMilliseconds = 30000
    )
    # wireguard.exe is a GUI-subsystem program. Explicitly wait for its process;
    # PowerShell's native invocation rules need not wait for GUI applications.
    # Drain both streams concurrently, but never publish their contents: native
    # configuration errors could include private key material.
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $ExecutablePath
    $startInfo.Arguments = $Arguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    $timedOut = $false
    try {
        if (-not $process.Start()) { throw 'Process did not start.' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $timedOut = $true
            try { $process.Kill(); [void]$process.WaitForExit(1000) } catch { }
            throw 'Process timed out.'
        }
        if (-not $stdout.Wait(1000) -or -not $stderr.Wait(1000)) { throw 'Process output did not finish.' }
        return $process.ExitCode
    } catch {
        if ($timedOut) { throw 'WireGuard took too long to respond. Refresh the status before trying again.' }
        throw 'The WireGuard process could not finish. Check the installation and refresh the status.'
    } finally { $process.Dispose() }
}

function Connect-MyVpn {
    $state = Initialize-MyVpnState
    if (-not $state.HasProfile) { throw 'Create or import your client profile first.' }
    [void](Test-MyVpnClientConfiguration -Content ([IO.File]::ReadAllText($state.ProfilePath)))
    $installation = Get-WireGuardInstallation
    $service = Get-MyVpnService
    if ($null -ne $service) {
        Assert-MyVpnOwnedService -Service $service -State $state
        Set-Service -Name $script:ServiceName -StartupType Manual -ErrorAction Stop
        if ($service.State -ne 'Running') { Start-Service -Name $script:ServiceName -ErrorAction Stop }
    } else {
        $marker = @{ TunnelName = $script:TunnelName; ProfilePath = $state.ProfilePath } | ConvertTo-Json
        [IO.File]::WriteAllText((Join-Path $state.RootDirectory 'ownership.json'), $marker, (New-Object Text.UTF8Encoding($false)))
        $exitCode = -1
        $invocationFailed = $false
        try {
            $arguments = '/installtunnelservice "' + $state.ProfilePath + '"'
            $exitCode = Invoke-MyVpnWireGuard -ExecutablePath $installation.WireGuardExe -Arguments $arguments
        } catch { $invocationFailed = $true }
        $createdService = Get-MyVpnService
        if ($null -ne $createdService) {
            Assert-MyVpnOwnedService -Service $createdService -State $state
            Set-Service -Name $script:ServiceName -StartupType Manual -ErrorAction Stop
        }
        if ($invocationFailed -or $exitCode -ne 0 -or $null -eq $createdService) {
            throw 'WireGuard could not start this profile. Check that WireGuard is installed and no other full-tunnel VPN is active.'
        }
    }
    $controller = Get-Service -Name $script:ServiceName -ErrorAction Stop
    $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(10))
    Get-MyVpnStatus
}

function Disconnect-MyVpn {
    $state = Initialize-MyVpnState
    $service = Get-MyVpnService
    if ($null -eq $service) { return (Get-MyVpnStatus) }
    Assert-MyVpnOwnedService -Service $service -State $state
    $installation = Get-WireGuardInstallation
    $exitCode = Invoke-MyVpnWireGuard -ExecutablePath $installation.WireGuardExe -Arguments ('/uninstalltunnelservice ' + $script:TunnelName)
    if ($exitCode -ne 0) { throw 'WireGuard could not disconnect. Use the official WireGuard app or Windows Services to inspect the tunnel.' }
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        if ($null -eq (Get-MyVpnService)) { return (Get-MyVpnStatus) }
        Start-Sleep -Milliseconds 250
    }
    throw 'Windows is still removing the tunnel service. Wait a moment, then refresh the status.'
}

Export-ModuleMember -Function Initialize-MyVpnState, Import-MyVpnProfile, Get-MyVpnStatus, Connect-MyVpn, Disconnect-MyVpn, Test-MyVpnClientConfiguration
