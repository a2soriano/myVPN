$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot '../windows/MyVPN.Controller.psm1') -Force
$script:passed = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
    $script:passed++
}

function Assert-Rejected {
    param([string]$Configuration, [string]$Message)
    $rejected = $false
    try { [void](Test-MyVpnClientConfiguration -Content $Configuration) } catch { $rejected = $true }
    Assert-True $rejected $Message
}

$keyBytes = New-Object byte[] 32
for ($i = 0; $i -lt 32; $i++) { $keyBytes[$i] = $i + 1 }
$testKey = [Convert]::ToBase64String($keyBytes)
$valid = @"
# Test-only synthetic keys, not a usable deployed VPN.
[Interface]
PrivateKey = $testKey
Address = 10.66.66.2/32, fd66:66:66::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = $testKey
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
"@
Assert-True (Test-MyVpnClientConfiguration -Content $valid) 'A normal dual-stack WireGuard client profile was rejected.'
Assert-True (Test-MyVpnClientConfiguration -Content ($valid.Replace('vpn.example.com:51820', '[2001:db8::1]:51820'))) 'A bracketed IPv6 endpoint was rejected.'
Assert-True (Test-MyVpnClientConfiguration -Content ($valid.Replace('vpn.example.com:51820', '192.0.2.10:51820'))) 'An IPv4 endpoint was rejected.'
Assert-True (Test-MyVpnClientConfiguration -Content ($valid.Replace('AllowedIPs = 0.0.0.0/0, ::/0', 'AllowedIPs = 10.66.66.0/24, fd66:66:66::/64'))) 'A split-tunnel profile was rejected.'

Assert-Rejected '' 'Empty input was accepted.'
Assert-Rejected ($valid + "`nPostUp = calc.exe") 'A script hook was accepted.'
Assert-Rejected ($valid.Replace('DNS = ', "PostUp = calc.exe`nDNS = ")) 'An Interface script hook was accepted.'
Assert-Rejected ($valid + "`n[Peer]`nPublicKey = $testKey") 'A second peer was accepted.'
Assert-Rejected ($valid.Replace('DNS = ', "PrivateKey = $testKey`nDNS = ")) 'A duplicate private key was accepted.'
Assert-Rejected ($valid.Replace($testKey, 'invalid-key')) 'Invalid key encoding was accepted.'
Assert-Rejected ($valid.Replace($testKey, ('A' * 43 + '='))) 'An all-zero key was accepted.'
Assert-Rejected ($valid.Replace('10.66.66.2/32', '10.66.66.2/33')) 'An invalid IPv4 prefix was accepted.'
Assert-Rejected ($valid.Replace('fd66:66:66::2/128', 'fd66:66:66::2/129')) 'An invalid IPv6 prefix was accepted.'
Assert-Rejected ($valid.Replace('vpn.example.com:51820', 'vpn.example.com:65536')) 'An out-of-range UDP port was accepted.'
Assert-Rejected ($valid.Replace('vpn.example.com:51820', 'https://vpn.example.com:51820')) 'A URL endpoint was accepted.'
Assert-Rejected ($valid.Replace('vpn.example.com:51820', 'vpn.example.com:0')) 'Port zero was accepted.'
Assert-Rejected ($valid.Replace('vpn.example.com:51820', '999.1.2.3:51820')) 'An invalid dotted IPv4 endpoint was accepted.'
Assert-Rejected ($valid.Replace('vpn.example.com:51820', 'vpn.example.com:51820;calc.exe')) 'Endpoint command injection was accepted.'
Assert-Rejected ($valid.Replace('DNS = 1.1.1.1, 2606:4700:4700::1111', 'DNS = evil.example.com')) 'A non-IP DNS server was accepted.'
Assert-Rejected ($valid.Replace('PersistentKeepalive = 25', 'PersistentKeepalive = 70000')) 'An invalid keepalive was accepted.'
Assert-Rejected ($valid.Replace('Address = 10.66.66.2/32, fd66:66:66::2/128', '')) 'A missing Interface address was accepted.'
Assert-Rejected ($valid.Replace('Endpoint = vpn.example.com:51820', '')) 'A missing endpoint was accepted.'
Assert-Rejected ($valid.Replace('[Peer]', '[Unknown]')) 'An unsupported section was accepted.'
Assert-Rejected ($valid.Replace('DNS = ', "SaveConfig = true`nDNS = ")) 'An unsupported state-changing directive was accepted.'
Assert-Rejected ($valid + [char]0) 'A null byte was accepted.'
Assert-Rejected ('x' * 65537) 'Oversized input was accepted.'

$module = Get-Module MyVPN.Controller
$waiting = & $module { ConvertFrom-MyVpnHandshakeOutput -Output 'peerkey 0' -Now 1000 }
Assert-True ($waiting.HandshakeState -eq 'Waiting' -and $null -eq $waiting.HandshakeAgeSeconds) 'A zero handshake was reported as connected.'
$recent = & $module { ConvertFrom-MyVpnHandshakeOutput -Output 'peerkey 995' -Now 1000 }
Assert-True ($recent.HandshakeState -eq 'Recent' -and $recent.HandshakeAgeSeconds -eq 5) 'Recent handshake age was wrong.'
$stale = & $module { ConvertFrom-MyVpnHandshakeOutput -Output 'peerkey 800' -Now 1000 }
Assert-True ($stale.HandshakeState -eq 'Stale' -and $stale.HandshakeAgeSeconds -eq 200) 'A stale handshake was reported as connected.'
$future = & $module { ConvertFrom-MyVpnHandshakeOutput -Output 'peerkey 2000' -Now 1000 }
Assert-True ($future.HandshakeState -eq 'Unknown') 'A future handshake timestamp was trusted.'
$invalid = & $module { ConvertFrom-MyVpnHandshakeOutput -Output 'malformed data' -Now 1000 }
Assert-True ($invalid.HandshakeState -eq 'Waiting') 'Malformed handshake output was reported as connected.'

# Exercise service ownership without touching Windows Services or real key files.
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('myvpn-controller-test-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporaryRoot)
try {
    $testState = [pscustomobject]@{ RootDirectory = $temporaryRoot; ProfilePath = 'C:\Users\Test User\AppData\Local\MyVPN\myvpn-desktop.conf' }
    $markerPath = Join-Path $temporaryRoot 'ownership.json'
    @{ TunnelName = 'myvpn-desktop'; ProfilePath = $testState.ProfilePath } | ConvertTo-Json | Set-Content -LiteralPath $markerPath
    & $module { function script:Get-WireGuardInstallation { [pscustomobject]@{ WireGuardExe = 'C:\Program Files\WireGuard\wireguard.exe' } } }
    $ownedService = [pscustomobject]@{ PathName = '"C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "' + $testState.ProfilePath + '"'; StartName = 'LocalSystem' }
    $ownedAccepted = & $module { param($Service, $State) Assert-MyVpnOwnedService -Service $Service -State $State; $true } $ownedService $testState
    Assert-True $ownedAccepted 'The exact app-owned tunnel service was rejected.'
    $foreignService = [pscustomobject]@{ PathName = '"C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "C:\another-tunnel.conf"'; StartName = 'LocalSystem' }
    $foreignRejected = & $module { param($Service, $State) try { Assert-MyVpnOwnedService -Service $Service -State $State; $false } catch { $true } } $foreignService $testState
    Assert-True $foreignRejected 'A same-name service using another tunnel configuration was accepted.'
    $argumentService = [pscustomobject]@{ PathName = $ownedService.PathName + ' extra-argument'; StartName = 'LocalSystem' }
    $argumentsRejected = & $module { param($Service, $State) try { Assert-MyVpnOwnedService -Service $Service -State $State; $false } catch { $true } } $argumentService $testState
    Assert-True $argumentsRejected 'A same-name service with injected arguments was accepted.'
    Remove-Item -LiteralPath $markerPath
    $unmarkedRejected = & $module { param($Service, $State) try { Assert-MyVpnOwnedService -Service $Service -State $State; $false } catch { $true } } $ownedService $testState
    Assert-True $unmarkedRejected 'An unmarked service was adopted.'
} finally { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }

# Validate bounded process waiting and discarded native output using a harmless
# child PowerShell process, without WireGuard or Windows networking privileges.
$powershellPath = (Get-Process -Id $PID).Path
$processResult = @(& $module {
    param($ExecutablePath)
    Invoke-MyVpnWireGuard -ExecutablePath $ExecutablePath -Arguments '-NoLogo -NoProfile -Command "[Console]::Out.Write(''sample-private-key''); [Console]::Error.Write(''sample-private-key''); exit 7"'
} $powershellPath)
Assert-True ($processResult.Count -eq 1 -and $processResult[0] -eq 7) 'Native process exit status or suppressed output was wrong.'
$stopwatch = [Diagnostics.Stopwatch]::StartNew()
$timeoutRejected = & $module {
    param($ExecutablePath)
    try {
        [void](Invoke-MyVpnWireGuard -ExecutablePath $ExecutablePath -Arguments '-NoLogo -NoProfile -Command "Start-Sleep -Seconds 10"' -TimeoutMilliseconds 100)
        $false
    } catch { $true }
} $powershellPath
$stopwatch.Stop()
Assert-True ($timeoutRejected -and $stopwatch.ElapsedMilliseconds -lt 5000) 'The native process timeout was not bounded.'

# Mock only external Windows operations. Exercise the real connect/disconnect
# transitions, native-failure handling, and profile ownership marker checks.
$transitionRoot = Join-Path ([IO.Path]::GetTempPath()) ('myvpn-controller-transitions-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($transitionRoot)
try {
    $transitionProfile = Join-Path $transitionRoot 'myvpn-desktop.conf'
    [IO.File]::WriteAllText($transitionProfile, $valid)
    $transitionState = [pscustomobject]@{ RootDirectory = $transitionRoot; ProfilePath = $transitionProfile; HasProfile = $true }
    & $module {
        param($State)
        $script:TestHarness = @{ State = $State; Service = $null; NativeExitCode = 0; NativeCalls = @(); SetCalls = @(); StartCalls = 0 }
        function script:Initialize-MyVpnState { $script:TestHarness.State }
        function script:Get-MyVpnService { $script:TestHarness.Service }
        function script:Set-Service {
            param($Name, $StartupType, $ErrorAction)
            $script:TestHarness.SetCalls += ($Name + ':' + $StartupType)
        }
        function script:Start-Service {
            param($Name, $ErrorAction)
            $script:TestHarness.StartCalls++
            $script:TestHarness.Service.State = 'Running'
        }
        function script:Get-Service {
            param($Name, $ErrorAction)
            $controller = [pscustomobject]@{}
            Add-Member -InputObject $controller -MemberType ScriptMethod -Name WaitForStatus -Value { param($Status, $Timeout) } -PassThru
        }
        function script:Invoke-MyVpnWireGuard {
            param($ExecutablePath, $Arguments)
            $script:TestHarness.NativeCalls += $Arguments
            if ($Arguments.StartsWith('/installtunnelservice ')) {
                $serviceState = 'Running'
                if ($script:TestHarness.NativeExitCode -ne 0) { $serviceState = 'Stopped' }
                $script:TestHarness.Service = [pscustomobject]@{
                    PathName = '"C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "' + $script:TestHarness.State.ProfilePath + '"'
                    StartName = 'LocalSystem'
                    State = $serviceState
                }
            } elseif ($script:TestHarness.NativeExitCode -eq 0) { $script:TestHarness.Service = $null }
            return $script:TestHarness.NativeExitCode
        }
        function script:Get-MyVpnStatus {
            $state = 'Missing'
            if ($null -ne $script:TestHarness.Service) { $state = $script:TestHarness.Service.State }
            [pscustomobject]@{ ServiceState = $state; HasProfile = $script:TestHarness.State.HasProfile; HandshakeState = 'Waiting'; HandshakeAgeSeconds = $null }
        }
    } $transitionState

    $connected = & $module { Connect-MyVpn }
    $installed = & $module { $script:TestHarness.NativeCalls.Count -eq 1 -and $script:TestHarness.NativeCalls[0] -eq ('/installtunnelservice "' + $script:TestHarness.State.ProfilePath + '"') }
    Assert-True ($connected.ServiceState -eq 'Running' -and $installed) 'A new tunnel did not use the expected quoted install command.'
    $manual = & $module { $script:TestHarness.SetCalls -contains 'WireGuardTunnel$myvpn-desktop:Manual' }
    Assert-True $manual 'A newly installed tunnel was left on automatic startup.'

    & $module { $script:TestHarness.Service.State = 'Stopped'; $script:TestHarness.NativeCalls = @() }
    $reconnected = & $module { Connect-MyVpn }
    $restartedOnly = & $module { $script:TestHarness.StartCalls -eq 1 -and $script:TestHarness.NativeCalls.Count -eq 0 }
    Assert-True ($reconnected.ServiceState -eq 'Running' -and $restartedOnly) 'An owned stopped tunnel was not restarted safely.'

    $disconnected = & $module { Disconnect-MyVpn }
    $removedOwned = & $module { $script:TestHarness.NativeCalls[-1] -eq '/uninstalltunnelservice myvpn-desktop' }
    Assert-True ($disconnected.ServiceState -eq 'Missing' -and $removedOwned) 'Disconnect did not remove only the owned tunnel.'
    $alreadyDisconnected = & $module { Disconnect-MyVpn }
    Assert-True ($alreadyDisconnected.ServiceState -eq 'Missing') 'Disconnecting an absent tunnel did not remain safe.'

    & $module { $script:TestHarness.NativeExitCode = 1; $script:TestHarness.SetCalls = @() }
    $failedInstallRejected = & $module { try { [void](Connect-MyVpn); $false } catch { $true } }
    $failureControlled = & $module { $script:TestHarness.Service.State -eq 'Stopped' -and $script:TestHarness.SetCalls -contains 'WireGuardTunnel$myvpn-desktop:Manual' }
    Assert-True ($failedInstallRejected -and $failureControlled) 'A failed installer was reported as connected or left an automatic-start service.'

    $failedRemovalRejected = & $module { try { [void](Disconnect-MyVpn); $false } catch { $true } }
    $retainedAfterFailure = & $module { $null -ne $script:TestHarness.Service }
    Assert-True ($failedRemovalRejected -and $retainedAfterFailure) 'A failed disconnect was reported as successful.'

    & $module { $script:TestHarness.NativeExitCode = 0 }
    $cleanedUp = & $module { Disconnect-MyVpn }
    Assert-True ($cleanedUp.ServiceState -eq 'Missing') 'A stopped tunnel left after failed startup could not be removed.'
} finally { Remove-Item -LiteralPath $transitionRoot -Recurse -Force }

Write-Output ("Controller validation passed: {0} assertions." -f $script:passed)
