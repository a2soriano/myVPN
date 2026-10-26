#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Show', 'Connect', 'Disconnect')][string]$Action = 'Show')

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') {
    throw 'MyVPN is a Windows desktop application. Run MyVPN.cmd on Windows 10 or 11.'
}

# A WireGuard tunnel service needs elevation. Do not store an admin password.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $arguments = '-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "{0}" -Action {1}' -f $PSCommandPath, $Action
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments -ErrorAction Stop | Out-Null
        exit 0
    } catch {
        Write-Error 'Administrator access was not granted. Starting and stopping the VPN requires a Windows UAC approval.'
        exit 1
    }
}

Import-Module (Join-Path $PSScriptRoot 'MyVPN.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'MyVPN.Controller.psm1') -Force
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$script:state = Initialize-MyVpnState
$script:busy = $false
$script:lastStatus = $null
$script:backgroundColor = [Drawing.ColorTranslator]::FromHtml('#111827')
$script:panelColor = [Drawing.ColorTranslator]::FromHtml('#1F2937')
$script:textColor = [Drawing.ColorTranslator]::FromHtml('#F9FAFB')
$script:mutedColor = [Drawing.ColorTranslator]::FromHtml('#A7B2C4')
$script:accentColor = [Drawing.ColorTranslator]::FromHtml('#34D399')
$script:wgInstalled = $false
try { $null = Get-WireGuardInstallation; $script:wgInstalled = $true } catch { }

function New-Label {
    param([string]$Text, [int]$X, [int]$Y, [int]$Width, [int]$Height, [int]$Size = 10)
    $label = New-Object Windows.Forms.Label
    $label.Text = $Text
    $label.SetBounds($X, $Y, $Width, $Height)
    $label.ForeColor = $script:textColor
    $label.Font = New-Object Drawing.Font('Segoe UI', $Size)
    return $label
}

function New-Button {
    param([string]$Text, [int]$X, [int]$Y, [int]$Width, [int]$Height)
    $button = New-Object Windows.Forms.Button
    $button.Text = $Text
    $button.SetBounds($X, $Y, $Width, $Height)
    $button.FlatStyle = 'Flat'
    $button.FlatAppearance.BorderColor = [Drawing.ColorTranslator]::FromHtml('#4B5563')
    $button.BackColor = $script:panelColor
    $button.ForeColor = $script:textColor
    $button.Font = New-Object Drawing.Font('Segoe UI', 10)
    return $button
}

function Show-AppError {
    param([string]$Message)
    [Windows.Forms.MessageBox]::Show($Message, 'MyVPN', 'OK', 'Error') | Out-Null
}

function Open-ServerGuide {
    $guide = Join-Path (Split-Path $PSScriptRoot -Parent) 'docs\server.md'
    Start-Process -FilePath 'notepad.exe' -ArgumentList ('"{0}"' -f $guide) | Out-Null
}

$form = New-Object Windows.Forms.Form
$form.Text = 'MyVPN'
$form.ClientSize = New-Object Drawing.Size(600, 520)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.StartPosition = 'CenterScreen'
$form.BackColor = $script:backgroundColor
$form.Font = New-Object Drawing.Font('Segoe UI', 10)

$title = New-Label 'myVPN' 28 22 540 48 28
$subtitle = New-Label 'Your keys. Your server. Your connection.' 30 78 535 26 11
$subtitle.ForeColor = $script:mutedColor
$statusLabel = New-Label 'Checking setup...' 30 133 535 35 19
$detailLabel = New-Label '' 30 178 535 66 10
$detailLabel.ForeColor = $script:mutedColor
$toggleButton = New-Button 'Connect' 30 252 540 58
$toggleButton.BackColor = $script:accentColor
$toggleButton.ForeColor = $script:backgroundColor
$toggleButton.Font = New-Object Drawing.Font('Segoe UI', 15, [Drawing.FontStyle]::Bold)
$createButton = New-Button 'Create a VPN' 30 328 262 43
$importButton = New-Button 'Import profile' 308 328 262 43
$folderButton = New-Button 'Open setup folder' 30 382 262 40
$guideButton = New-Button 'Server guide' 308 382 262 40
$installerLink = New-Object Windows.Forms.LinkLabel
$installerLink.Text = 'Install WireGuard for Windows'
$installerLink.SetBounds(30, 444, 330, 24)
$installerLink.LinkColor = $script:accentColor
$installerLink.ActiveLinkColor = $script:textColor
$footer = New-Label 'Closing this window leaves the VPN running. Use Disconnect to turn it off.' 30 481 540 25 9
$footer.ForeColor = $script:mutedColor
$form.Controls.AddRange(@($title, $subtitle, $statusLabel, $detailLabel, $toggleButton,
    $createButton, $importButton, $folderButton, $guideButton, $installerLink, $footer))

function Update-AppStatus {
    if ($script:busy) { return }
    try {
        $script:lastStatus = Get-MyVpnStatus
        $running = $script:lastStatus.ServiceState -eq 'Running'
        $hasService = $script:lastStatus.ServiceState -ne 'Missing'
        $script:state = Initialize-MyVpnState
        $toggleButton.Text = $(if ($running) { 'Disconnect' } elseif ($hasService) { 'Reset stopped tunnel' } else { 'Connect' })
        $toggleButton.Enabled = $script:wgInstalled -and ($script:state.HasProfile -or $hasService)
        $createButton.Enabled = $script:wgInstalled -and -not $hasService
        $importButton.Enabled = $script:wgInstalled -and -not $hasService
        if (-not $script:wgInstalled) {
            $statusLabel.Text = 'Install WireGuard first'
            $detailLabel.Text = 'Use the link below to install the free official Windows app, then reopen MyVPN.'
        } elseif ($running) {
            if ($script:lastStatus.HandshakeState -eq 'Recent') {
                $statusLabel.Text = 'Server responded'
                $statusLabel.ForeColor = $script:accentColor
                $detailLabel.Text = 'Encrypted handshake confirmed. Follow the server guide to check browsing and your exit IP.'
            } elseif ($script:lastStatus.HandshakeState -eq 'Stale') {
                $statusLabel.Text = 'Server response is stale'
                $statusLabel.ForeColor = [Drawing.Color]::Orange
                $detailLabel.Text = 'The tunnel is started, but there is no recent handshake. Check the server and its UDP port.'
            } else {
                $statusLabel.Text = 'Waiting for the server'
                $statusLabel.ForeColor = [Drawing.Color]::Orange
                $detailLabel.Text = 'The tunnel is started. A handshake is still needed; internet access has not been verified.'
            }
        } elseif ($hasService) {
            $statusLabel.Text = 'Tunnel stopped'
            $statusLabel.ForeColor = [Drawing.Color]::Orange
            $detailLabel.Text = 'Reset the stopped tunnel to reconnect or replace its profile. No active VPN connection is confirmed.'
        } elseif (-not $script:state.HasProfile) {
            $statusLabel.Text = 'Create your first VPN'
            $statusLabel.ForeColor = $script:textColor
            $detailLabel.Text = 'Create the server and PC profiles, set up your server using the guide, then click Connect.'
        } else {
            $statusLabel.Text = 'Disconnected'
            $statusLabel.ForeColor = $script:textColor
            $detailLabel.Text = 'Your PC profile is ready. Make sure its server is set up and reachable before connecting.'
        }
    } catch {
        $statusLabel.Text = 'Setup needs attention'
        $statusLabel.ForeColor = [Drawing.Color]::Orange
        $detailLabel.Text = $_.Exception.Message
        $toggleButton.Enabled = $false
        $createButton.Enabled = $false
        $importButton.Enabled = $false
    }
}

function Invoke-AppAction {
    param([scriptblock]$Action)
    if ($script:busy) { return }
    $script:busy = $true
    $form.UseWaitCursor = $true
    $toggleButton.Enabled = $false
    $createButton.Enabled = $false
    $importButton.Enabled = $false
    $form.Refresh()
    try { & $Action } catch { Show-AppError $_.Exception.Message } finally {
        $script:busy = $false
        $form.UseWaitCursor = $false
        Update-AppStatus
    }
}

function Show-CreateDialog {
    $dialog = New-Object Windows.Forms.Form
    $dialog.Text = 'Create your VPN profiles'
    $dialog.ClientSize = New-Object Drawing.Size(550, 370)
    $dialog.FormBorderStyle = 'FixedDialog'
    $dialog.MaximizeBox = $false
    $dialog.MinimizeBox = $false
    $dialog.StartPosition = 'CenterParent'
    $dialog.BackColor = $script:backgroundColor
    $intro = New-Label 'Enter the address of your Linux server or local test VM. This creates profiles; it does not deploy the server.' 22 20 505 50 10
    $endpointLabel = New-Label 'Server hostname or IP (optional :port)' 22 88 500 25 10
    $endpointBox = New-Object Windows.Forms.TextBox
    $endpointBox.SetBounds(22, 117, 500, 29)
    $endpointBox.Font = New-Object Drawing.Font('Segoe UI', 11)
    $example = New-Label 'Example: vpn.example.com:51820 or your VM IPv4 address' 22 153 500 24 9
    $example.ForeColor = $script:mutedColor
    $dnsLabel = New-Label 'DNS resolver inside the tunnel (editable)' 22 192 500 25 10
    $dnsBox = New-Object Windows.Forms.TextBox
    $dnsBox.SetBounds(22, 219, 500, 29)
    $dnsBox.Text = '1.1.1.1'
    $dnsBox.Font = New-Object Drawing.Font('Segoe UI', 11)
    $note = New-Label 'Profiles contain private keys. They stay in your Windows user data folder. IPv6 internet is blocked in this first version.' 22 262 500 43 9
    $note.ForeColor = $script:mutedColor
    $save = New-Button 'Generate profiles' 320 318 202 35
    $save.BackColor = $script:accentColor
    $save.ForeColor = $script:backgroundColor
    $dialog.Controls.AddRange(@($intro, $endpointLabel, $endpointBox, $example, $dnsLabel, $dnsBox, $note, $save))
    $dialog.AcceptButton = $save
    $save.Add_Click({
        try {
            $null = ConvertTo-MyVpnEndpoint -Endpoint $endpointBox.Text.Trim()
            if (-not (Test-MyVpnDnsServer -DnsServer $dnsBox.Text.Trim())) {
                throw 'Enter a valid DNS resolver IP address.'
            }
            $dialog.Tag = @{ Endpoint = $endpointBox.Text.Trim(); Dns = $dnsBox.Text.Trim() }
            $dialog.DialogResult = [Windows.Forms.DialogResult]::OK
            $dialog.Close()
        } catch { Show-AppError $_.Exception.Message }
    })
    $result = $dialog.ShowDialog($form)
    $values = $dialog.Tag
    $dialog.Dispose()
    if ($result -ne [Windows.Forms.DialogResult]::OK) { return }
    Invoke-AppAction {
        $setupRoot = Join-Path $script:state.RootDirectory 'setups'
        # The key generator creates the new leaf directory and locks its ACL first.
        $output = Join-Path $setupRoot ('setup-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [Guid]::NewGuid().ToString('N').Substring(0, 6))
        $generated = New-MyVpnConfiguration -Endpoint $values.Endpoint -DnsServer $values.Dns -OutputDirectory $output
        Import-MyVpnProfile -Path $generated.ClientConfigPath | Out-Null
        $message = "Your PC profile is loaded. Before connecting, install wg0.conf on your server using the Server guide.`r`n`r`nSetup folder: $output`r`n`r`nKeep both configuration files private."
        [Windows.Forms.MessageBox]::Show($message, 'Profiles created', 'OK', 'Information') | Out-Null
    }
}

$toggleButton.Add_Click({
    Invoke-AppAction {
        $current = Get-MyVpnStatus
        if ($current.ServiceState -ne 'Missing') { Disconnect-MyVpn | Out-Null }
        else { Connect-MyVpn | Out-Null }
    }
})
$createButton.Add_Click({ Show-CreateDialog })
$importButton.Add_Click({
    $picker = New-Object Windows.Forms.OpenFileDialog
    $picker.Title = 'Import your WireGuard client profile'
    $picker.Filter = 'WireGuard profiles (*.conf)|*.conf'
    if ($picker.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
        $selectedPath = $picker.FileName
        Invoke-AppAction { Import-MyVpnProfile -Path $selectedPath | Out-Null }
    }
    $picker.Dispose()
})
$folderButton.Add_Click({
    Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:state.RootDirectory) | Out-Null
})
$guideButton.Add_Click({ Open-ServerGuide })
$installerLink.Add_LinkClicked({ Start-Process 'https://www.wireguard.com/install/' | Out-Null })

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 4000
$timer.Add_Tick({ Update-AppStatus })
$form.Add_Shown({
    Update-AppStatus
    $timer.Start()
    if ($Action -eq 'Connect') { Invoke-AppAction { Connect-MyVpn | Out-Null } }
    elseif ($Action -eq 'Disconnect') { Invoke-AppAction { Disconnect-MyVpn | Out-Null } }
})
$form.Add_FormClosed({ $timer.Stop(); $timer.Dispose() })
[Windows.Forms.Application]::Run($form)
$form.Dispose()
