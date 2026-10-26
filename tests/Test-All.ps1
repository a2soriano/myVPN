#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$scripts = Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object { $_.Extension -in @('.ps1', '.psm1') }
foreach ($file in $scripts) {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ('PowerShell syntax error in {0}: {1}' -f $file.Name, ($errors.Message -join '; ')) }
}
Write-Output ('PowerShell syntax: {0} scripts passed.' -f $scripts.Count)
& (Join-Path $PSScriptRoot 'Test-Core.ps1')
& (Join-Path $PSScriptRoot 'Test-Controller.ps1')
Write-Output 'Logic checks complete. Windows native and live-tunnel checks are separate.'
