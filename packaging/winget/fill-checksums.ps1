# Fills the InstallerSha256 values of the winget manifests from the
# checksums.txt of a release. Reads a local file; downloads nothing.
#   pwsh packaging/winget/fill-checksums.ps1 -Version 0.2.0 -Checksums dist/checksums.txt
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Checksums
)
$ErrorActionPreference = 'Stop'
$manifest = Join-Path $PSScriptRoot "manifests/a/AttackScout/AttackscoutAgent/$Version/AttackScout.AttackscoutAgent.installer.yaml"
$sums = @{}
foreach ($line in Get-Content $Checksums) {
    $parts = $line -split '\s+'
    if ($parts.Count -ge 2) { $sums[$parts[1]] = $parts[0].ToUpperInvariant() }
}
$out = @()
$pending = $null
foreach ($line in Get-Content $manifest) {
    if ($line -match 'InstallerUrl: .*/(attackscout-agent_[^/]+\.zip)$') { $pending = $Matches[1] }
    if ($line -match '^(\s*InstallerSha256: )' -and $pending) {
        if (-not $sums.ContainsKey($pending)) { throw "$pending missing from $Checksums" }
        $line = $Matches[1] + $sums[$pending]
        $pending = $null
    }
    $out += $line
}
Set-Content -Path $manifest -Value $out -Encoding utf8NoBOM
Write-Output "updated $manifest"
