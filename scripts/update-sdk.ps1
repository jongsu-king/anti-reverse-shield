<#
  Download the latest anti-reverse-shield native SDK for Windows x64, verify it
  against the release's SHA256SUMS.txt and unpack it into a vendor folder.

    scripts\update-sdk.ps1 [-Check] [-Dir third_party\anti-reverse-shield]

  -Check  only compare; exit code 10 if a newer release exists.
  The installed version is recorded in <Dir>\VERSION.
#>
param([switch]$Check, [string]$Dir = "third_party\anti-reverse-shield")
$ErrorActionPreference = "Stop"
$repo = "jongsu-king/anti-reverse-shield"
$release = Invoke-RestMethod -Headers @{ Accept = "application/vnd.github+json" } "https://api.github.com/repos/$repo/releases/latest"
$version = $release.tag_name.TrimStart("v")
$current = if (Test-Path "$Dir\VERSION") { (Get-Content "$Dir\VERSION" -Raw).Trim() } else { "none" }
Write-Host "installed: $current   latest: $version"
if ($current -eq $version) { Write-Host "up to date"; exit 0 }
if ($Check) { Write-Host "a newer SDK is available"; exit 10 }

$name = "anti-reverse-shield-sdk-$version-windows-x64.zip"
$base = "https://github.com/$repo/releases/download/$($release.tag_name)"
$tmp = New-Item -ItemType Directory -Path (Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid()))
try {
  Invoke-WebRequest "$base/$name" -OutFile "$tmp\$name"
  Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile "$tmp\SHA256SUMS.txt"
  $line = Select-String -Path "$tmp\SHA256SUMS.txt" -Pattern " $([regex]::Escape($name))$"
  $expected = if ($line) { ($line.Line -split '\s+')[0].ToLower() } else { "" }
  $actual = (Get-FileHash "$tmp\$name" -Algorithm SHA256).Hash.ToLower()
  if (-not $expected -or $expected -ne $actual) { throw "SHA-256 of $name does not match SHA256SUMS.txt; nothing changed" }
  Expand-Archive "$tmp\$name" -DestinationPath "$tmp\x"
  $src = Get-ChildItem "$tmp\x" -Directory | Select-Object -First 1
  if (Test-Path $Dir) { Remove-Item $Dir -Recurse -Force }
  $parent = Split-Path -Parent $Dir
  if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
  Move-Item $src.FullName $Dir
  Set-Content "$Dir\VERSION" $version
  Write-Host "updated $Dir to $version (verified $actual)"
} finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
