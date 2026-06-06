param([string]$Root)

$ErrorActionPreference = 'SilentlyContinue'
$outDir  = Join-Path $Root "packaging\output"
$portDir = Join-Path $outDir "SoteriaAegis-Portable"

if (Test-Path $portDir) { Remove-Item $portDir -Recurse -Force }
New-Item $portDir -ItemType Directory | Out-Null

Copy-Item (Join-Path $Root "rust-core\target\release\soteriad.exe")    (Join-Path $portDir "soteriad.exe")       -Force
Copy-Item (Join-Path $Root "desktop\target\debug\SoteriaAegis.exe")    (Join-Path $portDir "SoteriaAegis.exe")   -Force

$dt = Get-Date -Format 'yyyy-MM-dd HH:mm zzz'
$readme = @"
Soteria Aegis - Portable Edition
==================================

Contents
--------
  SoteriaAegis.exe   - Desktop GUI (egui) - double-click to run
  soteriad.exe       - Command-line interface
  README.txt         - This file

Quick Start
-----------
  Double-click SoteriaAegis.exe to launch the desktop app.
  Or run soteriad.exe from any terminal for CLI commands.

Data directories (Windows)
-------------------------
  Config:  %APPDATA%\Soteria\config.toml
  Volumes: %LOCALAPPDATA%\Soteria\volumes\
  Logs:    %LOCALAPPDATA%\Soteria\logs\

No installation required. No admin rights needed.
Remove this folder to uninstall.

Build info
----------
  Config: Release
  Date:   $dt
"@
Set-Content (Join-Path $portDir "README.txt") $readme -Encoding UTF8

$zipPath = Join-Path $outDir "SoteriaAegis-Portable.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Add-Type -Assembly System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($portDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

$z = Get-Item $zipPath
Write-Host "Portable ZIP: $($z.FullName) ($([math]::Round($z.Length/1MB,1)) MB)"
Write-Host "Contents:"
Get-ChildItem $portDir | ForEach-Object {
    Write-Host ("  {0} ({1:N1} MB)" -f $_.Name, ($_.Length/1MB))
}
