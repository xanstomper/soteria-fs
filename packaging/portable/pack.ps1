param(
    [string]$Config = "Release",
    [switch]$SkipGuiBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$OutDir = Join-Path $Root "packaging\output"
$PortableDir = Join-Path $OutDir "SoteriaAegis-Portable"
$ZipPath = Join-Path $OutDir "SoteriaAegis-Portable.zip"

Write-Host ""
Write-Host "=== Soteria Aegis Portable Packer ===" -ForegroundColor Cyan

# Step 1: Build CLI
Write-Host ""
Write-Host "[1/5] Building soteriad CLI ($Config)..." -ForegroundColor Yellow
Push-Location (Join-Path $Root "rust-core")
try {
    if ($Config -eq "Release") {
        cargo build --release 2>&1 | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
    } else {
        cargo build 2>&1 | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
    }
} finally { Pop-Location }

# Step 2: Build desktop GUI (optional)
$guiSrc = $null
if (-not $SkipGuiBuild) {
    Write-Host ""
    Write-Host "[2/5] Building SoteriaAegis desktop GUI ($Config)..." -ForegroundColor Yellow
    Push-Location (Join-Path $Root "desktop")
    try {
        if ($Config -eq "Release") {
            cargo build --release 2>&1 | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
        } else {
            cargo build 2>&1 | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
        }
    } finally { Pop-Location }

    $exeName = "SoteriaAegis.exe"
    $guiRelease = Join-Path $Root "desktop" "target" "release" $exeName
    $guiDebug   = Join-Path $Root "desktop" "target" "debug"   $exeName
    $guiSrc = if (Test-Path $guiRelease) { $guiRelease } elseif (Test-Path $guiDebug) { $guiDebug } else { $null }
    if (-not $guiSrc) {
        Write-Warning "Desktop GUI not found - packaging CLI-only portable."
    }
} else {
    Write-Host ""
    Write-Host "[2/5] Skipping desktop GUI build." -ForegroundColor DarkYellow
}

# Step 3: Locate CLI binary
$cliName = "soteriad.exe"
$cliSrcRelease = Join-Path $Root "rust-core" "target" "release" $cliName
$cliSrcDebug   = Join-Path $Root "rust-core" "target" "debug"   $cliName
$cliSrc = if (Test-Path $cliSrcRelease) { $cliSrcRelease } elseif (Test-Path $cliSrcDebug) { $cliSrcDebug } else { throw "CLI binary not found. Build it first: cd rust-core && cargo build --release" }

Write-Host ""
Write-Host "[3/5] CLI binary: $cliSrc" -ForegroundColor DarkGray
if ($guiSrc) { Write-Host "      GUI binary: $guiSrc" -ForegroundColor DarkGray }

# Step 4: Stage portable layout
Write-Host ""
Write-Host "[4/5] Staging portable layout..." -ForegroundColor Yellow
Write-Host "      Dest: $PortableDir"
if (Test-Path $PortableDir) { Remove-Item $PortableDir -Recurse -Force }
New-Item $PortableDir -ItemType Directory | Out-Null

Copy-Item $cliSrc (Join-Path $PortableDir $cliName) -Force

if ($guiSrc) {
    Copy-Item $guiSrc (Join-Path $PortableDir "SoteriaAegis.exe") -Force
}

$buildDate = Get-Date -Format 'yyyy-MM-dd HH:mm zzz'
$readme = "Soteria Aegis - Portable Edition" + "`r`n" +
"===================================`r`n`r`n" +
"Contents`r`n--------`r`n" +
"  SoteriaAegis.exe   - Desktop GUI (egui) - double-click to run`r`n" +
"  soteriad.exe       - Command-line interface`r`n" +
"  README.txt         - This file`r`n`r`n" +
"Quick Start`r`n-----------`r`n" +
"  Double-click SoteriaAegis.exe to launch the desktop app.`r`n" +
"  Or run soteriad.exe from any terminal for CLI commands.`r`n`r`n" +
"Data directories (Windows)`r`n--------------------------`r`n" +
"  Config:  `%APPDATA%`\Soteria\config.toml`r`n" +
"  Volumes: `%LOCALAPPDATA%`\Soteria\volumes\`r`n" +
"  Logs:    `%LOCALAPPDATA%`\Soteria\logs\`r`n`r`n" +
"No installation required. No admin rights needed.`r`n" +
"Remove this folder to uninstall.`r`n`r`n" +
"Build info`r`n----------`r`n" +
"  Config: $Config`r`n" +
"  Date:   $buildDate`r`n"

Set-Content (Join-Path $PortableDir "README.txt") $readme -Encoding UTF8

# Step 5: Compress
Write-Host ""
Write-Host "[5/5] Compressing portable ZIP..." -ForegroundColor Yellow
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
$compress = [System.IO.Compression.ZipFile]::Open($ZipPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Get-ChildItem $PortableDir -File | ForEach-Object {
        $entry = $compress.CreateEntry($_.Name, [System.IO.Compression.CompressionLevel]::Optimal)
        $stream = $entry.Open()
        $fs = [System.IO.File]::OpenRead($_.FullName)
        try {
            $fs.CopyTo($stream)
        } finally { $fs.Close() }
        $stream.Close()
        $sizeMB = "{0:N1}" -f ($_.Length / 1MB)
        Write-Host "  + $($_.Name) ($sizeMB MB)" -ForegroundColor DarkGray
    }
} finally { $compress.Dispose() }

$zipSize = (Get-Item $ZipPath).Length
Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  ZIP: $ZipPath" -ForegroundColor Cyan
Write-Host "  Size: $([math]::Round($zipSize / 1MB, 1)) MB" -ForegroundColor Cyan
Write-Host ""
