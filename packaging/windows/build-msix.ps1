param(
    [string]$Version = "0.2.0",
    [string]$CertPath = "",
    [string]$CertPassword = ""
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "Building Soteria Aegis v$Version for Windows..." -ForegroundColor Cyan

# Build desktop app
Write-Host "[1/5] Building desktop app..." -ForegroundColor Yellow
Set-Location "$Root\desktop"
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "Desktop build failed" }

# Build CLI
Write-Host "[2/5] Building CLI..." -ForegroundColor Yellow
Set-Location "$Root\rust-core"
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "CLI build failed" }

# Create package structure
Write-Host "[3/5] Creating package..." -ForegroundColor Yellow
$PackageDir = "$Root\packaging\windows\package"
if (Test-Path $PackageDir) { Remove-Item -Recurse -Force $PackageDir }
New-Item -ItemType Directory -Force -Path "$PackageDir\App" | Out-Null
Copy-Item "$Root\desktop\target\release\SoteriaAegis.exe" "$PackageDir\App\"
Copy-Item "$Root\rust-core\target\release\soteriad.exe" "$PackageDir\App\"
Copy-Item "$Root\config\soteria.toml" "$PackageDir\App\"

# Build MSIX
Write-Host "[4/5] Building MSIX..." -ForegroundColor Yellow
$MsixPath = "$Root\packaging\windows\SoteriaAegis-$Version.msix"
$MakeAppx = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if ($MakeAppx) {
    & $MakeAppx pack /d "$PackageDir\AppxManifest" /p $MsixPath /o
} else {
    Write-Host "  makeappx not found, skipping MSIX" -ForegroundColor Yellow
}

# Sign
if ($CertPath -and $CertPassword) {
    Write-Host "[5/5] Signing..." -ForegroundColor Yellow
    $SignTool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    if ($SignTool) { & $SignTool sign /f $CertPath /p $CertPassword /fd SHA256 $MsixPath }
}

Write-Host "Done! MSIX: $MsixPath" -ForegroundColor Green
