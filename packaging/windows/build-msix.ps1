# Soteria Windows Packaging (MSIX)
#
# Prerequisites:
# - Windows 10 SDK (for makeappx.exe and signtool.exe)
# - A code signing certificate (.pfx)
#
# Usage:
#   pwsh packaging/windows/build-msix.ps1

param(
    [string]$Version = "0.1.0",
    [string]$CertPath = "",
    [string]$CertPassword = ""
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$BuildDir = "$Root\rust-core\target\release"
$PackageDir = "$Root\packaging\windows\package"
$MsixPath = "$Root\packaging\windows\Soteria-$Version.msix"

Write-Host "Building Soteria v$Version for Windows..." -ForegroundColor Cyan

# Step 1: Build the Rust binary
Write-Host "Building soteriad..." -ForegroundColor Yellow
Set-Location "$Root\rust-core"
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

# Step 2: Create package structure
Write-Host "Creating package structure..." -ForegroundColor Yellow
if (Test-Path $PackageDir) { Remove-Item -Recurse -Force $PackageDir }
New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null
New-Item -ItemType Directory -Force -Path "$PackageDir\App" | Out-Null
New-Item -ItemType Directory -Force -Path "$PackageDir\AppxManifest" | Out-Null

# Step 3: Copy files
Copy-Item "$BuildDir\soteriad.exe" "$PackageDir\App\"
Copy-Item "$Root\rust-core\config\soteria.toml" "$PackageDir\App\"

# Step 4: Create AppxManifest.xml
$Manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Soteria.SoteriaFS"
            Publisher="CN=Soteria"
            Version="$Version.0" />
  <Properties>
    <DisplayName>Soteria</DisplayName>
    <PublisherDisplayName>Soteria</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
    <Description>Hardware-rooted encrypted security platform</Description>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Capabilities>
    <rescap:Capability name="runFullTrust" />
  </Capabilities>
  <Applications>
    <Application Id="SoteriaApp" Executable="App\soteriad.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Soteria" Description="Encrypted security platform"
                          BackgroundColor="transparent" Square150x150Logo="Assets\Square150x150Logo.png"
                          Square44x44Logo="Assets\Square44x44Logo.png">
        <uap:DefaultTile Wide310x150Logo="Assets\Wide310x150Logo.png" />
      </uap:VisualElements>
    </Application>
  </Applications>
</Package>
"@
$Manifest | Out-File -FilePath "$PackageDir\AppxManifest\AppxManifest.xml" -Encoding utf8

# Step 5: Create MSIX package
Write-Host "Creating MSIX package..." -ForegroundColor Yellow
$MakeAppx = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\makeappx.exe"
if (-not (Test-Path $MakeAppx)) {
    $MakeAppx = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makeappx.exe" | Select-Object -First 1 -ExpandProperty FullName
}
& $MakeAppx pack /d "$PackageDir\AppxManifest" /p $MsixPath /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed" }

# Step 6: Sign the package (if certificate provided)
if ($CertPath -and $CertPassword) {
    Write-Host "Signing MSIX package..." -ForegroundColor Yellow
    $SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    if (-not (Test-Path $SignTool)) {
        $SignTool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" | Select-Object -First 1 -ExpandProperty FullName
    }
    & $SignTool sign /f $CertPath /p $CertPassword /fd SHA256 $MsixPath
    if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
}

Write-Host "Done! MSIX package: $MsixPath" -ForegroundColor Green
