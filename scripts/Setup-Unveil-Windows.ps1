# Unveil — Windows-only (WIN) one-click setup
# No Python, no terminal. Drops unveil-engine-WIN.exe + JAR into %LOCALAPPDATA%\Unveil and whitelists port 8000.
# Usage: irm https://raw.githubusercontent.com/Pa7ch3s/Unveil/main/scripts/Setup-Unveil-Windows.ps1 | iex
#    or: .\scripts\Setup-Unveil-Windows.ps1
$ErrorActionPreference = "Stop"
$Repo = "Pa7ch3s/Unveil"
$WinPath = Join-Path $env:LOCALAPPDATA "Unveil"
$Api = "https://api.github.com/repos/$Repo/releases/latest"

Write-Host "[Unveil WIN] Windows-only one-click setup" -ForegroundColor Cyan
Write-Host ""

# 1) Standard path
if (!(Test-Path $WinPath)) { New-Item -ItemType Directory -Path $WinPath -Force | Out-Null }
Write-Host "[1/5] Path: $WinPath" -ForegroundColor Green

# 2) Clear WSL/stale daemon config so extension uses 127.0.0.1:8000 (no "connectivity ghost")
$configPath = Join-Path $env:USERPROFILE ".unveil\config.json"
if (Test-Path $configPath) {
  Remove-Item $configPath -Force
  Write-Host "[2/5] Removed old config (WSL/stale) so daemon URL = 127.0.0.1:8000" -ForegroundColor Green
} else {
  Write-Host "[2/5] No existing daemon config; extension will use 127.0.0.1:8000" -ForegroundColor Green
}

# 3) Latest release
Write-Host "[3/5] Fetching latest release..." -ForegroundColor Yellow
try {
  $json = Invoke-RestMethod -Uri $Api -Headers @{ "User-Agent" = "Unveil-WIN-Setup" }
} catch {
  Write-Host "      API failed. Use fallback URLs from Releases page." -ForegroundColor Yellow
  $json = $null
}
$engineUrl = $null
$jarUrl = $null
if ($json) {
  $winExe = $json.assets | Where-Object { $_.name -eq "unveil-engine-WIN.exe" } | Select-Object -First 1
  $jarAsset = $json.assets | Where-Object { $_.name -like "unveil-burp*.jar" } | Select-Object -First 1
  $engineUrl = $winExe.browser_download_url
  $jarUrl = $jarAsset.browser_download_url
}
if (-not $engineUrl -or -not $jarUrl) {
  Write-Host "      Could not resolve WIN exe or JAR from API. Download from: https://github.com/$Repo/releases" -ForegroundColor Red
  exit 1
}

# 4) Download WIN engine and JAR
$enginePath = Join-Path $WinPath "unveil-engine-WIN.exe"
$jarPath = Join-Path $WinPath "unveil-burp.jar"
Write-Host "[4/5] Downloading unveil-engine-WIN.exe..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $engineUrl -OutFile $enginePath -UseBasicParsing
Write-Host "      $enginePath" -ForegroundColor Green
Write-Host "      Downloading unveil-burp.jar..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $jarUrl -OutFile $jarPath -UseBasicParsing
Write-Host "      $jarPath" -ForegroundColor Green

# 5) Firewall rule (WIN-labeled)
Write-Host "[5/5] Firewall rule (Unveil-WIN-Internal, port 8000)..." -ForegroundColor Yellow
try {
  New-NetFirewallRule -DisplayName "Unveil-WIN-Internal" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000 -ErrorAction Stop | Out-Null
  Write-Host "      Rule added." -ForegroundColor Green
} catch {
  Write-Host "      Run as Administrator to add rule, or allow port 8000 manually." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done (WIN). Next steps:" -ForegroundColor Cyan
Write-Host "  1. In Burp: remove any existing Unveil extension (Extensions tab)."
Write-Host "  2. Add -> Java -> select: $jarPath"
Write-Host "  3. Check Output tab: 'Unveil: backend started automatically from ...\unveil-engine-WIN.exe'"
Write-Host "  4. Daemon URL is 127.0.0.1:8000 (no WSL). Click Scan."
Write-Host ""
