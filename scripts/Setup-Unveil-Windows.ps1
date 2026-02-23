# Unveil — Windows-only (WIN) one-click setup. Locked to localhost; no WSL.
# Drops unveil-engine-WIN.exe + JAR into %LOCALAPPDATA%\Unveil, nukes stale config, opens firewall.
# Usage: irm https://raw.githubusercontent.com/Pa7ch3s/Unveil/main/scripts/Setup-Unveil-Windows.ps1 | iex
#    or: .\scripts\Setup-Unveil-Windows.ps1  (Admin PowerShell recommended for firewall)
$ErrorActionPreference = "Stop"
$Repo = "Pa7ch3s/Unveil"
$WinPath = Join-Path $env:LOCALAPPDATA "Unveil"
$Api = "https://api.github.com/repos/$Repo/releases/latest"
$FallbackTag = "v0.10.10"
$FallbackEngineUrl = "https://github.com/$Repo/releases/download/$FallbackTag/unveil-engine-WIN.exe"
$FallbackJarUrl = "https://github.com/$Repo/releases/download/$FallbackTag/unveil-burp-0.7.6.jar"

Write-Host "[Unveil WIN] Windows-only one-click setup (localhost only, no WSL)" -ForegroundColor Cyan
Write-Host ""

# 1) Clean-sweep: standard path + nuke old WSL/stale config
if (!(Test-Path $WinPath)) { New-Item -ItemType Directory -Path $WinPath -Force | Out-Null }
Write-Host "[1/5] Path: $WinPath" -ForegroundColor Green
Remove-Item -Path "$env:USERPROFILE\.unveil\config.json" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$home\.unveil\config.json" -Force -ErrorAction SilentlyContinue
Write-Host "[2/5] Cleared any WSL/stale config; extension will use 127.0.0.1:8000 only" -ForegroundColor Green

# 3) Latest release (with direct fallback links if API fails)
Write-Host "[3/5] Fetching latest release..." -ForegroundColor Yellow
$engineUrl = $null
$jarUrl = $null
try {
  $json = Invoke-RestMethod -Uri $Api -Headers @{ "User-Agent" = "Unveil-WIN-Setup" }
  if ($json) {
    $winExe = $json.assets | Where-Object { $_.name -eq "unveil-engine-WIN.exe" } | Select-Object -First 1
    $jarAsset = $json.assets | Where-Object { $_.name -like "unveil-burp*.jar" } | Select-Object -First 1
    if ($winExe) { $engineUrl = $winExe.browser_download_url }
    if ($jarAsset) { $jarUrl = $jarAsset.browser_download_url }
  }
} catch {
  Write-Host "      API failed; using direct fallback links for $FallbackTag" -ForegroundColor Yellow
}
if (-not $engineUrl) { $engineUrl = $FallbackEngineUrl; Write-Host "      Engine: $FallbackEngineUrl" -ForegroundColor Yellow }
if (-not $jarUrl) { $jarUrl = $FallbackJarUrl; Write-Host "      JAR: $FallbackJarUrl" -ForegroundColor Yellow }

# 4) Download WIN engine and JAR
$enginePath = Join-Path $WinPath "unveil-engine-WIN.exe"
$jarPath = Join-Path $WinPath "unveil-burp.jar"
Write-Host "[4/5] Downloading unveil-engine-WIN.exe..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $engineUrl -OutFile $enginePath -UseBasicParsing
Write-Host "      $enginePath" -ForegroundColor Green
Write-Host "      Downloading unveil-burp.jar..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $jarUrl -OutFile $jarPath -UseBasicParsing
Write-Host "      $jarPath" -ForegroundColor Green

# 5) Firewall rule (WIN-labeled) — duplicate rule is ignored
Write-Host "[5/5] Firewall rule (Unveil-WIN-Internal, port 8000)..." -ForegroundColor Yellow
New-NetFirewallRule -DisplayName "Unveil-WIN-Internal" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000 -ErrorAction SilentlyContinue | Out-Null
Write-Host "      Rule added or already present." -ForegroundColor Green

Write-Host ""
Write-Host "Done (WIN). Next steps:" -ForegroundColor Cyan
Write-Host "  1. In Burp: remove any existing Unveil extension (Extensions tab)."
Write-Host "  2. Add -> Java -> select: $jarPath"
Write-Host "  3. Check Output tab: 'Unveil: backend started automatically from ...\unveil-engine-WIN.exe'"
Write-Host "  4. Daemon URL is 127.0.0.1:8000 (no WSL). Click Scan."
Write-Host ""
Write-Host "Direct download links (if you need to re-download manually):" -ForegroundColor DarkGray
Write-Host "  Engine: $FallbackEngineUrl"
Write-Host "  JAR:    $FallbackJarUrl"
Write-Host ""
