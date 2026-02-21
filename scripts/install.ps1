# One-shot install: CLI (pipx/pip) + Burp JAR + daemon exe from latest release.
# Usage: irm https://raw.githubusercontent.com/Pa7ch3s/Unveil/main/scripts/install.ps1 | iex
#    or: .\scripts\install.ps1   (from repo root)
$ErrorActionPreference = "Stop"
$Repo = "Pa7ch3s/Unveil"
$InstallDir = if ($env:UNVEIL_INSTALL_DIR) { $env:UNVEIL_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Unveil" }
$Api = "https://api.github.com/repos/$Repo/releases/latest"

Write-Host "[Unveil] One-shot install (CLI + Burp extension + daemon exe)" -ForegroundColor Cyan
Write-Host ""

# 1) Install CLI
Write-Host "[1/4] Installing CLI..." -ForegroundColor Yellow
$pipx = Get-Command pipx -ErrorAction SilentlyContinue
$pip = Get-Command pip -ErrorAction SilentlyContinue
if ($pipx) {
  pipx install "git+https://github.com/$Repo.git"
  Write-Host "      CLI: pipx (run 'unveil -h')" -ForegroundColor Green
} elseif ($pip) {
  pip install --user "git+https://github.com/$Repo.git"
  Write-Host "      CLI: pip (run 'unveil -h')" -ForegroundColor Green
} else {
  Write-Host "      No pipx or pip found. Install Python 3, then re-run." -ForegroundColor Red
  exit 1
}

# 2) Fetch latest release
Write-Host "[2/4] Fetching latest release..." -ForegroundColor Yellow
try {
  $json = Invoke-RestMethod -Uri $Api -Headers @{ "User-Agent" = "Unveil-Install" }
} catch {
  Write-Host "      API failed. Using fallback URLs (v0.10.7)." -ForegroundColor Yellow
  $jarUrl = "https://github.com/$Repo/releases/download/v0.10.7/unveil-burp-0.7.5.jar"
  $exeUrl = "https://github.com/$Repo/releases/download/v0.10.7/unveil-daemon.exe"
  $json = $null
}
if ($json) {
  $jarAsset = $json.assets | Where-Object { $_.name -like "unveil-burp*.jar" } | Select-Object -First 1
  $exeAsset = $json.assets | Where-Object { $_.name -eq "unveil-daemon.exe" } | Select-Object -First 1
  $jarUrl = $jarAsset.browser_download_url
  $exeUrl = $exeAsset.browser_download_url
  if (-not $jarUrl) { $jarUrl = "https://github.com/$Repo/releases/download/v0.10.7/unveil-burp-0.7.5.jar" }
  if (-not $exeUrl) { $exeUrl = "https://github.com/$Repo/releases/download/v0.10.7/unveil-daemon.exe" }
}

# 3) Download JAR and exe
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$jarPath = Join-Path $InstallDir "unveil-burp.jar"
$exePath = Join-Path $InstallDir "unveil-daemon.exe"

Write-Host "[3/4] Downloading Burp extension JAR..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $jarUrl -OutFile $jarPath -UseBasicParsing
Write-Host "      JAR: $jarPath" -ForegroundColor Green

Write-Host "[4/4] Downloading daemon exe..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $exeUrl -OutFile $exePath -UseBasicParsing
Write-Host "      EXE: $exePath" -ForegroundColor Green

Write-Host ""
Write-Host "Done. Next steps:" -ForegroundColor Cyan
Write-Host "  * CLI:   run 'unveil -h'"
Write-Host "  * Burp:  Extensions -> Add -> Java -> select: $jarPath"
Write-Host "  * Daemon: run '$exePath' (keep running); in Unveil tab check 'Use daemon' and Scan."
Write-Host ""
