# ElectrumSV-Mc Startup Script (Tauri native mode) — Windows PowerShell
# Equivalent of start.sh for Windows development.
$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ProjectDir

# Standalone data directory — everything stays in the project folder
$DataDir = Join-Path $ProjectDir "data"
$env:ELECTRUMSV_DATA_DIR = $DataDir
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Write-Host "Starting ElectrumSV-Mc (Tauri native mode)..."
Write-Host "  Data directory: $DataDir"
Write-Host ""

# Check if GUI dependencies are installed
$ViteDir = Join-Path $ProjectDir "gui\node_modules\vite"
if (-not (Test-Path $ViteDir)) {
    Write-Host "Installing GUI dependencies (first run)..."
    Set-Location (Join-Path $ProjectDir "gui")
    npm install
}

# Launch Tauri dev mode (Rust backend + React frontend in one process)
Set-Location (Join-Path $ProjectDir "src-tauri")
cargo tauri dev