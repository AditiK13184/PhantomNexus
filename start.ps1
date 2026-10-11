param (
    [switch]$NoAdmin = $false
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check for existing processes on port 8000
$port8000 = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object -First 1
if ($port8000) {
    $proc = Get-Process -Id $port8000.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "[!] Port 8000 is already bound by PID $($port8000.OwningProcess) ($($proc.ProcessName))." -ForegroundColor Yellow
    Write-Host "    If this is an older non-admin backend, close that window or run: Stop-Process -Id $($port8000.OwningProcess) -Force" -ForegroundColor Yellow
}

$backendCmd = "Set-Location '$root\backend'; & '$root\.venv\Scripts\python.exe' -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000"
$frontendCmd = "Set-Location '$root\frontend'; npm run dev"

if ($NoAdmin) {
    Write-Host "Launching backend (Standard privileges)..."
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd
} else {
    Write-Host "Launching backend (Administrator privileges via RunAs)..."
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-Command", $backendCmd
}

Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd

Write-Host "Starting Phantom Nexus..."
Write-Host "  Backend  -> http://127.0.0.1:8000"
Write-Host "  Frontend -> http://localhost:5173"
Write-Host "  Live Monitoring will report elevation status and PID on the UI."

