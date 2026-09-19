# Full restart of the local open-kritt stack (Android research build).
# Stops and restarts: engine worker (native), llama.cpp server (native),
# and the Docker services (Postgres + backend + frontend UI).
#
# Usage:   .\scripts\restart.ps1
#          .\scripts\restart.ps1 -NoLlm     # leave llama-server running (skip its restart)
#          .\scripts\restart.ps1 -NoDb      # leave Postgres running (skip its restart)
param(
  [switch]$NoLlm,   # do not restart llama-server (keep the model warm)
  [switch]$NoDb     # do not restart Postgres
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

function Stop-Native([string]$match, [string]$label) {
  $procs = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='llama-server.exe'" |
    Where-Object { $_.CommandLine -match $match }
  foreach ($p in $procs) {
    Write-Host "  stopping $label (PID $($p.ProcessId))"
    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
  }
}

Write-Host "== stopping native processes ==" -ForegroundColor Cyan
Stop-Native 'open_kritt'    'engine worker'
if (-not $NoLlm) { Stop-Native 'llama-server' 'llama-server' }
Start-Sleep -Seconds 2

Write-Host "== restarting docker services ==" -ForegroundColor Cyan
$services = @('open-kritt-backend', 'open-kritt-frontend')
if (-not $NoDb) { $services = @('open-kritt-db') + $services }
docker restart @services | ForEach-Object { Write-Host "  restarted $_" }

# Relaunch llama-server (its own launcher loads the known-good model command).
if (-not $NoLlm) {
  Write-Host "== starting llama-server ==" -ForegroundColor Cyan
  Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-File',(Join-Path $PSScriptRoot 'start-llm.ps1')
  Write-Host "  waiting for model to load (port 8091)..."
  for ($i = 0; $i -lt 40; $i++) {
    try {
      if ((Invoke-WebRequest -Uri 'http://127.0.0.1:8091/health' -TimeoutSec 2 -UseBasicParsing).Content -match 'ok') {
        Write-Host "  llama-server ready"; break
      }
    } catch { Start-Sleep -Seconds 3 }
  }
}

# Relaunch the engine worker (its launcher loads .env.native: DB, LLM, jadx/apktool,
# ENGINE_DYNAMIC_INVESTIGATION, etc.).
Write-Host "== starting engine worker ==" -ForegroundColor Cyan
Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-File',(Join-Path $PSScriptRoot 'start-engine.ps1')

Write-Host "== done. stack restarted ==" -ForegroundColor Green
Write-Host "  UI:      http://127.0.0.1:5173"
Write-Host "  backend: http://127.0.0.1:3002"
Write-Host "  model:   http://127.0.0.1:8091"
