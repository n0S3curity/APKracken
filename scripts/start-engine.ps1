# Runs the open-kritt engine natively on Windows (local-only Android build).
# Loads .env.native from the repo root, then launches the engine from its venv.
#
# Prereqs (Phase 0):
#   1. Postgres up:   docker compose up -d db
#   2. Model up:      scripts\start-llm.ps1   (optional for an idle boot)
#   3. Engine venv:   python -m venv engine\.venv; engine\.venv\Scripts\pip install -r engine\requirements.txt
param(
  [switch]$Once  # boot, log ~10s, then exit (smoke test) instead of running forever
)
$ErrorActionPreference = "Stop"
$root    = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root ".env.native"
if (Test-Path $envFile) {
  Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and (-not $line.StartsWith("#")) -and $line.Contains("=")) {
      $parts = $line -split "=", 2
      [System.Environment]::SetEnvironmentVariable($parts[0].Trim(), $parts[1].Trim(), "Process")
    }
  }
  Write-Host "Loaded env from .env.native"
} else {
  Write-Warning ".env.native not found; relying on ambient environment."
}
$env:PYTHONUNBUFFERED = "1"
$py = Join-Path $root "engine\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Engine venv not found at $py. Create it (see header)." }
Push-Location (Join-Path $root "engine")
try {
  if ($Once) {
    $p = Start-Process -FilePath $py -ArgumentList "-m","open_kritt_engine" -NoNewWindow -PassThru
    Start-Sleep -Seconds 10
    if (-not $p.HasExited) { $p.Kill() }
    Write-Host "Smoke boot complete."
  } else {
    & $py -m open_kritt_engine
  }
} finally { Pop-Location }
