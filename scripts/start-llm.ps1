# ==========================================================================
#  Start Qwen3-Coder-30B-A3B on llama.cpp  (RTX 5080 optimized)
#  ~71 tok/s | ~14.6 GB VRAM | GPU-loaded MoE, experts partly on CPU RAM
#  OpenAI-compatible API + web UI at http://127.0.0.1:8091
# ==========================================================================

$Exe   = "C:\Users\Maor2\OneDrive\Desktop\TOOLS\llama-b9305-bin-win-cuda-13.1-x64\llama-server.exe"
$Model = "C:\Users\Maor2\Models\Qwen3-Coder-30B-A3B-Instruct-UD-Q4_K_XL.gguf"
$Port  = 8091

# --- tunables ---------------------------------------------------------------
# NCpuMoe: MoE expert layers kept on CPU (of 48). Lower = more on GPU/faster,
#          but more VRAM. 20 = benchmarked sweet spot. Raise to 22 if you need
#          more VRAM headroom (e.g. other GPU apps); it costs a little speed.
$NCpuMoe = 20
# 49152 ctx (was 32768) — the scan agents' investigation prompts were exceeding 32768 and
# getting rejected. q8_0 KV cache (below) HALVES the KV memory, so this larger context still
# fits ~14 GB VRAM (actually a touch less than the old f16/32k config). Raise toward 65536 only
# if you free GPU memory (close other GPU apps / raise $NCpuMoe).
$CtxSize = 49152
# ----------------------------------------------------------------------------

$env:CUDA_VISIBLE_DEVICES = "0"

if (-not (Test-Path $Exe))   { Write-Host "ERROR: llama-server not found at $Exe" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $Model)) { Write-Host "ERROR: model not found at $Model" -ForegroundColor Red; exit 1 }

# Stop any existing instance so the port/VRAM is free
Get-CimInstance Win32_Process -Filter "Name='llama-server.exe'" |
    ForEach-Object { Write-Host "Stopping existing llama-server (PID $($_.ProcessId))"; Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

Write-Host "Starting Qwen3-Coder-30B-A3B  (n-cpu-moe=$NCpuMoe, ctx=$CtxSize)..." -ForegroundColor Cyan

& $Exe `
    -m $Model `
    -ngl 99 `
    --n-cpu-moe $NCpuMoe `
    --no-mmap `
    --ctx-size $CtxSize `
    --parallel 1 `
    --flash-attn on `
    --cache-type-k q8_0 `
    --cache-type-v q8_0 `
    --temp 0.7 `
    --top-p 0.8 `
    --top-k 20 `
    --repeat-penalty 1.05 `
    --alias local `
    --host 0.0.0.0 `
    --port $Port

# (llama-server runs in the foreground here; press Ctrl+C in this window to stop it.)
# Web UI / API once it prints "listening":  http://127.0.0.1:8091
