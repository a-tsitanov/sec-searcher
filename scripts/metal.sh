#!/usr/bin/env bash
set -euo pipefail
main() {
    local action=${1:-start} model=${2:-Qwen3.6-35B-A3B-UD-Q3_K_M.gguf}
    local root label binary devices i job
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
    cd -- "$root"
    [[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo 'Metal mode requires Apple Silicon macOS.' >&2; return 1; }
    [[ "$model" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.gguf$ ]] || { echo 'Invalid model filename' >&2; return 2; }
    mkdir -p .runtime
    case "$action" in start|stop|status) ;; *) echo 'Usage: bash scripts/metal.sh start|stop|status [MODEL_FILE]' >&2; return 2 ;; esac
    label="local.sec-searcher.metal.$(printf '%s' "$root" | shasum -a 256 | cut -c 1-16)"
    job=$(launchctl list "$label" 2>/dev/null || true)
    if [[ -n "$job" ]]; then
        if [[ "$action" == stop ]]; then
            launchctl remove "$label"
            echo 'Metal launchd job stopped.'
            return 0
        fi
        if [[ "$action" == status ]]; then
            printf '%s\n' "$job"
            return 0
        fi
        if [[ "$job" == *'"PID"'* ]]; then
            [[ -f .runtime/metal.model && "$(cat .runtime/metal.model)" == "$model" ]] || {
                echo 'A different managed model is running; stop it first.' >&2; return 1;
            }
            curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8080/health >/dev/null || {
                echo 'Managed model is not ready; see .runtime/metal.log.' >&2; return 1;
            }
            echo 'Metal launchd job already running and healthy.'
            return 0
        fi
        launchctl remove "$label"
    fi
    if [[ "$action" != start ]]; then
        echo 'Managed Metal llama-server is not running.'
        return 0
    fi
    command -v curl >/dev/null
    if /usr/sbin/lsof -nP -iTCP:8080 -sTCP:LISTEN >/dev/null 2>&1; then
        echo 'Port 8080 is occupied. Stop the existing server before starting managed Metal.' >&2
        return 1
    fi
    [[ -f "models/$model" ]] || { echo "Missing models/$model" >&2; return 1; }
    if ! command -v llama-server >/dev/null; then
        command -v brew >/dev/null || { echo 'Install Homebrew, then rerun (https://brew.sh).' >&2; return 1; }
        brew install llama.cpp
    fi
    binary=$(command -v llama-server)
    devices=$("$binary" --list-devices 2>&1)
    [[ "$devices" == *Metal* || "$devices" == *MTL[0-9]* ]] || { echo 'This llama-server has no available Metal device.' >&2; return 1; }
    printf '%s\n' "$model" > .runtime/metal.model
    launchctl submit -l "$label" -o "$root/.runtime/metal.log" -e "$root/.runtime/metal.log" -- \
        "$binary" -m "$root/models/$model" --alias sec-qwen36-unsloth \
        --host 127.0.0.1 --port 8080 -c 32768 -np 1 --n-gpu-layers 999 \
        --jinja --reasoning off --chat-template-kwargs '{"enable_thinking":false}' \
        --cache-ram 0
    for i in {1..180}; do
        job=$(launchctl list "$label" 2>/dev/null || true)
        if [[ "$job" != *'"PID"'* ]]; then
            echo "llama-server failed; see $root/.runtime/metal.log" >&2; return 1
        fi
        if curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:8080/health >/dev/null 2>&1; then
            echo "Metal ready. Log: $root/.runtime/metal.log"
            return 0
        fi
        sleep 2
    done
    echo 'Model still loading; inspect .runtime/metal.log or stop with bash scripts/metal.sh stop.' >&2
    return 1
}
main "$@"
