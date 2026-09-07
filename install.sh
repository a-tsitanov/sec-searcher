#!/usr/bin/env bash
# Keep all work inside main so a truncated curl response cannot start installation.
set -euo pipefail

main() {
    local repo='' ref='main' target="${HOME}/sec-searcher" source_dir='' build_only=0
    local model='Qwen3.6-35B-A3B-UD-Q3_K_M.gguf' download=1
    local default_model='Qwen3.6-35B-A3B-UD-Q3_K_M.gguf'
    local expected='1b715841683f960bd9a49f008181bd910ee169b78d4cf465b6fde7f4d929ff99'
    local revision='a483e9e6cbd595906af30beda3187c2663a1118c'
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --repo|--ref|--dir|--source-dir|--model-file)
                [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "Missing value for $1" >&2; return 2; }
                case "$1" in
                    --repo) repo=$2 ;; --ref) ref=$2 ;; --dir) target=$2 ;;
                    --source-dir) source_dir=$2 ;; --model-file) model=$2 ;;
                esac
                shift 2 ;;
            --build-only) build_only=1; shift ;;
            --no-download) download=0; shift ;;
            --help|-h)
                cat <<'HELP'
Usage: bash install.sh [options]
  --repo HTTPS_URL    Git repository to clone (required for remote installation)
  --ref REF          Branch, tag or commit to check out on first install (default: main)
  --dir PATH         Installation directory (default: ~/sec-searcher)
  --source-dir PATH  Build an existing checkout instead of cloning
  --model-file NAME  Existing GGUF filename in models/ (default: Unsloth Qwen3.6 35B Q3)
  --no-download      Require an existing model; never download weights
  --build-only       Build app image only; do not download/load a model or start services
  --help             Show help
Requires Docker with Compose v2. Remote installation also needs git.
Default full install downloads ~16.6 GB of weights and runs CPU llama.cpp.
Existing checkouts are reused without git pull or overwriting local changes.
HELP
                return 0 ;;
            *) echo "Unknown option: $1" >&2; return 2 ;;
        esac
    done
    [[ "$model" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*\.gguf$ ]] || { echo 'Invalid GGUF filename' >&2; return 2; }
    command -v docker >/dev/null || { echo 'Install Docker with Compose v2 first: https://docs.docker.com/get-started/get-docker/' >&2; return 1; }
    docker info >/dev/null || { echo 'Start Docker and check daemon access.' >&2; return 1; }
    docker compose version >/dev/null || { echo 'Docker Compose v2 is required.' >&2; return 1; }

    if [[ -z "$source_dir" && -z "$repo" ]]; then
        local script_dir=''
        if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
            script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
        elif [[ -f pyproject.toml && -f compose.yaml ]]; then
            script_dir=$PWD
        fi
        [[ -n "$script_dir" && -f "$script_dir/pyproject.toml" ]] || {
            echo 'Remote installation requires --repo https://.../sec-searcher.git (or --source-dir PATH).' >&2; return 2;
        }
        source_dir=$script_dir
    fi
    if [[ -n "$source_dir" ]]; then
        [[ -z "$repo" ]] || { echo 'Use either --repo or --source-dir.' >&2; return 2; }
        cd -- "$source_dir"
    else
        [[ "$repo" == https://* && "$ref" != -* ]] || { echo 'Use an HTTPS repository URL and a valid ref.' >&2; return 2; }
        command -v git >/dev/null || { echo 'git is required to download the project.' >&2; return 1; }
        if [[ -e "$target" ]]; then
            [[ -d "$target/.git" ]] || { echo 'Destination exists and is not a Git checkout; use --source-dir explicitly.' >&2; return 1; }
            [[ "$(git -C "$target" remote get-url origin)" == "$repo" ]] || { echo 'Destination belongs to a different repository.' >&2; return 1; }
            echo 'Reusing existing checkout; no automatic updates or resets.'
        else
            mkdir -p -- "$(dirname -- "$target")"
            git clone --no-checkout -- "$repo" "$target"
            git -C "$target" checkout --detach "$ref"
        fi
        cd -- "$target"
    fi
    local file
    for file in pyproject.toml uv.lock Dockerfile compose.yaml src/sec_searcher/api.py; do
        [[ -f "$file" ]] || { echo "Not a Sec Searcher checkout: missing $file" >&2; return 1; }
    done
    export MODEL_FILE="$model"
    docker compose config --quiet
    docker compose build app
    if [[ "$build_only" == 1 ]]; then
        echo "Build complete: $PWD (services were not started)."
        return 0
    fi
    mkdir -p models
    if [[ ! -f "models/$model" ]]; then
        [[ "$download" == 1 && "$model" == "$default_model" ]] || {
            echo "Place your GGUF at $PWD/models/$model and rerun." >&2; return 1;
        }
        command -v curl >/dev/null || { echo 'curl is required to download the default model.' >&2; return 1; }
        echo 'Downloading Unsloth Qwen3.6 35B (~16.6 GB); interrupted downloads can be resumed.'
        curl --fail --location --proto '=https' --proto-redir '=https' \
            --retry 3 --connect-timeout 30 --speed-time 120 --speed-limit 1024 \
            --continue-at - --output "models/$model.part" \
            "https://huggingface.co/unsloth/Qwen3.6-35B-A3B-GGUF/resolve/$revision/$model"
    fi
    if [[ "$model" == "$default_model" ]]; then
        local candidate="models/$model" actual
        [[ -f "$candidate" ]] || candidate="$candidate.part"
        echo 'Verifying model SHA256...'
        if command -v sha256sum >/dev/null; then
            actual=$(sha256sum "$candidate")
        elif command -v shasum >/dev/null; then
            actual=$(shasum -a 256 "$candidate")
        else
            echo 'sha256sum or shasum is required.' >&2; return 1
        fi
        [[ "${actual%% *}" == "$expected" ]] || { echo "Model SHA256 mismatch: $candidate; services not started." >&2; return 1; }
        [[ "$candidate" == "models/$model" ]] || mv -- "$candidate" "models/$model"
    fi
    # Separate installer settings preserve an existing .env.
    printf 'MODEL_FILE=%s\n' "$model" > .env.install
    docker compose --env-file .env.install up -d --wait --wait-timeout 180
    echo "Installed in: $PWD"
    echo 'Web UI: http://127.0.0.1:8765'
    echo 'Model loading may take longer; check: docker compose --env-file .env.install logs -f llama'
    echo 'Stop: docker compose --env-file .env.install down'
}

main "$@"
