#!/usr/bin/env bash
# Sobe LiteLLM Proxy e gateway em segundo plano e espera os dois ficarem saudáveis.
# Usado no CI e localmente (Linux, macOS ou Git Bash). Requer Ollama rodando com os modelos baixados.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${LITELLM_MASTER_KEY:?defina LITELLM_MASTER_KEY}"
export CHAT_MODEL="${CHAT_MODEL:-ollama_chat/qwen2.5:0.5b}"
export OLLAMA_API_BASE="${OLLAMA_API_BASE:-http://127.0.0.1:11434}"
export LLM_BASE_URL="${LLM_BASE_URL:-http://127.0.0.1:4000}"
export LLM_API_KEY="$LITELLM_MASTER_KEY"
export PYTHONIOENCODING=utf-8
mkdir -p logs

wait_for() {  # curl reentra sozinho até o serviço responder (~4 min no máximo)
  curl -sf --retry 120 --retry-delay 2 --retry-connrefused --retry-all-errors "$1" > /dev/null
}

nohup uvx --python 3.12 --from "litellm[proxy]==${LITELLM_VERSION:-1.106.2}" \
  litellm --config litellm/config.yaml --host 127.0.0.1 --port 4000 > logs/litellm.log 2>&1 &
echo $! > logs/litellm.pid
wait_for http://127.0.0.1:4000/health/liveliness
echo "LiteLLM pronto"

nohup uv run uvicorn secure_rag_gateway.app:app --host 127.0.0.1 --port 8000 > logs/gateway.log 2>&1 &
echo $! > logs/gateway.pid
wait_for http://127.0.0.1:8000/healthz
echo "Gateway pronto: http://127.0.0.1:8000"
