#!/usr/bin/env bash
# Sobe o Langfuse self-hosted (compose oficial, versão fixada) com segredos aleatórios e projeto inicial.
# Gera .langfuse/.env (fora do git) e imprime as variáveis LANGFUSE_* para o gateway.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${LANGFUSE_VERSION:-v4.67.0}"
DIR=.langfuse
mkdir -p "$DIR"
curl -sfL "https://raw.githubusercontent.com/langfuse/langfuse/${VERSION}/docker-compose.yml" -o "$DIR/docker-compose.yml"

rand() { python -c "import secrets; print(secrets.token_hex($1))"; }
if [ ! -f "$DIR/.env" ]; then
  cat > "$DIR/.env" <<EOF
SALT=$(rand 16)
ENCRYPTION_KEY=$(rand 32)
NEXTAUTH_SECRET=$(rand 32)
LANGFUSE_INIT_ORG_ID=banco-exemplo
LANGFUSE_INIT_ORG_NAME="Banco Exemplo"
LANGFUSE_INIT_PROJECT_ID=secure-rag-gateway
LANGFUSE_INIT_PROJECT_NAME=secure-rag-gateway
LANGFUSE_INIT_PROJECT_PUBLIC_KEY=pk-lf-$(rand 8)
LANGFUSE_INIT_PROJECT_SECRET_KEY=sk-lf-$(rand 16)
LANGFUSE_INIT_USER_EMAIL=admin@bancoexemplo.local
LANGFUSE_INIT_USER_NAME=admin
LANGFUSE_INIT_USER_PASSWORD=$(rand 12)
EOF
fi

docker compose -f "$DIR/docker-compose.yml" --env-file "$DIR/.env" -p langfuse up -d
curl -sf --retry 90 --retry-delay 3 --retry-connrefused --retry-all-errors http://127.0.0.1:3000/api/public/health > /dev/null

# shellcheck disable=SC1091
. "$DIR/.env"
echo "Langfuse pronto em http://127.0.0.1:3000 (login: $LANGFUSE_INIT_USER_EMAIL, senha em $DIR/.env)"
echo "export LANGFUSE_PUBLIC_KEY=$LANGFUSE_INIT_PROJECT_PUBLIC_KEY"
echo "export LANGFUSE_SECRET_KEY=$LANGFUSE_INIT_PROJECT_SECRET_KEY"
echo "export LANGFUSE_BASE_URL=http://127.0.0.1:3000"
