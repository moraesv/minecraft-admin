# start-mcpanel.sh
#!/bin/bash

# Caminho base do projeto (pode ser passado via variável de ambiente)
BASE_DIR="${BASE_DIR:-$HOME/minecraft-panel}"

# Exporta variáveis do .env
set -a
source "$BASE_DIR/.env"
set +a

# Fecha a sessão screen se já existir (evita múltiplas sessões)
screen -S mcpanel -X quit || true

# Navega até o diretório do painel
cd "$BASE_DIR"

# Inicia o painel dentro de uma nova sessão screen
screen -dmS mcpanel ./minecraft-panel
