# start-mcpanel.sh
#!/bin/bash

# Caminho base do projeto (pode ser passado via variável de ambiente)
BASE_DIR="${BASE_DIR:-$HOME/minecraft-panel}"

# Navega até o diretório do painel
cd "$BASE_DIR"

# Inicia o painel dentro de uma nova sessão screen
screen -dmS mcpanel ./minecraft-panel
