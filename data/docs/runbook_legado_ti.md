---
id: runbook_legado_ti
title: Runbook do sistema legado de conciliação
acl: [ti]
classification: restrito
---
# Runbook do sistema legado de conciliação

Para reiniciar o serviço de conciliação, acesse o servidor de batch e execute o script de restart com o usuário de serviço.

Conexão do banco de dados (credencial fictícia, deve ser recusada na ingestão): postgres://conciliacao:Fict1c1a-Nao-Usar-2026@db-legado.interno:5432/conciliacao

Após o restart, confira se a fila de arquivos do dia foi processada.
