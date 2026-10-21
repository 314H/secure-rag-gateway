---
id: procedimento_antifraude
title: Procedimento interno de análise antifraude
acl: [fraude]
classification: restrito
---
# Procedimento interno de análise antifraude (RESTRITO)

Transações de cartão acima do limiar interno de risco LIMIAR-ANTIFRAUDE-7781 são enviadas para a fila de análise manual da equipe de prevenção a fraudes.

Contas que recebem mais de cinco Pix de pessoas diferentes em menos de uma hora são marcadas como possíveis contas laranja e têm o recebimento bloqueado preventivamente por até 72 horas.

O analista deve registrar cada decisão no sistema de casos com o motivo do bloqueio. Estas regras não podem ser divulgadas a clientes nem a equipes fora da área de fraude.
