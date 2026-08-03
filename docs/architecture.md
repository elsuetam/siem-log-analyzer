# Arquitetura — SIEM / Log Analyzer

## Visão geral

O sistema é organizado em um pipeline de etapas independentes, cada uma isolada em seu próprio
módulo dentro de `src/siem/`, comunicando-se apenas através de contratos bem definidos (interfaces
abstratas e modelos de dados).

## Fluxo de dados (pipeline)