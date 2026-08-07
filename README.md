# 🛡️ SIEM / Log Analyzer

Ferramenta de análise de logs e detecção de ameaças (Blue Team), desenvolvida em Python com foco em arquitetura limpa, modularidade e boas práticas de engenharia de software.

![Python](https://img.shields.io/badge/python-3.13-blue)
![Tests](https://img.shields.io/badge/tests-115%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)
![mypy](https://img.shields.io/badge/mypy-strict-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## O que é

Um SIEM (*Security Information and Event Management*) simplificado que lê logs de acesso web, detecta padrões de ataque conhecidos, calcula um score de risco por IP de origem, gera incidentes formais e produz relatórios visuais (dashboard HTML) e exportáveis (PDF) — todo o pipeline que um analista de segurança percorre manualmente, automatizado.

## Por que este projeto

Construído para demonstrar, na prática, competências centrais de engenharia de software aplicadas a cibersegurança:

- **Detecção de ameaças reais**: brute force, scanning/reconhecimento, SQL Injection e Directory Traversal — cobrindo vetores centrais do OWASP Top 10
- **Classificação por padrão de indústria**: cada detecção é mapeada para uma técnica [MITRE ATT&CK](https://attack.mitre.org/), o framework usado por analistas SOC no mundo real
- **Engenharia de software disciplinada**: arquitetura em camadas, interfaces abstratas, tipagem estrita, 115 testes automatizados, 96% de cobertura
- **Pipeline completo e funcional**: da leitura do log bruto ao relatório final, sem etapas manuais

## Funcionalidades

| Categoria | Detalhe |
|---|---|
| **Parsing** | Combined Log Format (Apache/Nginx), com tratamento robusto de linhas malformadas |
| **Detecção** | Brute Force, Active Scanning, SQL Injection, Directory Traversal |
| **Classificação** | Score de risco por IP (0–100), mapeamento MITRE ATT&CK por técnica |
| **Enriquecimento** | Geolocalização de IP via API pública (opcional, com fallback seguro se offline) |
| **Saída** | Dashboard HTML interativo (gráficos de severidade e top IPs) + relatório PDF exportável |
| **Configuração** | Todos os thresholds de detecção ajustáveis via `.env`, sem hardcoding |

## Arquitetura

Logs brutos (data/raw_logs/)
│
▼
[Parser] ──► LogEntry (normalizado)
│
▼
[Detectores] ──► DetectionEvent (+ técnica MITRE ATT&CK)
│ │ │ │
│ │ │ └─ Directory Traversal
│ │ └───── SQL Injection
│ └───────── Active Scanning
└───────────── Brute Force
│
▼
[Score de Risco] ──► RiskScore por IP (0–100)
│
▼
[Geração de Incidentes] ──► Incident (+ GeoIP opcional)
│
├──► Dashboard HTML (gráficos + lista de incidentes)
└──► Relatório PDF (resumo executivo + detalhamento)

Cada camada se comunica através de modelos de dados tipados (Pydantic) — parsers e detectores não conhecem nada sobre relatórios ou dashboard, e novos detectores podem ser adicionados sem alterar o restante do pipeline (interface `BaseDetector`). Detalhes de design em [`docs/architecture.md`](docs/architecture.md).

## Stack técnica

- **Python 3.13** com tipagem estrita (`mypy --strict`)
- **Pydantic v2** — validação e modelagem de dados
- **Jinja2** — geração do dashboard HTML
- **ReportLab** — geração de relatórios PDF
- **pytest** + **pytest-cov** — 115 testes, 96% de cobertura
- **ruff** — linting e formatação
- Sem dependências de banco de dados ou serviços externos obrigatórios — roda 100% local

## Instalação

```bash
git clone <url-do-repositorio>
cd siem-log-analyzer
python -m venv .venv
```

Windows:
```powershell
.venv\Scripts\activate
```
Linux/macOS:
```bash
source .venv/bin/activate
```

```bash
pip install -r requirements-dev.txt
pip install pydantic-settings requests reportlab pypdf
```

Copie o arquivo de configuração de exemplo:
```bash
cp .env.example .env
```

## Uso

1. Coloque arquivos de log (formato Combined Log Format) em `data/raw_logs/`
2. Execute:
```bash
python -m siem.main
```
3. Resultados gerados em:
   - `output/dashboards/dashboard.html` — dashboard interativo
   - `output/reports/report.pdf` — relatório exportável

### Opções de linha de comando

```bash
python -m siem.main --log-file caminho/para/arquivo.log   # processa um arquivo específico
python -m siem.main --version                               # mostra a versão
```

### Configuração (`.env`)

Todos os thresholds de detecção são ajustáveis sem alterar código:

```env
SIEM_BRUTE_FORCE_ATTEMPTS_THRESHOLD=5
SIEM_BRUTE_FORCE_WINDOW_SECONDS=60
SIEM_SCANNER_REQUESTS_THRESHOLD=20
SIEM_INCIDENT_RISK_SCORE_THRESHOLD=25.0
SIEM_ENABLE_GEOIP=false
```

Ver `.env.example` para a lista completa de opções.

## Rodando os testes

```bash
pytest --cov=siem --cov-report=term-missing
ruff check .
mypy src
```

## Estrutura do projeto

src/siem/
├── parsers/ # Interpretação de formatos de log (Combined Log Format)
├── detectors/ # Brute Force, Scanner, SQL Injection, Directory Traversal
├── models/ # LogEntry, DetectionEvent, RiskScore, Incident (Pydantic)
├── analysis/ # Cálculo de score de risco agregado
├── incidents/ # Geração de incidentes formais
├── enrichment/ # Enriquecimento GeoIP
├── mitre/ # Catálogo de técnicas MITRE ATT&CK
├── dashboard/ # Renderização do dashboard HTML
├── reports/ # Geração de relatórios PDF
└── config/ # Configurações centralizadas (.env)

tests/
├── unit/ # Testes isolados por módulo
└── integration/ # Testes de pipeline completo (ponta a ponta)

## Destaques técnicos

Pontos deste projeto que valem destaque em uma conversa técnica:

- **Sliding window com ponteiro duplo** para detecção de padrões temporais (brute force, scanning) — O(n) por IP, sem sobreposição de detecções
- **Injeção de dependência** em `GeoIPEnricher` (função HTTP injetável) — permite testar 100% da lógica sem chamadas de rede reais
- **Falha isolada por design**: enriquecimento GeoIP nunca derruba o pipeline principal, mesmo com API fora do ar
- **Interfaces abstratas** (`BaseParser`, `BaseDetector`) — novos formatos de log ou detectores se conectam sem alterar código existente
- **Modelos imutáveis e tipados** de ponta a ponta — nenhum dicionário solto trafegando entre camadas

## Roadmap

- [x] Parser de logs (Combined Log Format)
- [x] Detectores: Brute Force, Active Scanning, SQL Injection, Directory Traversal
- [x] Score de risco e geração de incidentes
- [x] Dashboard HTML com gráficos
- [x] Exportação de relatórios PDF
- [x] Enriquecimento GeoIP
- [x] Mapeamento MITRE ATT&CK
- [ ] Containerização (Docker)
- [ ] Sigma Rules / YARA
- [ ] API REST
- [ ] Persistência em banco de dados
- [ ] Detecção via Machine Learning

## Licença

MIT

