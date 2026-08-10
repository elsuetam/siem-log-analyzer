# 🛡️ SIEM / Log Analyzer

Ferramenta de análise de logs e detecção de ameaças (Blue Team), desenvolvida em Python com foco em arquitetura limpa, modularidade e boas práticas de engenharia de software.

[![CI Status](https://github.com/mateuss017/siem-log-analyzer/workflows/CI/badge.svg)](https://github.com/mateuss017/siem-log-analyzer/actions)
[![codecov](https://codecov.io/gh/mateuss017/siem-log-analyzer/branch/master/graph/badge.svg)](https://codecov.io/gh/mateuss017/siem-log-analyzer)
![Python](https://img.shields.io/badge/python-3.13-blue)
![Tests](https://img.shields.io/badge/tests-115%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)
![mypy](https://img.shields.io/badge/mypy-strict-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## O que é

Um SIEM (*Security Information and Event Management*) simplificado que lê logs de acesso web, detecta padrões de ataque conhecidos, calcula um score de risco por IP de origem, gera incidentes formais e exporta relatórios PDF + dashboard HTML interativo.

## Por que este projeto

Construído para demonstrar, na prática, competências centrais de engenharia de software aplicadas a cibersegurança:

- **Detecção de ameaças reais**: brute force, scanning/reconhecimento, SQL Injection e Directory Traversal — cobrindo vetores centrais do OWASP Top 10
- **Classificação por padrão de indústria**: cada detecção é mapeada para uma técnica [MITRE ATT&CK](https://attack.mitre.org/), o framework usado por analistas SOC no mundo real
- **Engenharia de software disciplinada**: arquitetura em camadas, interfaces abstratas, tipagem estrita, 115 testes automatizados, 96% de cobertura
- **Pipeline completo e funcional**: da leitura do log bruto ao relatório final, sem etapas manuais
- **CI/CD automatizado**: GitHub Actions com pytest, mypy, ruff, bandit e Codecov integrados

## Funcionalidades

| Categoria | Detalhe |
|---|---|
| **Parsing** | Combined Log Format (Apache/Nginx), com tratamento robusto de linhas malformadas |
| **Detecção** | Brute Force, Active Scanning, SQL Injection, Directory Traversal, Sigma Rules, YARA, ML Anomaly |
| **Classificação** | Score de risco por IP (0–100), mapeamento MITRE ATT&CK por técnica |
| **Enriquecimento** | Geolocalização de IP via API pública (opcional, com fallback seguro se offline) |
| **Saída** | Dashboard HTML interativo (gráficos de severidade e top IPs) + relatório PDF exportável |
| **Configuração** | Todos os thresholds de detecção ajustáveis via `.env`, sem hardcoding |
| **Persistência** | Incidentes armazenados em SQLite (ou PostgreSQL) |
| **CI/CD** | GitHub Actions automatizado com pytest, mypy, ruff, bandit e Codecov |

## Arquitetura

```
Logs brutos (data/raw_logs/)
│
▼
[Parser] ──► LogEntry (normalizado)
│
▼
[Detectores] ──► DetectionEvent (+ técnica MITRE ATT&CK)
│ │ │ │ │ │ │
│ │ │ │ │ │ └─ ML Anomaly Detector
│ │ │ │ │ └───── YARA Rules
│ │ │ │ └───────── Sigma Rules
│ │ │ └───────────── Directory Traversal
│ │ └───────────────── SQL Injection
│ └───────────────────── Active Scanning
└─────────────────────────── Brute Force
│
▼
[Score de Risco] ──► RiskScore por IP (0–100)
│
▼
[Geração de Incidentes] ──► Incident (+ GeoIP opcional)
│
├──► Dashboard HTML (gráficos + lista de incidentes)
├──► Relatório PDF (resumo executivo + detalhamento)
└──► Persistência em DB (SQLite/PostgreSQL)
```

Cada camada se comunica através de modelos de dados tipados (Pydantic) — parsers e detectores não conhecem nada sobre relatórios ou dashboard, e novos detectores podem ser adicionados sem alterar código existente.

## Stack técnica

- **Python 3.13** com tipagem estrita (`mypy --strict`)
- **Pydantic v2** — validação e modelagem de dados
- **FastAPI** — API REST (em desenvolvimento)
- **Jinja2** — geração do dashboard HTML
- **ReportLab** — geração de relatórios PDF
- **SQLAlchemy** — ORM para persistência
- **pytest** + **pytest-cov** — 115 testes, 96% de cobertura
- **ruff** — linting e formatação
- **mypy** — type checking com modo strict
- **bandit** — análise de segurança
- Sem dependências de banco de dados ou serviços externos obrigatórios — roda 100% local

## Instalação

### Windows (PowerShell)

```powershell
git clone https://github.com/mateuss017/siem-log-analyzer.git
cd siem-log-analyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

Se receber erro de permissão ao ativar o venv:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Linux/macOS

```bash
git clone https://github.com/mateuss017/siem-log-analyzer.git
cd siem-log-analyzer
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
```

## Uso

### Análise de logs (CLI)

1. Coloque arquivos de log (formato Combined Log Format) em `data/raw_logs/`:

```bash
# Exemplo de log em Combined Log Format
192.168.1.100 - - [10/Aug/2024:14:30:45 +0000] "GET /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
192.168.1.100 - - [10/Aug/2024:14:30:46 +0000] "POST /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"
10.0.0.50 - - [10/Aug/2024:14:35:00 +0000] "GET /search.php?id=1' OR '1'='1 HTTP/1.1" 200 5000 "-" "Chrome"
```

2. Execute:

```bash
python -m siem.main
```

3. Resultados gerados em:
   - `output/dashboards/dashboard.html` — dashboard interativo
   - `output/reports/report.pdf` — relatório exportável
   - `siem.db` — incidentes persistidos

### Opções de linha de comando

```bash
# Processar arquivo específico
python -m siem.main --log-file caminho/para/arquivo.log

# Ver versão
python -m siem.main --version

# Exibir ajuda
python -m siem.main --help
```

### Configuração (`.env`)

Todos os thresholds de detecção são ajustáveis sem alterar código:

```env
# Diretórios
SIEM_RAW_LOGS_DIR=data/raw_logs
SIEM_OUTPUT_DIR=output
SIEM_REPORTS_DIR=output/reports
SIEM_DASHBOARDS_DIR=output/dashboards

# Logging
SIEM_LOG_LEVEL=INFO
SIEM_FILE_ENCODING=utf-8
SIEM_TIMEZONE=UTC

# Thresholds de detecção
SIEM_BRUTE_FORCE_ATTEMPTS_THRESHOLD=5
SIEM_BRUTE_FORCE_WINDOW_SECONDS=60
SIEM_SCANNER_REQUESTS_THRESHOLD=20
SIEM_SCANNER_WINDOW_SECONDS=10
SIEM_INCIDENT_RISK_SCORE_THRESHOLD=25.0

# Recursos opcionais
SIEM_ENABLE_GEOIP=false
SIEM_GEOIP_TIMEOUT_SECONDS=5.0
SIEM_ENABLE_ML_ANOMALY_DETECTION=false
SIEM_ML_ANOMALY_CONTAMINATION=0.1
SIEM_ML_ANOMALY_MIN_IPS=10

# Regras externas
SIEM_SIGMA_RULES_DIR=rules/sigma
SIEM_YARA_RULES_DIR=rules/yara

# Banco de dados
SIEM_DATABASE_URL=sqlite:///./siem.db
```

Ver `.env.example` para a lista completa de opções.

## Rodando os testes

### Testes com cobertura

```bash
# Testes com relatório de cobertura (terminal + HTML)
pytest --cov=siem --cov-report=term-missing --cov-report=html

# Abrir relatório HTML (Windows)
Start-Process htmlcov/index.html

# Abrir relatório HTML (Linux/macOS)
open htmlcov/index.html
```

### Linting

```bash
# Verificar código
ruff check .

# Formatar código
ruff format .
```

### Type checking

```bash
# Validar tipos com mypy
mypy src
```

### Análise de segurança

```bash
# Executar bandit
bandit -r src/
```

### Tudo de uma vez

```bash
pytest --cov=siem --cov-report=term-missing && \
ruff check . && \
ruff format . && \
mypy src && \
bandit -r src/
```

## Estrutura do projeto

```
src/siem/
├── parsers/              # Interpretação de formatos de log
│   ├── base.py          # Interface abstrata BaseParser
│   ├── combined_log_format.py  # Parser para Apache/Nginx
│   └── exceptions.py    # Exceções de parsing
│
├── detectors/           # Detectores de ameaças
│   ├── base.py         # Interface abstrata BaseDetector
│   ├── brute_force.py  # Detecção de brute force
│   ├── scanner.py      # Detecção de scanning/reconhecimento
│   ├── sql_injection.py # Detecção de SQL Injection
│   ├── directory_traversal.py # Detecção de traversal
│   ├── sigma_rule.py   # Suporte a Sigma Rules
│   ├── yara_rule.py    # Suporte a YARA Rules
│   └── ml_anomaly.py   # Detecção por ML (Isolation Forest)
│
├── models/              # Modelos de dados (Pydantic)
│   ├── log_entry.py    # LogEntry - entrada de log normalizada
│   ├── detection_event.py # DetectionEvent - evento detectado
│   ├── incident.py     # Incident - incidente formalizado
│   ├── risk_score.py   # RiskScore - score por IP
│   └── geo_location.py # GeoLocation - localização do IP
│
├── analysis/            # Análise agregada
│   └── risk_score.py   # Cálculo de scores de risco
│
├── incidents/           # Geração de incidentes
│   └── generator.py    # Factory de incidentes
│
├── enrichment/          # Enriquecimento de dados
│   └── geoip.py        # Enriquecimento com GeoIP
│
├── mitre/               # Técnicas MITRE ATT&CK
│   ├── attack_reference.py # Mapeamento de técnicas
│   └── definitions.py      # Definições
│
├── dashboard/           # Geração de dashboards
│   ├── renderer.py     # Renderização HTML com Jinja2
│   └── templates/      # Templates HTML/CSS
│
├── reports/             # Geração de relatórios
│   └── pdf_report.py   # Gerador de PDF com ReportLab
│
├── persistence/         # Persistência em DB
│   ├── db.py           # Configuração SQLAlchemy
│   ├── models.py       # Modelos ORM
│   └── repository.py   # Repositories (Data Access)
│
├── api/                 # API REST (FastAPI - em desenvolvimento)
│   └── main.py         # Endpoints REST
│
├── config/              # Configurações
│   └── settings.py     # Configurações centralizadas (.env)
│
├── utils/               # Utilitários
│   ├── sliding_window.py # Algoritmo sliding window
│   ├── logging_config.py # Configuração de logging
│   └── exceptions.py    # Exceções customizadas
│
├── main.py             # Ponto de entrada da aplicação
└── pipeline.py         # Orquestração do pipeline

tests/
├── unit/                # Testes unitários
│   ├── detectors/      # Testes dos detectores
│   ├── parsers/        # Testes dos parsers
│   ├── enrichment/     # Testes do enriquecimento
│   ├── incidents/      # Testes de geração de incidentes
│   ├── dashboard/      # Testes do dashboard
│   ├── reports/        # Testes de relatórios
│   ├── persistence/    # Testes de persistência
│   ├── test_main.py    # Testes do main
│   └── test_settings.py # Testes das settings
│
└── integration/         # Testes de integração
    └── test_pipeline.py # Testes end-to-end do pipeline

.github/workflows/
└── ci.yml              # Pipeline CI/CD: pytest, mypy, ruff, bandit, codecov
```

## CI/CD (GitHub Actions)

O repositório inclui um pipeline automatizado que:

- ✅ **Lint** — Verifica código com ruff (check + format)
- ✅ **Type Check** — Valida tipos com `mypy --strict`
- ✅ **Testes** — Executa pytest com cobertura de código
- ✅ **Segurança** — Analisa código com bandit
- ✅ **Coverage** — Envia cobertura para Codecov
- ✅ **Artifacts** — Armazena relatórios HTML de cobertura

**Acionado em:** `push` e `pull_request` na branch master

**Status:** Todas as workflows passando ✅

## Destaques técnicos

Pontos deste projeto que valem destaque em uma conversa técnica:

- **Sliding window com ponteiro duplo** — Detecção de padrões temporais (brute force, scanning) com complexidade O(n) por IP, sem sobreposição de detecções
- **Injeção de dependência** — `GeoIPEnricher` recebe função HTTP injetável, permitindo 100% de testabilidade sem chamadas de rede reais
- **Falha isolada por design** — Enriquecimento GeoIP nunca derruba o pipeline principal, mesmo com API fora do ar
- **Interfaces abstratas** — `BaseParser`, `BaseDetector` permitem adicionar novos formatos/detectores sem alterar código existente
- **Modelos imutáveis e tipados** — Pydantic em toda a pipeline, nenhum dicionário solto trafegando entre camadas
- **Detecção multi-camadas** — Combina heurísticas (Brute Force, Scanner), assinaturas (YARA, Sigma) e ML (Isolation Forest)
- **Scores de risco agregados** — Múltiplas detecções por IP resultam em score consolidado (0–100)

## Roadmap

- [x] Parser de logs (Combined Log Format)
- [x] Detectores: Brute Force, Active Scanning, SQL Injection, Directory Traversal
- [x] Score de risco e geração de incidentes
- [x] Dashboard HTML com gráficos
- [x] Exportação de relatórios PDF
- [x] Enriquecimento GeoIP
- [x] Mapeamento MITRE ATT&CK
- [x] Sigma Rules / YARA
- [x] Persistência em banco de dados (SQLAlchemy)
- [x] CI/CD com GitHub Actions
- [x] Detecção via Machine Learning (Isolation Forest)
- [ ] Containerização (Docker)
- [ ] API REST completa (FastAPI)
- [ ] Dashboard interativo com WebSocket
- [ ] Correlação de incidentes
- [ ] Suporte a múltiplos formatos de log (JSON, syslog, CEF)

## Exemplos de Uso

### Exemplo 1: Análise de arquivo de log simples

```bash
# Criar arquivo de teste
mkdir -p data/raw_logs
echo '192.168.1.100 - - [10/Aug/2024:14:30:45 +0000] "POST /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"' > data/raw_logs/test.log

# Executar análise
python -m siem.main --log-file data/raw_logs/test.log

# Resultados
# - output/dashboards/dashboard.html
# - output/reports/report.pdf
```

### Exemplo 2: Ajustar thresholds sem alterar código

Edite `.env`:
```env
SIEM_BRUTE_FORCE_ATTEMPTS_THRESHOLD=3  # Mais sensível
SIEM_INCIDENT_RISK_SCORE_THRESHOLD=10.0  # Gera mais incidentes
SIEM_ENABLE_GEOIP=true  # Ativa enriquecimento
```

Depois execute:
```bash
python -m siem.main
```

## Desenvolvendo

### Adicionar um novo detector

1. Crie `src/siem/detectors/novo_detector.py`:

```python
from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry

class NovoDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "novo_detector"
    
    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        # Sua lógica aqui
        return []
```

2. Adicione testes em `tests/unit/detectors/test_novo_detector.py`

3. Registre em `src/siem/main.py` no método `_build_detectors()`

### Rodando testes com cobertura

```bash
# Relatório terminal
pytest --cov=siem --cov-report=term-missing

# Relatório HTML
pytest --cov=siem --cov-report=html
open htmlcov/index.html
```

### Validar qualidade antes de fazer push

```bash
./validate.sh  # Script auxiliar (se existir)
# Ou manualmente:
pytest --cov=siem && ruff check . && mypy src && bandit -r src/
```

## Contribuindo

Sugestões de melhorias são bem-vindas! Para contribuir:

1. **Fork** o repositório
2. **Crie uma branch** (`git checkout -b feature/sua-feature`)
3. **Commit suas mudanças** (`git commit -am 'Add feature: descrição'`)
4. **Push** para a branch (`git push origin feature/sua-feature`)
5. **Abra um Pull Request** com descrição clara

### Diretrizes

- Mantenha 96%+ de cobertura de testes
- Execute `mypy src`, `ruff check .` e `pytest` antes de fazer push
- Adicione testes para novas funcionalidades
- Mantenha docstrings em português

## Suporte & Contato

Para dúvidas, abra uma [Issue](https://github.com/mateuss017/siem-log-analyzer/issues) ou [Discussion](https://github.com/mateuss017/siem-log-analyzer/discussions).

## Licença

MIT — Veja [LICENSE](LICENSE) para detalhes.
