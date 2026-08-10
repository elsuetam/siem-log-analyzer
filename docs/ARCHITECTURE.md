# Arquitetura - SIEM / Log Analyzer

## Visão Geral

O SIEM Log Analyzer é uma ferramenta de análise de logs com arquitetura em **camadas desacopladas**, onde cada componente tem uma responsabilidade clara e bem definida. O pipeline processa logs brutos → eventos detectados → incidentes → relatórios.

```
INPUT (Logs)
    ↓
[PARSING] (normalização)
    ↓
[DETECTION] (múltiplos detectores)
    ↓
[ANALYSIS] (cálculo de scores)
    ↓
[CORRELATION] (agregação)
    ↓
[ENRICHMENT] (geolocalização, etc)
    ↓
[OUTPUT] (dashboard, PDF, DB)
```

---

## 1. Camada de Parsing

### Responsabilidade
Converter logs brutos em objetos `LogEntry` normalizados, tratando erros e linhas malformadas.

### Arquivos Principais
- `src/siem/parsers/base.py` — Interface abstrata `BaseParser`
- `src/siem/parsers/combined_log_format.py` — Parser Apache/Nginx
- `src/siem/parsers/exceptions.py` — Exceções de parsing

### Fluxo

```python
# INPUT: String bruta
log_line = '192.168.1.100 - - [10/Aug/2024:14:30:45 +0000] "GET /login HTTP/1.1" 401 1234 "-" "Mozilla/5.0"'

# PROCESSING
parser = CombinedLogFormatParser()
log_entry = parser.parse_line(log_line)  # Pode lançar MalformedLogLineError

# OUTPUT: Objeto tipado
LogEntry(
    timestamp=datetime(2024, 8, 10, 14, 30, 45),
    source_ip="192.168.1.100",
    method="GET",
    path="/login",
    protocol="HTTP/1.1",
    status_code=401,
    bytes_sent=1234,
    user_agent="Mozilla/5.0",
    raw_line="..."
)
```

### Design Pattern: Strategy Pattern

```python
# BaseParser define interface
class BaseParser(ABC):
    @abstractmethod
    def parse_line(self, line: str) -> LogEntry | None:
        """Converte linha bruta em LogEntry normalizado"""
        pass

# CombinedLogFormatParser implementa
class CombinedLogFormatParser(BaseParser):
    def parse_line(self, line: str) -> LogEntry | None:
        # Regex + validação
        # Retorna LogEntry ou lança MalformedLogLineError
        pass
```

### Características
- ✅ **Robusto**: Linhas malformadas são ignoradas (não interrompem pipeline)
- ✅ **Extensível**: Adicionar novo formato = implementar BaseParser
- ✅ **Tipado**: Pydantic valida/normaliza dados
- ✅ **Auditável**: Campo `raw_line` preservado para rastreabilidade

---

## 2. Camada de Detecção

### Responsabilidade
Identificar padrões suspeitos em logs normalizados, gerando `DetectionEvent` com informações de ameaça.

### Arquivos Principais
- `src/siem/detectors/base.py` — Interface `BaseDetector`
- `src/siem/detectors/brute_force.py` — Detector de brute force
- `src/siem/detectors/scanner.py` — Detector de scanning
- `src/siem/detectors/sql_injection.py` — Detector de SQL injection
- `src/siem/detectors/directory_traversal.py` — Detector de traversal
- `src/siem/detectors/sigma_rule.py` — Suporte a Sigma Rules
- `src/siem/detectors/yara_rule.py` — Suporte a YARA Rules
- `src/siem/detectors/ml_anomaly.py` — Detector por ML (Isolation Forest)

### Design Pattern: Strategy Pattern (múltiplos detectores)

```python
class BaseDetector(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Identificador único do detector"""
        pass
    
    @abstractmethod
    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        """Executa detecção sobre logs normalizados"""
        pass

# Uso no pipeline
detectors: list[BaseDetector] = [
    BruteForceDetector(attempts_threshold=5, window_seconds=60),
    ScannerDetector(requests_threshold=20, window_seconds=10),
    SqlInjectionDetector(),
    DirectoryTraversalDetector(),
    YaraDetector(rules_dir="rules/yara"),
    SigmaRuleDetector(rules_dir="rules/sigma"),
    MLAnomalyDetector(contamination=0.1),
]

all_detections = []
for detector in detectors:
    detections = detector.detect(log_entries)
    all_detections.extend(detections)
```

### Tipos de Detectores

#### 1. Brute Force Detector
```
Algoritmo: Sliding Window
Entrada: LogEntry com status_code 401/403 + path contendo "login"
Saída: DetectionEvent com MITRE T1110 (Brute Force)

Exemplo:
- IP X faz 5+ requisições a /login com falha em 60 segundos
→ "Brute Force detectado"
```

**Código-chave:**
```python
class BruteForceDetector(BaseDetector):
    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        failures_by_ip = defaultdict(list)
        
        for entry in entries:
            if self._is_auth_failure(entry):
                failures_by_ip[entry.source_ip].append(entry)
        
        events = []
        for source_ip, failures in failures_by_ip.items():
            # find_windows_meeting_threshold: algoritmo sliding window O(n)
            windows = find_windows_meeting_threshold(
                items=failures,
                get_timestamp=lambda e: e.timestamp,
                window=timedelta(seconds=self._window_seconds),
                meets_threshold=lambda g: len(g) >= self._attempts_threshold
            )
            events.extend(self._build_event(source_ip, w) for w in windows)
        
        return events
```

#### 2. Scanner Detector
```
Algoritmo: Contagem de paths distintos em janela de tempo
Entrada: LogEntry com path variável de mesmo IP
Saída: DetectionEvent com MITRE T1595 (Active Scanning)

Exemplo:
- IP Y faz 20+ requisições a paths diferentes em 10 segundos
→ "Active Scanning detectado"
```

#### 3. SQL Injection Detector
```
Algoritmo: Regex + heurísticas
Entrada: LogEntry com path suspeito (contém SQL keywords)
Saída: DetectionEvent com MITRE T1190 (Exploit Public-Facing App)

Exemplo:
- GET /search?q='; DROP TABLE users; --
→ "SQL Injection detectada"
```

#### 4. Directory Traversal Detector
```
Algoritmo: Regex pattern matching
Entrada: LogEntry com path contendo "../" ou "%2e%2e"
Saída: DetectionEvent com MITRE T1083 (File and Directory Discovery)

Exemplo:
- GET /admin/../../etc/passwd
→ "Directory Traversal detectado"
```

#### 5. YARA Detector
```
Algoritmo: Matching contra arquivo de regras YARA
Entrada: LogEntry, regras YARA carregadas
Saída: DetectionEvent com técnica MITRE customizada

Exemplo de regra:
rule SuspiciousUserAgent {
  strings:
    $ua = /sqlmap|nmap|nikto|burp/i
  condition:
    $ua
}
```

#### 6. Sigma Detector
```
Algoritmo: Matching contra arquivo de regras Sigma
Entrada: LogEntry, regras Sigma carregadas
Saída: DetectionEvent com técnica MITRE da regra

Exemplo de regra:
title: Brute Force Login
logsource:
  product: linux
  service: auth
detection:
  selection:
    - 'Failed password'
  condition: selection | count > 5
```

#### 7. ML Anomaly Detector
```
Algoritmo: Isolation Forest (scikit-learn)
Entrada: Features extraídas de LogEntry (bytes_sent, status_code_401_ratio, etc)
Saída: DetectionEvent com MITRE T1087 (Account Discovery)

Processo:
1. Extrair features por IP (comportamento agregado)
2. Treinar Isolation Forest com contamination=0.1
3. Marcar IPs anômalos como DetectionEvent
```

### Output Padrão

Todos os detectores retornam `list[DetectionEvent]`:

```python
@dataclass
class DetectionEvent(BaseModel):
    detector_name: str                    # Ex: "brute_force_detector"
    severity: DetectionSeverity           # "low", "medium", "high", "critical"
    source_ip: str                        # "192.168.1.100"
    description: str                      # "5 tentativas de login falhadas em 60s"
    first_seen: datetime                  # Timestamp primeira ocorrência
    last_seen: datetime                   # Timestamp última ocorrência
    occurrence_count: int                 # Número de ocorrências
    mitre_technique_id: str | None        # "T1110" (Brute Force)
    mitre_technique_name: str | None      # "Brute Force"
```

---

## 3. Camada de Análise

### Responsabilidade
Agregar múltiplas detecções e calcular score de risco consolidado por IP.

### Arquivos Principais
- `src/siem/analysis/risk_score.py` — Cálculo de scores

### Algoritmo

```python
def calculate_risk_scores(
    detections: list[DetectionEvent]
) -> dict[str, RiskScore]:
    """
    Entrada: Todas as detecções de todos os detectores
    Processo: Agregar por IP + calcular score (0-100)
    Saída: Mapa IP → RiskScore
    """
    
    # 1. Agrupar por IP
    detections_by_ip = defaultdict(list)
    for detection in detections:
        detections_by_ip[detection.source_ip].append(detection)
    
    # 2. Calcular score por IP
    scores = {}
    for source_ip, detections_list in detections_by_ip.items():
        # Exemplo de fórmula (pode ser customizada):
        # score = sum(severity_weight * occurrence_count)
        # score = min(score, 100)  # Cap em 100
        
        score_value = 0.0
        for detection in detections_list:
            weight = {
                DetectionSeverity.LOW: 5,
                DetectionSeverity.MEDIUM: 15,
                DetectionSeverity.HIGH: 30,
                DetectionSeverity.CRITICAL: 50,
            }[detection.severity]
            
            score_value += weight * detection.occurrence_count
        
        score_value = min(score_value, 100.0)
        
        scores[source_ip] = RiskScore(
            source_ip=source_ip,
            score=score_value,
            detection_count=len(detections_list),
            detections=detections_list
        )
    
    return scores
```

### Exemplo

```
Entrada (DetectionEvents):
- IP 192.168.1.100: BruteForce (CRITICAL, 5 ocorrências)
- IP 192.168.1.100: Scanner (HIGH, 2 ocorrências)

Cálculo:
- BruteForce: 50 * 5 = 250
- Scanner: 30 * 2 = 60
- Total: 310 → min(310, 100) = 100

Saída (RiskScore):
- source_ip: "192.168.1.100"
- score: 100.0
- detection_count: 2
- detections: [BruteForce, Scanner]
```

---

## 4. Camada de Geração de Incidentes

### Responsabilidade
Converter scores de risco em `Incident` formalizados (apenas scores > threshold).

### Arquivos Principais
- `src/siem/incidents/generator.py` — Factory de incidentes

### Fluxo

```python
def generate_incidents(
    risk_scores: dict[str, RiskScore],
    threshold: float = 25.0
) -> list[Incident]:
    """
    Entrada: Scores de risco e threshold mínimo
    Processo: Filtrar scores >= threshold, criar Incident
    Saída: Lista de incidentes formalizados
    """
    
    incidents = []
    for source_ip, risk_score in risk_scores.items():
        if risk_score.score >= threshold:
            incident = Incident(
                incident_id=generate_uuid(),
                source_ip=source_ip,
                risk_score=risk_score.score,
                title=f"Security Incident: IP {source_ip}",
                description=f"Risk score: {risk_score.score:.0f}. Detections: {risk_score.detection_count}",
                detections=risk_score.detections,
                status=IncidentStatus.OPEN,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                geo_location=None  # Preenchido depois no enrichment
            )
            incidents.append(incident)
    
    return incidents
```

### Modelo

```python
@dataclass
class Incident(BaseModel):
    incident_id: str                      # UUID único
    source_ip: str                        # IP origem
    risk_score: float                     # 0-100
    title: str                            # Título curto
    description: str                      # Descrição detalhada
    detections: list[DetectionEvent]      # Detecções que geraram incidente
    status: IncidentStatus                # "open", "investigating", "resolved"
    created_at: datetime                  # Criado em
    updated_at: datetime                  # Atualizado em
    geo_location: GeoLocation | None      # Localização geográfica (opcional)
```

---

## 5. Camada de Enriquecimento

### Responsabilidade
Adicionar dados contextais (geolocalização) aos incidentes.

### Arquivos Principais
- `src/siem/enrichment/geoip.py` — Enriquecimento com GeoIP

### Design Pattern: Dependency Injection

```python
class GeoIPEnricher:
    def __init__(self, http_client: Callable = requests.get, timeout_seconds: float = 5.0):
        """
        http_client: função injetável para permitir testing sem rede real
        """
        self.http_client = http_client
        self.timeout = timeout_seconds
    
    def enrich(self, ips: list[str]) -> dict[str, GeoLocation]:
        """
        Entrada: Lista de IPs
        Saída: Mapa IP → GeoLocation
        Falhas: Retorna {} parcialmente preenchido (nunca falha o pipeline)
        """
        geo_data = {}
        for ip in ips:
            try:
                # Chamada segura com timeout
                response = self.http_client(
                    f"https://ip-api.com/json/{ip}",
                    timeout=self.timeout
                )
                response.raise_for_status()
                data = response.json()
                
                geo_data[ip] = GeoLocation(
                    country=data.get("country"),
                    city=data.get("city"),
                    latitude=data.get("lat"),
                    longitude=data.get("lon"),
                    is_private=is_private_ip(ip)
                )
            except Exception as e:
                # Log, mas não interrompe pipeline
                logger.warning(f"GeoIP lookup failed for {ip}: {e}")
                geo_data[ip] = GeoLocation(
                    country=None,
                    city=None,
                    latitude=None,
                    longitude=None,
                    is_private=is_private_ip(ip)
                )
        
        return geo_data
```

### Características
- ✅ **Resiliente**: Falhas de rede não interrompem pipeline
- ✅ **Testável**: Função HTTP é injetável
- ✅ **Seguro**: Detecta IPs privados (não consulta API)

---

## 6. Camada de MITRE ATT&CK

### Responsabilidade
Mapear detectores para técnicas MITRE ATT&CK (framework padrão de analistas SOC).

### Arquivos Principais
- `src/siem/mitre/attack_reference.py` — Mapeamento de técnicas
- `src/siem/mitre/definitions.py` — Definições

### Estrutura

```python
@dataclass
class MitreTechnique:
    technique_id: str          # "T1110"
    name: str                  # "Brute Force"
    description: str           # Descrição longa
    tactic: str                # "credential-access"
    url: str                   # Link para ATT&CK framework

# Mapeamento global
BRUTE_FORCE = MitreTechnique(
    technique_id="T1110",
    name="Brute Force",
    description="Adversaries use brute force techniques...",
    tactic="credential-access",
    url="https://attack.mitre.org/techniques/T1110/"
)

# Cada detector referencia técnica
class BruteForceDetector(BaseDetector):
    def _build_event(self, source_ip: str, window_entries: list[LogEntry]) -> DetectionEvent:
        return DetectionEvent(
            ...,
            mitre_technique_id=BRUTE_FORCE.technique_id,
            mitre_technique_name=BRUTE_FORCE.name,
        )
```

### Benefício
Relatórios podem agrupar por técnica MITRE, facilitando análise por especialistas.

---

## 7. Camada de Persistência

### Responsabilidade
Armazenar incidentes em banco de dados (SQLite ou PostgreSQL).

### Arquivos Principais
- `src/siem/persistence/db.py` — Configuração SQLAlchemy
- `src/siem/persistence/models.py` — Modelos ORM
- `src/siem/persistence/repository.py` — Data Access Object

### Arquitetura

```python
# models.py: Mapeamento ORM
class IncidentModel(Base):
    __tablename__ = "incidents"
    
    id = Column(String, primary_key=True)
    source_ip = Column(String, index=True)  # Índice para queries rápidas
    risk_score = Column(Float)
    title = Column(String)
    description = Column(Text)
    status = Column(String)
    created_at = Column(DateTime, index=True)  # Índice temporal
    updated_at = Column(DateTime)

# repository.py: Data Access
class IncidentRepository:
    def __init__(self, session_factory):
        self.session_factory = session_factory
    
    def save_all(self, incidents: list[Incident]) -> None:
        """Persiste incidentes em massa"""
        with self.session_factory() as session:
            for incident in incidents:
                model = IncidentModel(
                    id=incident.incident_id,
                    source_ip=incident.source_ip,
                    risk_score=incident.risk_score,
                    title=incident.title,
                    description=incident.description,
                    status=incident.status.value,
                    created_at=incident.created_at,
                    updated_at=incident.updated_at,
                )
                session.add(model)
            session.commit()
    
    def find_by_risk_score(self, min_score: float) -> list[Incident]:
        """Busca incidentes por score mínimo"""
        with self.session_factory() as session:
            models = session.query(IncidentModel)\
                .filter(IncidentModel.risk_score >= min_score)\
                .order_by(IncidentModel.risk_score.desc())\
                .all()
            return [self._to_domain(m) for m in models]
```

### Configuração

```python
# Suportado em .env
SIEM_DATABASE_URL=sqlite:///./siem.db     # SQLite local
SIEM_DATABASE_URL=postgresql://user:pass@host/db  # PostgreSQL produção
```

---

## 8. Camada de Saída (Reports & Dashboard)

### Responsabilidade
Gerar dashboard HTML e relatório PDF a partir de incidentes.

### Arquivos Principais
- `src/siem/dashboard/renderer.py` — Renderização HTML
- `src/siem/reports/pdf_report.py` — Gerador PDF
- `templates/` — Templates Jinja2

### Dashboard HTML

```python
class DashboardRenderer:
    def render_to_file(
        self,
        data: DashboardData,
        output_path: Path
    ) -> None:
        """
        Entrada: DashboardData com incidentes agregados
        Processo: Renderizar template Jinja2 com dados
        Saída: HTML estático em output_path
        """
        
        env = Environment(loader=FileSystemLoader("templates"))
        template = env.get_template("dashboard.html")
        
        html_content = template.render(
            incidents=data.incidents,
            total_entries=data.total_entries,
            total_detections=data.total_detections,
            severity_distribution=self._calculate_severity_dist(data.incidents),
            top_ips=self._get_top_ips(data.incidents, n=10),
            generated_at=datetime.now().isoformat(),
        )
        
        output_path.write_text(html_content)
```

**Template exemplo (Jinja2):**
```html
<h1>SIEM Dashboard</h1>
<div class="metrics">
  <p>Total Entradas: {{ total_entries }}</p>
  <p>Total Detecções: {{ total_detections }}</p>
  <p>Incidentes: {{ incidents|length }}</p>
</div>

<table class="incidents">
  <thead>
    <tr>
      <th>IP</th>
      <th>Score</th>
      <th>Detecções</th>
      <th>Status</th>
    </tr>
  </thead>
  <tbody>
    {% for incident in incidents %}
    <tr>
      <td>{{ incident.source_ip }}</td>
      <td>{{ incident.risk_score }}</td>
      <td>{{ incident.detections|length }}</td>
      <td>{{ incident.status }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
```

### Relatório PDF

```python
class PDFReportGenerator:
    def generate(
        self,
        incidents: list[Incident],
        output_path: Path,
        total_entries: int,
        total_detections: int
    ) -> None:
        """
        Entrada: Incidentes + metadados
        Processo: Usar ReportLab para gerar PDF
        Saída: PDF em output_path
        """
        
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        
        c = canvas.Canvas(str(output_path), pagesize=letter)
        c.setTitle("SIEM Analysis Report")
        
        # Cabeçalho
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, 750, "SIEM Analysis Report")
        
        # Resumo executivo
        c.setFont("Helvetica", 12)
        c.drawString(50, 700, f"Total Log Entries: {total_entries}")
        c.drawString(50, 680, f"Total Detections: {total_detections}")
        c.drawString(50, 660, f"Security Incidents: {len(incidents)}")
        
        # Tabela de incidentes
        y = 600
        for incident in incidents[:10]:  # Primeiros 10
            c.setFont("Helvetica-Bold", 10)
            c.drawString(50, y, f"[{incident.risk_score:.0f}] {incident.title}")
            
            c.setFont("Helvetica", 9)
            y -= 15
            c.drawString(70, y, f"IP: {incident.source_ip}")
            
            y -= 15
            c.drawString(70, y, f"Detections: {len(incident.detections)}")
            
            y -= 25
        
        c.save()
```

---

## 9. Camada de API REST (Roadmap)

### Responsabilidade
Expor endpoints HTTP para análise sob demanda e consulta de incidentes.

### Arquivos Principais
- `src/siem/api/main.py` — Endpoints FastAPI

### Endpoints Planejados

```python
from fastapi import FastAPI, UploadFile

app = FastAPI(title="SIEM API", version="0.1.0")

# 1. Análise sob demanda
@app.post("/api/v1/analyze")
async def analyze(file: UploadFile) -> dict:
    """
    Endpoint: POST /api/v1/analyze
    Entrada: File upload ou JSON com logs
    Saída: { incidents: [...], total_detections: N, total_entries: M }
    """
    pass

# 2. Listar incidentes
@app.get("/api/v1/incidents")
async def list_incidents(
    min_score: float = 0,
    status: str = "open",
    limit: int = 100
) -> list[Incident]:
    """
    Endpoint: GET /api/v1/incidents?min_score=50&status=open
    Entrada: Query parameters
    Saída: Lista de incidentes
    """
    pass

# 3. Detalhe de incidente
@app.get("/api/v1/incidents/{incident_id}")
async def get_incident(incident_id: str) -> Incident:
    """
    Endpoint: GET /api/v1/incidents/{id}
    Entrada: ID de incidente
    Saída: Incidente completo com detecções
    """
    pass

# 4. Estatísticas
@app.get("/api/v1/stats")
async def get_stats(days: int = 7) -> dict:
    """
    Endpoint: GET /api/v1/stats?days=7
    Entrada: Período em dias
    Saída: { total_incidents: N, avg_score: M, top_ips: [...] }
    """
    pass

# 5. Resolver incidente
@app.patch("/api/v1/incidents/{incident_id}")
async def update_incident(incident_id: str, status: str) -> Incident:
    """
    Endpoint: PATCH /api/v1/incidents/{id}
    Entrada: { status: "resolved" }
    Saída: Incidente atualizado
    """
    pass
```

---

## Pipeline Completo

### Fluxo de Execução

```
1. ENTRADA
   └─ Arquivo de log (data/raw_logs/access.log)

2. PARSING
   └─ CombinedLogFormatParser.parse_line()
   └─ Saída: list[LogEntry]

3. DETECÇÃO (paralelo)
   ├─ BruteForceDetector.detect()
   ├─ ScannerDetector.detect()
   ├─ SqlInjectionDetector.detect()
   ├─ DirectoryTraversalDetector.detect()
   ├─ YaraDetector.detect()
   ├─ SigmaRuleDetector.detect()
   └─ MLAnomalyDetector.detect()
   └─ Saída: list[DetectionEvent] (agregado)

4. ANÁLISE
   └─ calculate_risk_scores(detections)
   └─ Saída: dict[IP → RiskScore]

5. GERAÇÃO DE INCIDENTES
   └─ generate_incidents(risk_scores, threshold=25.0)
   └─ Filtrar: score >= 25.0
   └─ Saída: list[Incident]

6. ENRIQUECIMENTO
   └─ GeoIPEnricher.enrich(ips)
   └─ Adiciona geolocalização (se habilitado)
   └─ Saída: list[Incident] (enriquecido)

7. PERSISTÊNCIA
   └─ IncidentRepository.save_all(incidents)
   └─ Armazena em DB (SQLite/PostgreSQL)

8. SAÍDA
   ├─ DashboardRenderer.render_to_file()
   │  └─ output/dashboards/dashboard.html
   ├─ PDFReportGenerator.generate()
   │  └─ output/reports/report.pdf
   └─ Console output (resumo de incidentes)
```

---

## Decisões de Design

### 1. **Por que Pydantic?**
- ✅ Validação automática de tipos
- ✅ Serialização/desserialização JSON
- ✅ Documentação autodescritiva
- ✅ Imutabilidade (mode="after_validation")

### 2. **Por que Base Classes Abstratas?**
- ✅ Novos detectores/parsers sem alterar código existente
- ✅ Contrato claro de implementação
- ✅ Fácil testing com mocks

### 3. **Por que Sliding Window?**
- ✅ Complexidade O(n) em vez de O(n²)
- ✅ Detecção de padrões temporais sem sobreposição
- ✅ Eficiência com logs grandes

### 4. **Por que Injeção de Dependência (GeoIP)?**
- ✅ 100% testável sem rede real
- ✅ Fácil mock em testes
- ✅ Falhas isoladas (não interrompem pipeline)

### 5. **Por que SQLAlchemy?**
- ✅ Suporte a múltiplos DBs (SQLite, PostgreSQL, etc)
- ✅ Migrations (com Alembic)
- ✅ Type-safe queries

### 6. **Por que Jinja2 para Dashboard?**
- ✅ Templates simples e legíveis
- ✅ Rendering 100% server-side (sem JS complexo)
- ✅ Fácil integração com Python

---

## Extensibilidade

### Adicionar um Novo Detector

```python
# src/siem/detectors/novo_detector.py
from siem.detectors.base import BaseDetector
from siem.models.detection_event import DetectionEvent, DetectionSeverity
from siem.models.log_entry import LogEntry
from siem.mitre.attack_reference import CUSTOM_TECHNIQUE

class NovoDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "novo_detector"
    
    def detect(self, entries: list[LogEntry]) -> list[DetectionEvent]:
        detections = []
        
        for entry in entries:
            if self._is_suspicious(entry):
                detections.append(DetectionEvent(
                    detector_name=self.name,
                    severity=DetectionSeverity.MEDIUM,
                    source_ip=entry.source_ip,
                    description="Padrão suspeito detectado",
                    first_seen=entry.timestamp,
                    last_seen=entry.timestamp,
                    occurrence_count=1,
                    mitre_technique_id=CUSTOM_TECHNIQUE.technique_id,
                    mitre_technique_name=CUSTOM_TECHNIQUE.name,
                ))
        
        return detections
    
    def _is_suspicious(self, entry: LogEntry) -> bool:
        # Sua lógica de detecção
        return False

# src/siem/main.py (adicionar ao método _build_detectors)
detectors: list[BaseDetector] = [
    # ... detectores existentes ...
    NovoDetector(),  # ← Novo detector
]
```

### Adicionar Novo Formato de Log

```python
# src/siem/parsers/json_parser.py
from siem.parsers.base import BaseParser

class JSONLogParser(BaseParser):
    def parse_line(self, line: str) -> LogEntry | None:
        try:
            data = json.loads(line)
            return LogEntry(
                timestamp=datetime.fromisoformat(data["timestamp"]),
                source_ip=data["client_ip"],
                method=data["method"],
                path=data["path"],
                protocol=data.get("protocol", "HTTP/1.1"),
                status_code=int(data["status"]),
                bytes_sent=int(data.get("bytes", 0)),
                user_agent=data.get("user_agent"),
                raw_line=line,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise MalformedLogLineError(f"Invalid JSON log: {e.reason}")

# src/siem/main.py
parser = JSONLogParser()  # Em vez de CombinedLogFormatParser
```

---

## Performance & Escalabilidade

### Otimizações Atuais
- ✅ Sliding window O(n) para brute force/scanner
- ✅ Parsing com regex compilado (cache)
- ✅ Detecção paralela (múltiplos detectores)
- ✅ Índices DB em campos frequentemente consultados

### Possíveis Melhorias
- Processamento em streaming (em vez de load-all-in-memory)
- Paralelização com multiprocessing/asyncio
- Cache de regras YARA/Sigma compiladas
- Sharding de dados por IP em ambiente distribuído

---

## Testing

### Estratégia
- ✅ 115 testes com 96% de cobertura
- ✅ Unit tests: cada camada isolada
- ✅ Integration tests: pipeline end-to-end
- ✅ Fixtures compartilhadas (conftest.py)

### Exemplo de Teste de Detector

```python
def test_brute_force_detector():
    # Arrange
    detector = BruteForceDetector(attempts_threshold=3, window_seconds=60)
    
    entries = [
        LogEntry(
            timestamp=datetime(2024, 8, 10, 14, 30, 45),
            source_ip="192.168.1.100",
            method="POST",
            path="/login",
            status_code=401,
            ...
        ),
        # 3 entradas com mesmo IP, path /login, status 401 em < 60s
    ]
    
    # Act
    detections = detector.detect(entries)
    
    # Assert
    assert len(detections) == 1
    assert detections[0].source_ip == "192.168.1.100"
    assert detections[0].severity == DetectionSeverity.HIGH
    assert detections[0].mitre_technique_id == "T1110"
```

---

## Conclusão

A arquitetura do SIEM Log Analyzer segue princípios **SOLID**:
- **S**ingle Responsibility: Cada camada tem uma responsabilidade
- **O**pen/Closed: Aberto para extensão (novos detectores), fechado para modificação
- **L**iskov Substitution: Todos os detectores implementam BaseDetector
- **I**nterface Segregation: Interfaces mínimas e coesas
- **D**ependency Inversion: Depend de abstrações, não de implementações

Resultado: **Code que é testável, extensível, manutenível e pronto para evolução.**
