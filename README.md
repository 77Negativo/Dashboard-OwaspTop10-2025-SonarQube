# Dashboard OWASP Top 10 2025 - SonarQube Intelligence

Sistema avançado de análise de segurança e governança que conecta-se ao SonarQube para classificar vulnerabilidades segundo o **OWASP Top 10 2025**, gerar dashboards executivos interativos e manter histórico versionado de scans para análise temporal.

## Índice

- [Características](#características)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Configuração](#configuração)
- [Uso](#uso)
- [Estrutura do Dashboard](#estrutura-do-dashboard)
- [OWASP Top 10 2025](#owasp-top-10-2025)
- [Classificação Automática](#classificação-automática)
- [Sistema de Governança](#sistema-de-governança)
- [Histórico de Scans](#histórico-de-scans)
- [Estrutura de Arquivos](#estrutura-de-arquivos)
- [Troubleshooting](#troubleshooting)
- [Contribuindo](#contribuindo)

## Características

### Funcionalidades Principais

- **Classificação Automática OWASP 2025**: Mapeia regras do SonarQube para as 10 categorias da nova versão do OWASP
- **Dashboard Executivo Interativo**: Interface web moderna com 6 abas de análise
- **Histórico Versionado**: Snapshots timestamped para análise de evolução temporal
- **Intelligence Gerencial**: Insights, oportunidades, recomendações e benchmarks automáticos
- **Detecção de Secrets**: Identificação automática de credenciais expostas
- **Análise de Misconfigurations**: Detecção de configurações de segurança incorretas
- **Filtro de Branches**: Análise focada em branches principais (main, master, develop, developer)
- **Aggregate Report**: Visualização de evolução de vulnerabilidades ao longo do tempo
- **Modais Interativos**: Drill-down em qualquer categoria OWASP para ver detalhes
- **Links Diretos**: Acesso rápido ao SonarQube para correções

### Diferenciais

- Filtro automático de `dependency-check-report.html`
- Tratamento especial para riscos críticos (Secrets e Misconfigurations)
- Métricas de coverage por projeto
- Score de maturidade de governança
- Comparação com benchmarks da indústria
- Matriz de risco de projetos
- Recomendações priorizadas com ROI e timeline

## Pré-requisitos

- **Python 3.7+**
- **SonarQube** (versão 8.0 ou superior)
- **Token de autenticação** do SonarQube com permissões de leitura
- Navegador web moderno (Chrome, Firefox, Edge, Safari)

### Bibliotecas Python

```bash
pip install requests urllib3
```

Ou use o arquivo requirements (se disponível):

```bash
pip install -r requirements.txt
```

## Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/Dashboard-OwaspTop10-2025-SonarQube.git
cd Dashboard-OwaspTop10-2025-SonarQube
```

### 2. Instale as dependências

```bash
pip install requests urllib3
```

### 3. Configure o SonarQube

**Gerar Token de Autenticação:**

1. Acesse seu SonarQube
2. Vá em **User > My Account > Security**
3. Gere um novo token
4. Copie e guarde o token (será usado na execução)

## Configuração

### Variáveis de Ambiente (Opcional)

Você pode configurar as seguintes constantes no arquivo `Dashboard-OwaspTop10-2025.py`:

```python
# Total de repositórios esperados
TOTAL_REPOSITORIES_EXPECTED = 209

# Branches principais a monitorar
MAIN_BRANCHES = ['main', 'master', 'develop', 'developer']

# Padrão para detectar secrets
SECRETS_PATTERN = "secrets"

# Padrões para detectar misconfigurations
MISCONFIG_PATTERNS = ["config", "ssl", "tls", "certificate", "encryption", "cipher", "security"]
```

### SSL/TLS

Por padrão, o sistema **desabilita a verificação SSL** para facilitar conexões com SonarQube em ambientes internos. Para habilitar, modifique:

```python
# Na função _make_request
verify=False  # Altere para True se necessário
```

## Uso

### Execução Básica

```bash
python Dashboard-OwaspTop10-2025.py
```

### Fluxo de Execução

1. **Informe a URL do SonarQube**:
   ```
   URL do SonarQube: https://sonarqube.sua-empresa.com
   ```

2. **Informe o Token de autenticação**:
   ```
   Token: squ_abc123def456...
   ```

3. **Aguarde a coleta de dados**:
   - O sistema validará a conexão
   - Coletará todos os projetos
   - Processará branches principais
   - Classificará vulnerabilidades
   - Gerará insights

4. **Dashboard abrirá automaticamente**:
   - Servidor HTTP na porta 8000
   - Dashboard em `http://localhost:8000/sonarqube_dashboard.html`

### Exemplo de Saída

```
======================================================================
  DASHBOARD EXECUTIVO SONARQUBE - INTELLIGENCE OWASP 2025
======================================================================

URL do SonarQube: https://sonarqube.empresa.com
Token: ********************************

======================================================================
TESTANDO CONEXÃO E AUTENTICAÇÃO
======================================================================
1. Testando conexão: https://sonarqube.empresa.com/api/system/status
   ✓ Conexão OK - SonarQube 9.9.0 está UP

2. Testando acesso a projetos: https://sonarqube.empresa.com/api/projects/search
   ✓ Acesso OK - 209 projetos disponíveis
======================================================================

======================================================================
COLETANDO DADOS PARA DASHBOARD
======================================================================

[1/209] Projeto ABC
  Key: abc-service
  ✓ 1 branch(es) principal(is) encontrada(s)

  📍 Branch Principal: main (Main)
    ✓ Cobertura: 85.3%, Bugs: 5, Vulns: 12
    ✓ Quality Gate: PASSED
    → Coletando issues...
    ✓ Issues coletados: 47
    🔐 SECRETS encontrados: 2 issues relacionados a secrets
    📊 Classificação OWASP Top 10 2025:
      - A04:2025-Cryptographic Failures: 2 issue(s)
      - A01:2025-Broken Access Control: 8 issue(s)
      - A05:2025-Injection: 15 issue(s)

  ✓ 1 branch(es) principal(is) processada(s) com sucesso
  🔐 ATENÇÃO: 2 secrets encontrados!
  📊 Coverage médio: 85.3%
  🏛️ Maturidade de Governança: DEFINED (Score: 52.5)

...

======================================================================
✓ Coleta concluída:
  - 209 projetos/repositórios no total
  - 215 branches principais coletadas
  - Branches monitoradas: main, master, develop, developer
  - Total esperado: 209 repositórios

🏛️ GOVERNANÇA GLOBAL:
  - Nível de Maturidade: MANAGED
  - Score de Governança: 68.5/100
  - Issues Totais: 1248
  - Categorias OWASP Afetadas: 8/10

📊 MÉTRICAS CRÍTICAS:
  - Projetos com Coverage: 187/209 (89.5%)
  - Projetos com Secrets: 23/209 (11.0%)
  - Projetos com Misconfigurations: 45/209 (21.5%)

🔐 CRÍTICO - VAZAMENTO DE SECRETS:
  - 🚨 23 projeto(s) com secrets expostos!
  - 🚨 CORREÇÃO URGENTE NECESSÁRIA!

⚙️ CRÍTICO - CONFIGURAÇÕES INCORRETAS:
  - 🚨 45 projeto(s) com configurações de segurança incorretas!
  - 🚨 REVISÃO E CORREÇÃO URGENTE NECESSÁRIA!
======================================================================

✓ Dados salvos: sonarqube_dashboard_data.json
✓ Dashboard gerado: sonarqube_dashboard.html

📊 HISTÓRICO DE SCANS:
  - 5 snapshot(s) armazenado(s) em sonarqube_scans_history/
  - Período: 2025-01-20T10:15:30 até 2025-01-28T14:30:22

🌐 Servidor: http://localhost:8000
⚠️  Ctrl+C para parar
```

## Estrutura do Dashboard

O dashboard possui **6 abas principais**:

### 1. Overview Executivo

Visão geral com métricas principais:
- Total de projetos monitorados
- Projetos com coverage
- Projetos com secrets (CRÍTICO)
- Projetos com misconfigurations (CRÍTICO)
- Score de governança global

**Gráficos:**
- Distribuição de maturidade de governança
- Status Quality Gate
- Top 5 Categorias OWASP 2025
- Coverage vs Issues por projeto

### 2. Intelligence & Insights

Análises gerenciais com:

**Alertas Críticos:**
- Secrets expostos detectados
- Configurações de segurança incorretas
- Projetos com alto volume de vulnerabilidades
- Quality Gates reprovados

**Oportunidades:**
- Focar nas Top 3 categorias OWASP
- Evolução da governança
- Melhoria em testes

**Recomendações (Top 5):**
1. Implementar Secret Scanning Automático
2. Auditoria de Configurações de Segurança
3. Quality Gates Obrigatórios
4. Implementar Coverage Mínimo
5. Treinamento OWASP Top 10 2025

**Benchmarks:**
- Score de governança (vs. indústria)
- Exposição de secrets
- Quality Gate pass rate
- Coverage ratio

### 3. OWASP Analysis

Cards interativos das **10 categorias OWASP 2025**:

- **A01:2025** - Broken Access Control
- **A02:2025** - Security Misconfiguration
- **A03:2025** - Software Supply Chain Failures
- **A04:2025** - Cryptographic Failures
- **A05:2025** - Injection
- **A06:2025** - Insecure Design
- **A07:2025** - Authentication Failures
- **A08:2025** - Software and Data Integrity Failures
- **A09:2025** - Logging & Alerting Failures
- **A10:2025** - Mishandling of Exception Conditions

Clique em qualquer card para ver:
- Total de issues
- Projetos afetados
- Issues detalhadas com links para o SonarQube
- Distribuição por severidade

### 4. Risk Management

Gestão de riscos com:
- **Matriz de Risco de Projetos**: Scatter plot de risco vs. exposição
- **Secrets Expostos**: Lista detalhada com links diretos
- **Misconfigurations**: Configurações incorretas detectadas
- **Top 10 Projetos de Maior Risco**

### 5. Project Details

Tabela completa de todos os projetos com:
- Nome do projeto
- Branches principais
- Quality Gate status
- Secrets detectados
- Misconfigurations detectadas
- Coverage médio
- Score de governança
- Nível de maturidade
- Link para o SonarQube

**Recursos:**
- Busca por nome de projeto
- Ordenação por qualquer coluna
- Paginação

### 6. Aggregate Report

Análise temporal com histórico de scans:

**Gráficos de Evolução:**
- Total de issues ao longo do tempo
- Evolução por categoria OWASP
- Score de governança
- Projetos com secrets/misconfigurations

**Seletor de Período:**
- Últimos 7 dias
- Últimos 30 dias
- Últimos 90 dias
- Período customizado

**Análise de Tendências:**
- Projetos em melhoria
- Projetos em degradação
- Novas vulnerabilidades
- Vulnerabilidades corrigidas

## OWASP Top 10 2025

### Mapeamento de Categorias

| Categoria | Descrição | Prioridade | Impacto |
|-----------|-----------|------------|---------|
| **A01** | Broken Access Control | 1 | Acesso não autorizado a dados e funcionalidades |
| **A02** | Security Misconfiguration | 2 | Exposição de sistema por configuração inadequada |
| **A03** | Software Supply Chain Failures | 3 | Compromisso através de dependências vulneráveis |
| **A04** | Cryptographic Failures | 4 | Exposição de dados sensíveis e credenciais |
| **A05** | Injection | 5 | Execução de código malicioso no sistema |
| **A06** | Insecure Design | 6 | Falhas arquiteturais fundamentais |
| **A07** | Authentication Failures | 7 | Bypass de autenticação e sessões comprometidas |
| **A08** | Software and Data Integrity Failures | 8 | Dados e código comprometidos |
| **A09** | Logging & Alerting Failures | 9 | Detecção tardia de incidentes de segurança |
| **A10** | Mishandling of Exception Conditions | 10 | Vazamento de informações através de erros |

## Classificação Automática

O sistema utiliza um **algoritmo inteligente** de classificação em 3 níveis:

### Nível 1: Match Direto por Regra
Mapeia regras específicas do SonarQube para categorias OWASP:
```python
'java:S2077' → A05:2025-Injection
'java:S2068' → A07:2025-Authentication Failures
'java:S4790' → A04:2025-Cryptographic Failures
```

### Nível 2: Análise por Keywords
Busca palavras-chave na regra, mensagem e componente:
```python
'secret', 'password', 'token' → A04:2025-Cryptographic Failures
'injection', 'sql' → A05:2025-Injection
'auth', 'login' → A07:2025-Authentication Failures
```

### Nível 3: Fallback Inteligente
Para casos não classificados nos níveis anteriores, analisa o contexto completo.

## Sistema de Governança

### Score de Maturidade

Calculado com base em:
- **Volume total de issues** (penalidade de até 40 pontos)
- **Categorias OWASP afetadas** (penalidade de até 30 pontos)

### Níveis de Maturidade

```
SCORE    NÍVEL        DESCRIÇÃO
0-20     INICIAL      Processos ad-hoc
21-40    DEVELOPING   Alguns processos definidos
41-60    DEFINED      Processos documentados
61-80    MANAGED      Processos monitorados
81-100   OPTIMIZED    Melhoria contínua
```

### Classificação de Risco

```
SEVERIDADE (SonarQube) → RISCO
BLOCKER                → CRITICAL
CRITICAL               → CRITICAL
MAJOR                  → HIGH
MINOR                  → MEDIUM
INFO                   → LOW
```

## Histórico de Scans

### Versionamento Automático

Cada execução gera um snapshot timestamped:

```
sonarqube_scans_history/
├── scan_20250120_101530.json
├── scan_20250125_143022.json
└── scan_20250128_150155.json
```

### Estrutura do Snapshot

```json
{
  "version": "1.0",
  "timestamp": "2025-01-28T15:01:55",
  "scan_date": "20250128_150155",
  "data": {
    "collection_date": "2025-01-28T15:01:55",
    "total_projects": 209,
    "owasp_metrics_global": {...},
    "governance_metrics": {...},
    "projects": [...],
    "insights": {...}
  }
}
```

### Recuperação de Histórico

```python
# Últimos 30 dias
start_date = datetime.now() - timedelta(days=30)
scans = collector.get_scan_history(start_date=start_date)

# Período específico
scans = collector.get_scan_history(
    start_date=datetime(2025, 1, 1),
    end_date=datetime(2025, 1, 31)
)
```

## Estrutura de Arquivos

```
Dashboard-OwaspTop10-2025-SonarQube/
├── Dashboard-OwaspTop10-2025.py          # Script principal
├── README.md                             # Este arquivo
├── .gitignore                            # Arquivos ignorados pelo Git
├── sonarqube_dashboard.html              # Dashboard gerado (não versionado)
├── sonarqube_dashboard_data.json         # Dados em JSON (não versionado)
└── sonarqube_scans_history/              # Histórico de scans (não versionado)
    ├── scan_20250120_101530.json
    ├── scan_20250125_143022.json
    └── scan_20250128_150155.json
```

## Troubleshooting

### Erro de Conexão

**Problema**: `✗ Erro de conexão: [SSL: CERTIFICATE_VERIFY_FAILED]`

**Solução**: O sistema já desabilita SSL por padrão. Verifique se a URL está correta.

### Erro de Autenticação

**Problema**: `✗ Erro: 401`

**Solução**:
1. Verifique se o token está correto
2. Confirme que o token tem permissões de leitura
3. Verifique se o token não expirou

### Nenhum Projeto Encontrado

**Problema**: `⚠️  Nenhum projeto encontrado!`

**Solução**:
1. Verifique permissões do token
2. Confirme que existem projetos no SonarQube
3. Verifique se o usuário tem acesso aos projetos

### Porta 8000 em Uso

**Problema**: `OSError: [Errno 48] Address already in use`

**Solução**: Altere a porta no código:
```python
start_server(8001)  # Altere para outra porta
```

### Issues Não Classificadas

**Problema**: Muitas issues como "OTHER"

**Solução**: Adicione regras específicas ao mapeamento:
```python
OWASP_TOP_10_2025_MAPPING = {
    'A01:2025-Broken Access Control': {
        'rules': [
            'java:S2077',
            'sua:regra:aqui'  # Adicione sua regra
        ],
        ...
    }
}
```

### Dashboard Não Abre Automaticamente

**Solução**: Abra manualmente:
```
http://localhost:8000/sonarqube_dashboard.html
```

## Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

### Diretrizes

- Mantenha o código limpo e documentado
- Adicione testes quando possível
- Siga as convenções de código Python (PEP 8)
- Atualize o README quando adicionar funcionalidades

## Roadmap

- [ ] Exportação para PDF/Excel
- [ ] Integração com Jira para criação de tickets
- [ ] Notificações por email/Slack
- [ ] API REST para integração
- [ ] Docker container
- [ ] CI/CD pipeline
- [ ] Autenticação multi-usuário
- [ ] Customização de thresholds
- [ ] Machine Learning para predição de riscos

## Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## Suporte

Para dúvidas, problemas ou sugestões:

- Abra uma [issue](https://github.com/seu-usuario/Dashboard-OwaspTop10-2025-SonarQube/issues)
- Entre em contato: seu-email@empresa.com

## Agradecimentos

- [OWASP Foundation](https://owasp.org/) - Pelos padrões de segurança
- [SonarQube](https://www.sonarqube.org/) - Pela plataforma de análise de código
- [Chart.js](https://www.chartjs.org/) - Pelos gráficos interativos
- [Font Awesome](https://fontawesome.com/) - Pelos ícones

---

**Desenvolvido com segurança em mente** 🛡️
