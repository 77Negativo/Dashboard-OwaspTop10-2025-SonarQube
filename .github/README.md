# GitHub Actions - Dashboard OWASP Top 10 2025

## 📊 SonarQube Code Analysis Workflow

Este repositório utiliza o **workflow reusável** de análise SonarQube do repositório `77Negativo/core-action-sec`.

### Funcionamento

O workflow `sonarqube-scan.yaml` é executado automaticamente quando:
- Há um **push** nas branches: `main`, `develop` ou `staging`
- Há um **pull request** para as branches: `main` ou `develop`
- Executado **manualmente** via workflow_dispatch

### Arquitetura

```
Dashboard-OwaspTop10-2025-SonarQube
        ↓
  .github/workflows/sonarqube-scan.yaml
        ↓
    (chama workflow reusável)
        ↓
  77Negativo/core-action-sec/.github/workflows/sonarqube-analysis.yaml
        ↓
    (usa action SonarQube)
        ↓
  .github/actions/sonarqube/action.yml
        ↓
  SonarQube Server (http://192.168.8.221)
```

### Configuração Atual

O workflow está configurado para analisar o projeto Python com as seguintes configurações:

- **Project Key**: `dashboard-owasp-top10-2025`
- **Project Name**: `Dashboard OWASP Top 10 2025 - SonarQube`
- **Source Directory**: `.` (raiz do projeto)
- **Exclusions**:
  - `**/__pycache__/**`
  - `**/*.pyc`
  - `**/.pytest_cache/**`
  - `**/venv/**` e `**/env/**`
  - `**/sonarqube_scans_history/**`
  - `**/sonarqube_dashboard.html`

### Secrets Necessários

Para que o workflow funcione, os seguintes secrets devem estar configurados no repositório:

1. **`SONAR_TOKEN`** (Secret)
   - Token de autenticação do SonarQube
   - Como obter: SonarQube → My Account → Security → Generate Token

2. **`SONAR_HOST_URL`** (Secret ou Variable)
   - URL do servidor SonarQube
   - Valor atual: `http://192.168.8.221`

### Como Configurar os Secrets

1. Vá para **Settings** do repositório Dashboard
2. Navegue até **Secrets and variables** → **Actions**
3. Clique em **New repository secret**
4. Adicione:
   - Name: `SONAR_TOKEN`
   - Value: `[seu-token-do-sonarqube]`
5. Adicione:
   - Name: `SONAR_HOST_URL`
   - Value: `http://192.168.8.221`

### Execução Manual

Para executar o workflow manualmente:

1. Vá para a aba **Actions** do repositório Dashboard
2. Selecione o workflow **"📊 SonarQube Code Analysis"**
3. Clique em **"Run workflow"**
4. (Opcional) Marque **"Fail on Quality Gate"** se quiser que o workflow falhe caso o Quality Gate não passe
5. Clique em **"Run workflow"** para iniciar

### Outputs do Workflow

O workflow retorna as seguintes informações:

- **`quality-gate-status`**: Status do Quality Gate (OK, ERROR, WARN, etc)
- **`project-url`**: URL do projeto no SonarQube
- **`environment-name`**: Nome do environment detectado (PROD, STG, DEV)

### Visualizando Resultados

Após a execução do workflow:

1. **No GitHub Actions**:
   - Vá para a aba **Actions**
   - Clique no workflow executado
   - Veja o **Summary** para um resumo completo com métricas

2. **No SonarQube**:
   - Acesse: http://192.168.8.221
   - Procure pelo projeto: `dashboard-owasp-top10-2025_[ENV]`
   - Veja dashboard completo com bugs, vulnerabilidades, code smells, coverage, etc

### Personalizando o Workflow

Para modificar as configurações do workflow, edite o arquivo `.github/workflows/sonarqube-scan.yaml` e ajuste os inputs:

```yaml
with:
  project-key: 'dashboard-owasp-top10-2025'  # Altere se necessário
  sources: '.'                                # Diretórios de código fonte
  exclusions: |                               # Arquivos a excluir
    **/__pycache__/**,
    **/*.pyc
  fail-on-quality-gate: false                 # true para falhar se QG não passar
```

### Environment Detection

O workflow detecta automaticamente o environment baseado na branch:

- `main` ou `master` → **PROD**
- `staging` ou `stg` → **STG**
- `develop` ou `dev` → **DEV**
- Outras branches → **DEV**

O projeto no SonarQube será criado com o sufixo do environment:
- `dashboard-owasp-top10-2025_PROD`
- `dashboard-owasp-top10-2025_STG`
- `dashboard-owasp-top10-2025_DEV`

### Troubleshooting

#### Workflow falha com erro de autenticação
- Verifique se o `SONAR_TOKEN` está configurado corretamente
- Confirme que o token tem permissões de análise no SonarQube

#### Workflow não conecta ao SonarQube
- Verifique se o `SONAR_HOST_URL` está correto
- Confirme que o runner `k8s-onprem-runners` tem acesso à rede interna (192.168.x.x)

#### Quality Gate não aparece
- Verifique se o Quality Gate está configurado no projeto SonarQube
- Aumente o timeout se o projeto for muito grande

### Links Úteis

- **Repositório core-action-sec**: https://github.com/77Negativo/core-action-sec
- **Documentação do workflow reusável**: Ver `core-action-sec/.github/workflows/sonarqube-analysis.yaml`
- **SonarQube Server**: http://192.168.8.221
