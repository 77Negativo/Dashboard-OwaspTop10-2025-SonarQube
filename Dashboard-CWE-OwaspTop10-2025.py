#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import os
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import http.server
import socketserver
import webbrowser
import urllib3
import ssl
import warnings
from collections import defaultdict
from requests.exceptions import HTTPError, RequestException

warnings.filterwarnings('ignore', message='Unverified HTTPS request')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TOTAL_REPOSITORIES_EXPECTED = 209

MAIN_BRANCHES = ['main', 'master', 'develop', 'developer']

SECRETS_PATTERN = "secrets"

MISCONFIG_PATTERNS = ["config", "ssl", "tls", "certificate", "encryption", "cipher", "security"]

# Diretório para armazenar os scans históricos
SCANS_DIRECTORY = "sonarqube_scans_history"

SEVERITY_RISK_MAPPING = {
    'BLOCKER': 'CRITICAL',
    'CRITICAL': 'CRITICAL', 
    'MAJOR': 'HIGH',
    'MINOR': 'MEDIUM',
    'INFO': 'LOW'
}

RISK_COLORS = {
    'CRITICAL': '#8B0000',
    'HIGH': '#DC3545',
    'MEDIUM': '#FF9800',
    'LOW': '#FFC107'
}

OWASP_TOP_10_2025_MAPPING = {
    'A01:2025-Broken Access Control': {
        'description': 'Controle de Acesso Quebrado',
        'rules': [
            'java:S2077', 'java:S3649', 'java:S5131', 'java:S5144',
            'javascript:S5148', 'php:S3649', 'python:S5131',
            'csharp:S2077', 'sql:S2077', 'java:S5808', 'java:S4601',
            'php:S4834', 'csharp:S4834', 'xml:S5604'
        ],
        'keywords': ['access', 'authorization', 'permission', 'privilege', 'authentication'],
        'color': '#8B0000',
        'priority': 1,
        'icon': 'fa-shield-alt',
        'impact': 'Acesso não autorizado a dados e funcionalidades'
    },
    'A02:2025-Security Misconfiguration': {
        'description': 'Configuração de Segurança Incorreta',
        'rules': [
            'java:S4434', 'java:S4502', 'java:S5527', 'javascript:S4426',
            'python:S5445', 'csharp:S4426', 'docker:S6471' 'php:S4502',
            'java:S5122', 'csharp:S5122'
        ],
        'keywords': ['config', 'ssl', 'tls', 'certificate', 'encryption', 'cipher'],
        'color': '#DC3545',
        'priority': 2,
        'icon': 'fa-cogs',
        'impact': 'Exposição de sistema por configuração inadequada',
        'highlight': True
    },
    'A03:2025-Software Supply Chain Failures': {
        'description': 'Falhas na Cadeia de Suprimentos de Software',
        'rules': [
            'java:S4823', 'javascript:S4507', 'python:S4507',
            'csharp:S4507', 'docker:S6476',  'java:S4507', 'php:S4823'
        ],
        'keywords': ['dependency', 'package', 'library', 'component', 'supply', 'chain'],
        'color': '#FF6B6B',
        'priority': 3,
        'icon': 'fa-link',
        'impact': 'Compromisso através de dependências vulneráveis'
    },
    'A04:2025-Cryptographic Failures': {
        'description': 'Falhas Criptográficas',
        'rules': [
            'java:S4790', 'java:S5542', 'java:S5547', 'javascript:S4790',
            'python:S4426', 'csharp:S4790', 'secrets:S6290', 'secrets:S6706'
            'java:S2278', 'csharp:S2278'
        ],
        'keywords': ['crypto', 'hash', 'encrypt', 'decrypt', 'key', 'secret', 'password', 'token'],
        'color': '#FF9800',
        'priority': 4,
        'icon': 'fa-key',
        'impact': 'Exposição de dados sensíveis e credenciais',
        'highlight': True
    },
    'A05:2025-Injection': {
        'description': 'Injeção',
        'rules': [
            'java:S2077', 'java:S3649', 'javascript:S3649', 'php:S3649',
            'python:S3649', 'csharp:S3649', 'sql:S1192',  'java:S2091',
            'csharp:S2091', 'php:S2091', 'javasecurity:S5147', 'jssecurity:S5147',
            'pythonsecurity:S5147', 'csharp:S5147'
        ],
        'keywords': ['injection', 'sql', 'nosql', 'ldap', 'xpath', 'command'],
        'color': '#FFC107',
        'priority': 5,
        'icon': 'fa-syringe',
        'impact': 'Execução de código malicioso no sistema'
    },
    'A06:2025-Insecure Design': {
        'description': 'Design Inseguro',
        'rules': [
            'java:S1313', 'java:S2245', 'javascript:S2245',
            'python:S2245', 'csharp:S2245'
        ],
        'keywords': ['design', 'pattern', 'architecture', 'threat', 'model'],
        'color': '#9C27B0',
        'priority': 6,
        'icon': 'fa-drafting-compass',
        'impact': 'Falhas arquiteturais fundamentais'
    },
    'A07:2025-Authentication Failures': {
        'description': 'Falhas de Autenticação',
        'rules': [
            'java:S2068', 'java:S6437', 'javascript:S2068',
            'python:S2068', 'csharp:S2068', 'secrets:S6290', 'java:S5804', 'java:S5876'
        ],
        'keywords': ['authentication', 'session', 'login', 'credential', 'password'],
        'color': '#3F51B5',
        'priority': 7,
        'icon': 'fa-user-shield',
        'impact': 'Bypass de autenticação e sessões comprometidas'
    },
    'A08:2025-Software and Data Integrity Failures': {
        'description': 'Falhas de Integridade de Software e Dados',
        'rules': [
            'java:S4829', 'javascript:S4829', 'python:S4829',
            'csharp:S4829', 'docker:S6475',  'csharp:S5042', 'csharp:S5766'
        ],
        'keywords': ['integrity', 'signature', 'verify', 'checksum', 'hash'],
        'color': '#009688',
        'priority': 8,
        'icon': 'fa-certificate',
        'impact': 'Dados e código comprometidos'
    },
    'A09:2025-Logging & Alerting Failures': {
        'description': 'Falhas de Logging e Alertas',
        'rules': [
            'java:S2139', 'java:S106', 'javascript:S106',
            'python:S106', 'csharp:S106', 'java:S4792',
            'csharp:S4792'
        ],
        'keywords': ['log', 'logging', 'alert', 'monitor', 'audit', 'trace'],
        'color': '#607D8B',
        'priority': 9,
        'icon': 'fa-clipboard-list',
        'impact': 'Detecção tardia de incidentes de segurança'
    },
    'A10:2025-Mishandling of Exception Conditions': {
        'description': 'Manuseio Inadequado de Condições de Exceção',
        'rules': [
            'java:S1181', 'java:S2139', 'javascript:S1181',
            'python:S1181', 'csharp:S1181'
        ],
        'keywords': ['exception', 'error', 'handling', 'catch', 'throw'],
        'color': '#795548',
        'priority': 10,
        'icon': 'fa-exclamation-triangle',
        'impact': 'Vazamento de informações através de erros'
    }
}

GOVERNANCE_MATURITY_LEVELS = {
    'INICIAL': {'min_score': 0, 'max_score': 20, 'description': 'Inicial - Processos ad-hoc'},
    'DEVELOPING': {'min_score': 21, 'max_score': 40, 'description': 'Em Desenvolvimento - Alguns processos definidos'},
    'DEFINED': {'min_score': 41, 'max_score': 60, 'description': 'Definido - Processos documentados'},
    'MANAGED': {'min_score': 61, 'max_score': 80, 'description': 'Gerenciado - Processos monitorados'},
    'OPTIMIZED': {'min_score': 81, 'max_score': 100, 'description': 'Otimizado - Melhoria contínua'}
}

# CWE Top 25 2025 - Most Dangerous Software Weaknesses
CWE_TOP_25_2025 = {
    'CWE-79': {'rank': 1, 'name': 'Cross-site Scripting (XSS)', 'category': 'Input Validation', 'owasp': 'A03:2021', 'identity_related': False},
    'CWE-89': {'rank': 2, 'name': 'SQL Injection', 'category': 'Input Validation', 'owasp': 'A03:2021', 'identity_related': False},
    'CWE-20': {'rank': 3, 'name': 'Improper Input Validation', 'category': 'Input Validation', 'owasp': 'A03:2021', 'identity_related': False},
    'CWE-78': {'rank': 4, 'name': 'OS Command Injection', 'category': 'Input Validation', 'owasp': 'A03:2021', 'identity_related': False},
    'CWE-787': {'rank': 5, 'name': 'Out-of-bounds Write', 'category': 'Memory', 'owasp': 'A06:2021', 'identity_related': False},
    'CWE-862': {'rank': 6, 'name': 'Missing Authorization', 'category': 'Authorization', 'owasp': 'A01:2021', 'identity_related': True},
    'CWE-352': {'rank': 7, 'name': 'Cross-Site Request Forgery (CSRF)', 'category': 'Input Validation', 'owasp': 'A01:2021', 'identity_related': False},
    'CWE-434': {'rank': 8, 'name': 'Unrestricted Upload of File with Dangerous Type', 'category': 'Input Validation', 'owasp': 'A04:2021', 'identity_related': False},
    'CWE-94': {'rank': 9, 'name': 'Improper Control of Generation of Code', 'category': 'Input Validation', 'owasp': 'A03:2021', 'identity_related': False},
    'CWE-22': {'rank': 10, 'name': 'Path Traversal', 'category': 'Input Validation', 'owasp': 'A01:2021', 'identity_related': False},
    'CWE-502': {'rank': 11, 'name': 'Deserialization of Untrusted Data', 'category': 'Input Validation', 'owasp': 'A08:2021', 'identity_related': False},
    'CWE-287': {'rank': 12, 'name': 'Improper Authentication', 'category': 'Authentication', 'owasp': 'A07:2021', 'identity_related': True},
    'CWE-285': {'rank': 13, 'name': 'Improper Authorization', 'category': 'Authorization', 'owasp': 'A01:2021', 'identity_related': True},
    'CWE-798': {'rank': 14, 'name': 'Use of Hard-coded Credentials', 'category': 'Authentication', 'owasp': 'A07:2021', 'identity_related': True},
    'CWE-269': {'rank': 15, 'name': 'Improper Privilege Management', 'category': 'Authorization', 'owasp': 'A01:2021', 'identity_related': True},
    'CWE-918': {'rank': 16, 'name': 'Server-Side Request Forgery (SSRF)', 'category': 'Input Validation', 'owasp': 'A10:2021', 'identity_related': False},
    'CWE-416': {'rank': 17, 'name': 'Use After Free', 'category': 'Memory', 'owasp': 'A06:2021', 'identity_related': False},
    'CWE-476': {'rank': 18, 'name': 'NULL Pointer Dereference', 'category': 'Memory', 'owasp': 'A06:2021', 'identity_related': False},
    'CWE-611': {'rank': 19, 'name': 'Improper Restriction of XML External Entity Reference', 'category': 'Input Validation', 'owasp': 'A05:2021', 'identity_related': False},
    'CWE-119': {'rank': 20, 'name': 'Improper Restriction of Operations within Bounds of Memory Buffer', 'category': 'Memory', 'owasp': 'A06:2021', 'identity_related': False},
    'CWE-522': {'rank': 21, 'name': 'Insufficiently Protected Credentials', 'category': 'Authentication', 'owasp': 'A02:2021', 'identity_related': True},
    'CWE-125': {'rank': 22, 'name': 'Out-of-bounds Read', 'category': 'Memory', 'owasp': 'A06:2021', 'identity_related': False},
    'CWE-306': {'rank': 23, 'name': 'Missing Authentication for Critical Function', 'category': 'Authentication', 'owasp': 'A07:2021', 'identity_related': True},
    'CWE-295': {'rank': 24, 'name': 'Improper Certificate Validation', 'category': 'Config', 'owasp': 'A02:2021', 'identity_related': False},
    'CWE-732': {'rank': 25, 'name': 'Incorrect Permission Assignment for Critical Resource', 'category': 'Authorization', 'owasp': 'A01:2021', 'identity_related': True}
}

# Mapeamento de CWE para categorias de domínio
CWE_DOMAIN_MAPPING = {
    'Authentication': ['CWE-287', 'CWE-798', 'CWE-522', 'CWE-306'],
    'Authorization': ['CWE-862', 'CWE-285', 'CWE-269', 'CWE-732'],
    'Input Validation': ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-78', 'CWE-352', 'CWE-434', 'CWE-94', 'CWE-22', 'CWE-502', 'CWE-918', 'CWE-611'],
    'Memory': ['CWE-787', 'CWE-416', 'CWE-476', 'CWE-119', 'CWE-125'],
    'Config': ['CWE-295']
}


class SonarQubeCollector:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip('/')
        self.token = token
        
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        
        # Criar diretório para armazenar scans históricos
        self.ensure_scans_directory()
        
        print(f"🔧 Autenticação configurada: Bearer token")
        print(f"🔧 SSL será SEMPRE desabilitado em todas requisições")
        print(f"🔧 Total de repositórios esperados: {TOTAL_REPOSITORIES_EXPECTED}")
        print(f"🔧 Branches monitoradas: {', '.join(MAIN_BRANCHES)}")
        print(f"🔧 Monitoramento de secrets: Todas as regras que contêm '{SECRETS_PATTERN}'")
        print(f"🔧 Monitoramento de misconfigurations: {', '.join(MISCONFIG_PATTERNS)}")
        print(f"🔧 Classificação de risco: CRITICAL > HIGH > MEDIUM > LOW")
        print(f"🔧 Governança baseada em: OWASP Top 10 2025")
        print(f"🔧 FILTRO: Ignorando dependency-check-report.html")
        print()
    
    def _make_request(self, url: str, params: dict = None, timeout: int = 30) -> requests.Response:
        return requests.get(
            url,
            headers=self.headers,
            params=params,
            verify=False,
            timeout=timeout,
            allow_redirects=True
        )
    
    def ensure_scans_directory(self):
        """Garante que o diretório de scans existe"""
        if not os.path.exists(SCANS_DIRECTORY):
            os.makedirs(SCANS_DIRECTORY)
            print(f"📁 Diretório criado: {SCANS_DIRECTORY}")
        else:
            print(f"📁 Diretório existente: {SCANS_DIRECTORY}")
    
    def save_scan_snapshot(self, data: Dict) -> str:
        """Salva um snapshot do scan com versionamento"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_{timestamp}.json"
        filepath = os.path.join(SCANS_DIRECTORY, filename)
        
        # Adicionar metadados ao snapshot
        snapshot = {
            'version': '1.0',
            'timestamp': datetime.now().isoformat(),
            'scan_date': timestamp,
            'data': data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Snapshot salvo: {filepath}")
        return filepath
    
    def get_scan_history(self, start_date: Optional[datetime] = None, 
                        end_date: Optional[datetime] = None) -> List[Dict]:
        """Recupera histórico de scans filtrado por data"""
        if not os.path.exists(SCANS_DIRECTORY):
            return []
        
        scans = []
        for filename in sorted(os.listdir(SCANS_DIRECTORY)):
            if not filename.startswith('scan_') or not filename.endswith('.json'):
                continue
            
            filepath = os.path.join(SCANS_DIRECTORY, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    snapshot = json.load(f)
                    scan_datetime = datetime.fromisoformat(snapshot['timestamp'])
                    
                    # Filtrar por data se especificado
                    if start_date and scan_datetime < start_date:
                        continue
                    if end_date and scan_datetime > end_date:
                        continue
                    
                    scans.append({
                        'filename': filename,
                        'filepath': filepath,
                        'timestamp': snapshot['timestamp'],
                        'scan_date': snapshot['scan_date'],
                        'data': snapshot['data']
                    })
            except Exception as e:
                print(f"⚠️ Erro ao ler {filename}: {e}")
                continue
        
        return scans

    
    def is_main_branch(self, branch_name: str, is_main: bool = False) -> bool:
        if is_main:
            return True
        
        branch_lower = branch_name.lower()
        return any(main_branch in branch_lower for main_branch in MAIN_BRANCHES)
    
    def classify_rule_to_owasp(self, rule: str, message: str = "", component: str = "") -> str:
        rule_lower = rule.lower()
        message_lower = message.lower()
        component_lower = component.lower()
        
        for owasp_category, data in OWASP_TOP_10_2025_MAPPING.items():
            if rule in data.get('rules', []):
                return owasp_category
        
        combined_text = f"{rule_lower} {message_lower} {component_lower}"
        
        for owasp_category, data in OWASP_TOP_10_2025_MAPPING.items():
            keywords = data.get('keywords', [])
            if any(keyword in combined_text for keyword in keywords):
                return owasp_category
        
        if 'secret' in combined_text or 'password' in combined_text or 'token' in combined_text:
            return 'A04:2025-Cryptographic Failures'
        elif 'injection' in combined_text or 'sql' in combined_text:
            return 'A05:2025-Injection'
        elif 'auth' in combined_text or 'login' in combined_text:
            return 'A07:2025-Authentication Failures'
        elif 'access' in combined_text or 'permission' in combined_text:
            return 'A01:2025-Broken Access Control'
        elif any(pattern in combined_text for pattern in MISCONFIG_PATTERNS):
            return 'A02:2025-Security Misconfiguration'
        
        return 'OTHER'
    
    def calculate_governance_maturity_score(self, owasp_metrics: Dict) -> Dict:
        total_issues = sum(owasp_metrics.values())
        total_categories = len(OWASP_TOP_10_2025_MAPPING)
        
        if total_issues == 0:
            base_score = 100
        else:
            categories_with_issues = len([v for v in owasp_metrics.values() if v > 0])
            coverage_penalty = (categories_with_issues / total_categories) * 30
            
            volume_penalty = min((total_issues / 100) * 40, 40)
            
            base_score = max(0, 100 - coverage_penalty - volume_penalty)
        
        for level, data in GOVERNANCE_MATURITY_LEVELS.items():
            if data['min_score'] <= base_score <= data['max_score']:
                return {
                    'score': base_score,
                    'level': level,
                    'description': data['description'],
                    'total_issues': total_issues,
                    'categories_affected': len([v for v in owasp_metrics.values() if v > 0])
                }
        
        return {
            'score': base_score,
            'level': 'UNDEFINED',
            'description': 'Nível indefinido',
            'total_issues': total_issues,
            'categories_affected': len([v for v in owasp_metrics.values() if v > 0])
        }
    
    def generate_insights(self, data: Dict) -> Dict:
        insights = {
            'critical_alerts': [],
            'opportunities': [],
            'recommendations': [],
            'trends': [],
            'benchmarks': {}
        }
        
        projects = data.get('projects', [])
        total_projects = len(projects)
        secrets_count = len([d for d in data.get('issues_details', []) if 'secret' in d.get('rule', '').lower()])
        misconfig_count = len([d for d in data.get('issues_details', []) if d.get('owasp_category') == 'A02:2025-Security Misconfiguration'])
        governance = data.get('governance_metrics', {})
        owasp_global = data.get('owasp_metrics_global', {})
        coverage_projects = len([p for p in projects if p.get('average_coverage', 0) > 0])
        
        if secrets_count > 0:
            insights['critical_alerts'].append({
                'level': 'CRITICAL',
                'title': f'🔐 {secrets_count} Secrets Expostos Detectados',
                'description': f'{data.get("projects_with_secrets", 0)} projetos afetados. Risco CRÍTICO de vazamento de dados.',
                'action': 'Revogar credenciais imediatamente',
                'impact': 'Alto risco de breach de segurança',
                'category': 'A04:2025-Cryptographic Failures'
            })
        
        if misconfig_count > 0:
            insights['critical_alerts'].append({
                'level': 'CRITICAL',
                'title': f'⚙️ {misconfig_count} Configurações de Segurança Incorretas',
                'description': f'Configurações inadequadas que podem expor o sistema a ataques.',
                'action': 'Revisar e corrigir configurações de segurança',
                'impact': 'Exposição do sistema por configuração inadequada',
                'category': 'A02:2025-Security Misconfiguration'
            })
        
        high_vuln_projects = [p for p in projects if sum((p.get('owasp_metrics', {})).values()) > 50]
        if high_vuln_projects:
            insights['critical_alerts'].append({
                'level': 'HIGH',
                'title': f'🔴 {len(high_vuln_projects)} Projetos com Alto Volume de Vulnerabilidades',
                'description': f'Projetos com >50 issues de segurança necessitam intervenção urgente.',
                'action': 'Revisar e priorizar correções',
                'impact': 'Risco elevado de exploração'
            })
        
        failed_qg = data.get('projects_main_failed', 0)
        if failed_qg > 0:
            insights['critical_alerts'].append({
                'level': 'MEDIUM',
                'title': f'⚠️ {failed_qg} Projetos com Quality Gate Reprovado',
                'description': f'Projetos não atendem aos critérios mínimos de qualidade.',
                'action': 'Implementar correções para aprovar QG',
                'impact': 'Qualidade do código comprometida'
            })
        
        no_coverage_projects = total_projects - coverage_projects
        if no_coverage_projects > 0:
            insights['critical_alerts'].append({
                'level': 'MEDIUM',
                'title': f'📊 {no_coverage_projects} Projetos sem Coverage de Testes',
                'description': f'Projetos sem métricas de cobertura de testes configuradas.',
                'action': 'Implementar testes e configurar coverage',
                'impact': 'Qualidade e confiabilidade questionáveis'
            })
        
        top_owasp = sorted(owasp_global.items(), key=lambda x: x[1], reverse=True)[:3]
        if top_owasp:
            insights['opportunities'].append({
                'title': '🎯 Focar nas Top 3 Categorias OWASP',
                'description': f'Concentrar esforços em: {", ".join([cat.replace("A0", "A").replace(":2025-", "") for cat, count in top_owasp if count > 0])}',
                'benefit': 'Redução de 60-80% dos riscos de segurança',
                'effort': 'Médio'
            })
        
        if governance.get('level') in ['INITIAL', 'DEVELOPING']:
            insights['opportunities'].append({
                'title': '📈 Oportunidade de Evolução da Governança',
                'description': f'Nível atual: {governance.get("level")}. Potencial para subir 2 níveis.',
                'benefit': 'Redução de 40-60% nos incidentes de segurança',
                'effort': 'Alto'
            })
        
        if coverage_projects < total_projects * 0.8:
            insights['opportunities'].append({
                'title': '🧪 Oportunidade de Melhoria em Testes',
                'description': f'Apenas {coverage_projects}/{total_projects} projetos têm coverage configurado.',
                'benefit': 'Aumento da qualidade e confiabilidade do código',
                'effort': 'Médio'
            })
        
        insights['recommendations'].extend([
            {
                'priority': 1,
                'title': '🔐 Implementar Secret Scanning Automático',
                'description': 'Scanner automático no CI/CD para detectar credentials',
                'timeline': '2-4 semanas',
                'roi': 'Alto - Prevenção de vazamentos'
            },
            {
                'priority': 2,
                'title': '⚙️ Auditoria de Configurações de Segurança',
                'description': 'Revisar e padronizar configurações de SSL/TLS e certificados',
                'timeline': '3-5 semanas',
                'roi': 'Alto - Redução de exposição'
            },
            {
                'priority': 3,
                'title': '📊 Quality Gates Obrigatórios',
                'description': 'Tornar QG mandatório para deploy em produção',
                'timeline': '1-2 semanas',
                'roi': 'Médio - Melhoria da qualidade'
            },
            {
                'priority': 4,
                'title': '🧪 Implementar Coverage Mínimo',
                'description': 'Configurar coverage mínimo de 80% para todos os projetos',
                'timeline': '4-6 semanas',
                'roi': 'Alto - Melhoria da qualidade'
            },
            {
                'priority': 5,
                'title': '🎓 Treinamento OWASP Top 10 2025',
                'description': 'Capacitar equipes nas novas categorias de risco',
                'timeline': '4-6 semanas',
                'roi': 'Alto - Prevenção proativa'
            }
        ])
        
        insights['benchmarks'] = {
            'governance_score': {
                'current': governance.get('score', 0),
                'industry_avg': 65,
                'best_practice': 85,
                'status': 'below' if governance.get('score', 0) < 65 else 'above'
            },
            'secrets_ratio': {
                'current': (secrets_count / max(total_projects, 1) * 100),
                'industry_avg': 15,
                'best_practice': 5,
                'status': 'above' if (secrets_count / max(total_projects, 1) * 100) > 15 else 'below'
            },
            'qg_pass_rate': {
                'current': (data.get('projects_main_passed', 0) / max(total_projects, 1) * 100),
                'industry_avg': 75,
                'best_practice': 95,
                'status': 'below' if (data.get('projects_main_passed', 0) / max(total_projects, 1) * 100) < 75 else 'above'
            },
            'coverage_ratio': {
                'current': (coverage_projects / max(total_projects, 1) * 100),
                'industry_avg': 70,
                'best_practice': 90,
                'status': 'below' if (coverage_projects / max(total_projects, 1) * 100) < 70 else 'above'
            }
        }
        
        return insights
    
    def test_connection_and_auth(self) -> bool:
        print("=" * 70)
        print("TESTANDO CONEXÃO E AUTENTICAÇÃO")
        print("=" * 70)
        
        try:
            url = f"{self.base_url}/api/system/status"
            print(f"1. Testando conexão: {url}")
            
            response = requests.get(url, verify=False, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✓ Conexão OK - SonarQube {data.get('version')} está UP")
            else:
                print(f"   ✗ Erro: Status {response.status_code}")
                return False
        except Exception as e:
            print(f"   ✗ Erro de conexão: {e}")
            return False
        
        try:
            url = f"{self.base_url}/api/projects/search"
            print(f"\n2. Testando acesso a projetos: {url}")
            
            response = self._make_request(url, params={'ps': 1})
            
            if response.status_code == 200:
                data = response.json()
                total = data.get('paging', {}).get('total', 0)
                print(f"   ✓ Acesso OK - {total} projetos disponíveis")
                print("=" * 70)
                print()
                return True
            else:
                print(f"   ✗ Erro: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"   ✗ Erro: {e}")
            return False
    
    def get_all_projects(self) -> List[Dict]:
        projects = []
        page = 1
        page_size = 500
        
        print("Coletando projetos...")
        
        while True:
            url = f"{self.base_url}/api/projects/search"
            
            try:
                response = self._make_request(url, params={'p': page, 'ps': page_size})
                response.raise_for_status()
                data = response.json()
                
                components = data.get('components', [])
                projects.extend(components)
                
                total = data.get('paging', {}).get('total', 0)
                
                if len(projects) >= total or len(components) == 0:
                    break
                    
                page += 1
                
            except Exception as e:
                print(f"  ✗ Erro: {e}")
                break
        
        print(f"✓ {len(projects)} projetos coletados")
        return projects
    
    def get_project_branches(self, project_key: str) -> List[Dict]:
        url = f"{self.base_url}/api/project_branches/list"
        
        try:
            response = self._make_request(url, params={'project': project_key})
            response.raise_for_status()
            all_branches = response.json().get('branches', [])
            
            main_branches = []
            for branch in all_branches:
                branch_name = branch.get('name', '')
                is_main = branch.get('isMain', False)
                
                if self.is_main_branch(branch_name, is_main):
                    main_branches.append(branch)
            
            if not main_branches and all_branches:
                main_branches = [all_branches[0]]
            
            return main_branches
            
        except Exception as e:
            print(f"    ⚠ Erro ao obter branches: {e}")
            return []
    
    def get_issues_detailed(self, project_key: str, branch: str = None) -> List[Dict]:
        issues = []
        page = 1
        page_size = 500
        
        print(f"    → Coletando issues...")
        
        while True:
            url = f"{self.base_url}/api/issues/search"
            params = {
                'componentKeys': project_key,
                'p': page,
                'ps': page_size,
                'resolved': 'false',
                'additionalFields': 'comments'
            }
            
            if branch:
                params['branch'] = branch
            
            try:
                response = self._make_request(url, params=params)
                response.raise_for_status()
                data = response.json()
                
                batch = data.get('issues', [])
                
                for issue in batch:
                    component = issue.get('component', '')
                    if 'dependency-check-report.html' not in component:
                        issues.append(issue)
                
                total = data.get('total', 0)
                
                if len(issues) >= total or len(batch) == 0:
                    break
                
                page += 1
                
                if page > 10:
                    break
                    
            except Exception as e:
                print(f"      ⚠ Erro na página {page}: {e}")
                break
        
        print(f"    ✓ Issues coletados: {len(issues)}")
        
        blockers = [i for i in issues if i.get('severity') == 'BLOCKER']
        if blockers:
            print(f"    🔴 BLOCKERS encontrados: {len(blockers)}")
        
        secret_issues = [i for i in issues if SECRETS_PATTERN in i.get('rule', '').lower()]
        if secret_issues:
            print(f"    🔐 SECRETS encontrados: {len(secret_issues)} issues relacionados a secrets")
        
        misconfig_issues = [i for i in issues if any(pattern in i.get('rule', '').lower() or pattern in i.get('message', '').lower() for pattern in MISCONFIG_PATTERNS)]
        if misconfig_issues:
            print(f"    ⚙️ MISCONFIGURATIONS encontrados: {len(misconfig_issues)} issues de configuração")
            
        owasp_classification = defaultdict(int)
        for issue in issues:
            rule = issue.get('rule', '')
            message = issue.get('message', '')
            component = issue.get('component', '')
            owasp_category = self.classify_rule_to_owasp(rule, message, component)
            owasp_classification[owasp_category] += 1
            
        if owasp_classification:
            print(f"    📊 Classificação OWASP Top 10 2025:")
            for category, count in owasp_classification.items():
                if count > 0:
                    print(f"      - {category}: {count} issue(s)")
        
        return issues
    
    def get_current_metrics(self, project_key: str, branch: str = None) -> Dict:
        url = f"{self.base_url}/api/measures/component"
        params = {
            'component': project_key,
            'metricKeys': 'coverage,bugs,vulnerabilities,code_smells,duplicated_lines_density,ncloc,security_hotspots,sqale_index,reliability_rating,security_rating,sqale_rating,blocker_violations,critical_violations,major_violations,minor_violations,info_violations,new_bugs,new_vulnerabilities,new_code_smells'
        }
        
        if branch:
            params['branch'] = branch
        
        try:
            response = self._make_request(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            measures = data.get('component', {}).get('measures', [])
            metrics = {}
            
            for measure in measures:
                key = measure.get('metric')
                value = measure.get('value', '0')
                
                if 'rating' in key:
                    metrics[key] = value
                else:
                    try:
                        metrics[key] = float(value)
                    except:
                        metrics[key] = value
            
            return metrics
        except Exception as e:
            print(f"      ⚠ Erro ao obter métricas: {e}")
            return {}
    
    def get_quality_gate_status(self, project_key: str, branch: str = None) -> str:
        url = f"{self.base_url}/api/qualitygates/project_status"
        params = {'projectKey': project_key}
        
        if branch:
            params['branch'] = branch
        
        try:
            response = self._make_request(url, params=params)
            response.raise_for_status()
            data = response.json()
            
            status = data.get('projectStatus', {}).get('status', 'NONE')
            return status
        except Exception as e:
            return 'NONE'
    
    def collect_dashboard_data(self) -> Dict:
        print("\n" + "=" * 70)
        print("COLETANDO DADOS PARA DASHBOARD")
        print("=" * 70)
        print()
        print("ℹ️  Coletando apenas branches principais: main, master, develop, developer")
        print("ℹ️  Implementando classificação OWASP Top 10 2025...")
        print("ℹ️  Destaque especial para Secrets e Misconfigurations...")
        print("ℹ️  Gerando insights de inteligência gerencial...")
        print("ℹ️  FILTRO ATIVO: Ignorando dependency-check-report.html")
        print("ℹ️  Isso pode demorar alguns minutos dependendo do número de projetos.")
        print()
        
        all_projects = self.get_all_projects()
        dashboard_data = {
            'collection_date': datetime.now().isoformat(),
            'sonar_url': self.base_url,
            'total_projects': len(all_projects),
            'total_repositories_expected': TOTAL_REPOSITORIES_EXPECTED,
            'main_branches_filter': MAIN_BRANCHES,
            'secrets_pattern': SECRETS_PATTERN,
            'misconfig_patterns': MISCONFIG_PATTERNS,
            'owasp_top_10_2025': OWASP_TOP_10_2025_MAPPING,
            'projects_main_passed': 0,
            'projects_main_failed': 0,
            'projects_main_none': 0,
            'projects_with_secrets': 0,
            'projects_with_misconfigs': 0,
            'projects_with_coverage': 0,
            'owasp_metrics_global': defaultdict(int),
            'owasp_metrics_by_project': {},
            'governance_metrics': {},
            'issues_details': [],
            'projects_risk_matrix': [],
            'projects': []
        }
        
        for idx, project in enumerate(all_projects, 1):
            project_key = project.get('key')
            project_name = project.get('name')
            
            print(f"\n[{idx}/{len(all_projects)}] {project_name}")
            print(f"  Key: {project_key}")
            
            branches = self.get_project_branches(project_key)
            
            if not branches:
                print("  ⚠ Sem branches principais - usando branch padrão")
                branches = [{'name': 'main', 'isMain': True, 'type': 'BRANCH'}]
            else:
                print(f"  ✓ {len(branches)} branch(es) principal(is) encontrada(s)")
            
            project_data = {
                'key': project_key,
                'name': project_name,
                'branches': [],
                'main_qg_status': 'NONE',
                'has_secrets': False,
                'has_misconfigs': False,
                'secrets_count': 0,
                'misconfigs_count': 0,
                'owasp_metrics': defaultdict(int),
                'governance_maturity': {},
                'coverage_branches': [],
                'average_coverage': 0
            }
            
            project_has_secrets = False
            project_has_misconfigs = False
            project_owasp_metrics = defaultdict(int)
            project_coverage_sum = 0
            project_coverage_count = 0
            
            for branch in branches:
                branch_name = branch.get('name')
                is_main = branch.get('isMain', False)
                
                print(f"\n  📍 Branch Principal: {branch_name} {'(Main)' if is_main else ''}")
                
                try:
                    print(f"    → Coletando métricas atuais...")
                    current_metrics = self.get_current_metrics(project_key, branch_name)
                    
                    if current_metrics:
                        cov = current_metrics.get('coverage', 0)
                        bugs = current_metrics.get('bugs', 0)
                        vulns = current_metrics.get('vulnerabilities', 0)
                        print(f"    ✓ Cobertura: {cov:.1f}%, Bugs: {int(bugs)}, Vulns: {int(vulns)}")
                        
                        if cov > 0:
                            project_coverage_sum += cov
                            project_coverage_count += 1
                            project_data['coverage_branches'].append({
                                'branch': branch_name,
                                'coverage': cov
                            })
                    
                    qg_status = 'NONE'
                    if is_main or branch_name.lower() in ['main', 'master']:
                        qg_status = self.get_quality_gate_status(project_key, branch_name)
                        print(f"    ✓ Quality Gate: {qg_status}")
                        
                        project_data['main_qg_status'] = qg_status
                    
                    issues = self.get_issues_detailed(project_key, branch_name)
                    
                    issues_by_type = defaultdict(int)
                    issues_by_severity = defaultdict(int)
                    rules_count = defaultdict(int)
                    blocker_issues = []
                    secrets_issues = []
                    misconfig_issues = []
                    branch_owasp_metrics = defaultdict(int)
                    
                    for issue in issues:
                        issue_type = issue.get('type', 'UNKNOWN')
                        severity = issue.get('severity', 'UNKNOWN')
                        rule = issue.get('rule', 'UNKNOWN')
                        creation_date = issue.get('creationDate', '')
                        message = issue.get('message', '')
                        component = issue.get('component', '')
                        
                        issues_by_type[issue_type] += 1
                        issues_by_severity[severity] += 1
                        rules_count[rule] += 1
                        
                        owasp_category = self.classify_rule_to_owasp(rule, message, component)
                        branch_owasp_metrics[owasp_category] += 1
                        project_owasp_metrics[owasp_category] += 1
                        dashboard_data['owasp_metrics_global'][owasp_category] += 1
                        
                        if severity == 'BLOCKER':
                            blocker_issues.append({
                                'key': issue.get('key', ''),
                                'message': issue.get('message', 'Sem descrição'),
                                'component': issue.get('component', '').split(':')[-1] if ':' in issue.get('component', '') else issue.get('component', ''),
                                'line': issue.get('line', 0),
                                'type': issue_type,
                                'rule': rule,
                                'creationDate': creation_date,
                                'owasp_category': owasp_category
                            })
                        
                        if SECRETS_PATTERN in rule.lower():
                            project_has_secrets = True
                            project_data['secrets_count'] += 1
                            
                            secrets_issues.append({
                                'key': issue.get('key', ''),
                                'message': issue.get('message', 'Sem descrição'),
                                'component': issue.get('component', '').split(':')[-1] if ':' in issue.get('component', '') else issue.get('component', ''),
                                'line': issue.get('line', 0),
                                'severity': severity,
                                'risk_level': SEVERITY_RISK_MAPPING.get(severity, 'UNKNOWN'),
                                'type': issue_type,
                                'rule': rule,
                                'creationDate': creation_date,
                                'projectName': project_name,
                                'projectKey': project_key,
                                'branchName': branch_name,
                                'owasp_category': owasp_category
                            })
                        
                        if owasp_category == 'A02:2025-Security Misconfiguration' or any(pattern in rule.lower() or pattern in message.lower() for pattern in MISCONFIG_PATTERNS):
                            project_has_misconfigs = True
                            project_data['misconfigs_count'] += 1
                            
                            misconfig_issues.append({
                                'key': issue.get('key', ''),
                                'message': issue.get('message', 'Sem descrição'),
                                'component': issue.get('component', '').split(':')[-1] if ':' in issue.get('component', '') else issue.get('component', ''),
                                'line': issue.get('line', 0),
                                'severity': severity,
                                'risk_level': SEVERITY_RISK_MAPPING.get(severity, 'UNKNOWN'),
                                'type': issue_type,
                                'rule': rule,
                                'creationDate': creation_date,
                                'projectName': project_name,
                                'projectKey': project_key,
                                'branchName': branch_name,
                                'owasp_category': owasp_category
                            })
                        
                        dashboard_data['issues_details'].append({
                            'key': issue.get('key', ''),
                            'message': message,
                            'component': component,
                            'line': issue.get('line', 0),
                            'severity': severity,
                            'risk_level': SEVERITY_RISK_MAPPING.get(severity, 'UNKNOWN'),
                            'type': issue_type,
                            'rule': rule,
                            'tags': issue.get('tags', []),
                            'creationDate': creation_date,
                            'projectName': project_name,
                            'projectKey': project_key,
                            'project': project_name,
                            'branchName': branch_name,
                            'owasp_category': owasp_category
                        })
                    
                    branch_data = {
                        'name': branch_name,
                        'is_main': is_main,
                        'qg_status': qg_status,
                        'current_metrics': current_metrics,
                        'issues_by_type': dict(issues_by_type),
                        'issues_by_severity': dict(issues_by_severity),
                        'rules_count': dict(rules_count),
                        'blocker_issues': blocker_issues,
                        'secrets_issues': secrets_issues,
                        'misconfig_issues': misconfig_issues,
                        'owasp_metrics': dict(branch_owasp_metrics),
                        'total_issues': len(issues)
                    }
                    
                    project_data['branches'].append(branch_data)
                    
                except Exception as e:
                    print(f"    ✗ Erro ao processar branch {branch_name}: {e}")
                    print(f"    → Continuando com próxima branch...")
                    continue
            
            if project_coverage_count > 0:
                project_data['average_coverage'] = project_coverage_sum / project_coverage_count
                dashboard_data['projects_with_coverage'] += 1
            
            project_data['owasp_metrics'] = dict(project_owasp_metrics)
            governance_maturity = self.calculate_governance_maturity_score(project_owasp_metrics)
            project_data['governance_maturity'] = governance_maturity
            
            if project_has_secrets:
                project_data['has_secrets'] = True
                dashboard_data['projects_with_secrets'] += 1
            
            if project_has_misconfigs:
                project_data['has_misconfigs'] = True
                dashboard_data['projects_with_misconfigs'] += 1
            
            dashboard_data['owasp_metrics_by_project'][project_key] = {
                'project_name': project_name,
                'metrics': dict(project_owasp_metrics),
                'governance_maturity': governance_maturity
            }
            
            dashboard_data['projects'].append(project_data)
            
            main_status = project_data['main_qg_status']
            if main_status == 'OK':
                dashboard_data['projects_main_passed'] += 1
            elif main_status == 'ERROR':
                dashboard_data['projects_main_failed'] += 1
            else:
                dashboard_data['projects_main_none'] += 1
            
            branches_ok = len(project_data['branches'])
            branches_total = len(branches)
            if branches_ok < branches_total:
                print(f"  ⚠ {branches_ok}/{branches_total} branches processadas com sucesso")
            else:
                print(f"  ✓ {branches_ok} branch(es) principal(is) processada(s) com sucesso")
            
            if project_has_secrets:
                print(f"  🔐 ATENÇÃO: {project_data['secrets_count']} secrets encontrados!")
            
            if project_has_misconfigs:
                print(f"  ⚙️ ATENÇÃO: {project_data['misconfigs_count']} misconfigurations encontradas!")
            
            if project_data['average_coverage'] > 0:
                print(f"  📊 Coverage médio: {project_data['average_coverage']:.1f}%")
            
            print(f"  🏛️ Maturidade de Governança: {governance_maturity['level']} (Score: {governance_maturity['score']:.1f})")
        
        dashboard_data['governance_metrics'] = self.calculate_governance_maturity_score(
            dashboard_data['owasp_metrics_global']
        )
        
        dashboard_data['insights'] = self.generate_insights(dashboard_data)
        
        # Salvar snapshot histórico
        self.save_scan_snapshot(dashboard_data)
        
        print("\n" + "=" * 70)
        total_branches = sum(len(p['branches']) for p in dashboard_data['projects'])
        total_secrets = dashboard_data['projects_with_secrets']
        total_misconfigs = dashboard_data['projects_with_misconfigs']
        total_coverage = dashboard_data['projects_with_coverage']
        global_governance = dashboard_data['governance_metrics']
        
        print(f"✓ Coleta concluída:")
        print(f"  - {len(all_projects)} projetos/repositórios no total")
        print(f"  - {total_branches} branches principais coletadas")
        print(f"  - Branches monitoradas: {', '.join(MAIN_BRANCHES)}")
        print(f"  - Total esperado: {TOTAL_REPOSITORIES_EXPECTED} repositórios")
        
        print(f"\n🏛️ GOVERNANÇA GLOBAL:")
        print(f"  - Nível de Maturidade: {global_governance['level']}")
        print(f"  - Score de Governança: {global_governance['score']:.1f}/100")
        print(f"  - Issues Totais: {global_governance['total_issues']}")
        print(f"  - Categorias OWASP Afetadas: {global_governance['categories_affected']}/10")
        
        print(f"\n📊 MÉTRICAS CRÍTICAS:")
        print(f"  - Projetos com Coverage: {total_coverage}/{len(all_projects)} ({total_coverage/max(len(all_projects), 1)*100:.1f}%)")
        print(f"  - Projetos com Secrets: {total_secrets}/{len(all_projects)} ({total_secrets/max(len(all_projects), 1)*100:.1f}%)")
        print(f"  - Projetos com Misconfigurations: {total_misconfigs}/{len(all_projects)} ({total_misconfigs/max(len(all_projects), 1)*100:.1f}%)")
        
        if total_secrets > 0:
            print(f"\n🔐 CRÍTICO - VAZAMENTO DE SECRETS:")
            print(f"  - 🚨 {total_secrets} projeto(s) com secrets expostos!")
            print(f"  - 🚨 CORREÇÃO URGENTE NECESSÁRIA!")
        
        if total_misconfigs > 0:
            print(f"\n⚙️ CRÍTICO - CONFIGURAÇÕES INCORRETAS:")
            print(f"  - 🚨 {total_misconfigs} projeto(s) com configurações de segurança incorretas!")
            print(f"  - 🚨 REVISÃO E CORREÇÃO URGENTE NECESSÁRIA!")
        
        print("=" * 70)

        dashboard_data['owasp_metrics_global'] = dict(dashboard_data['owasp_metrics_global'])

        # Calcular métricas CWE 360º
        print("\n📊 Calculando métricas CWE 360º...")
        dashboard_data['cwe_metrics'] = self.calculate_cwe_metrics(dashboard_data)
        print(f"   ✓ {len(dashboard_data['cwe_metrics']['cwe_issues'])} issues CWE identificadas")
        print(f"   ✓ {dashboard_data['cwe_metrics']['cwe_top_25_coverage']}/25 CWEs Top 25 presentes")
        print("=" * 70)

        return dashboard_data

    def extract_cwe_from_rule(self, rule: str, message: str = "", tags: List[str] = None) -> Optional[str]:
        """Extrai o CWE ID de uma regra, mensagem ou tags"""
        import re

        # Primeiro, tentar extrair das tags (mais confiável)
        if tags:
            for tag in tags:
                cwe_match = re.search(r'cwe-?(\d+)', tag, re.IGNORECASE)
                if cwe_match:
                    return f"CWE-{cwe_match.group(1)}"

        # Depois tentar na mensagem e regra
        combined_text = f"{rule} {message}"
        cwe_match = re.search(r'CWE-?(\d+)', combined_text, re.IGNORECASE)
        if cwe_match:
            return f"CWE-{cwe_match.group(1)}"

        return None

    def map_owasp_to_cwe(self, owasp_category: str) -> str:
        """Mapeia categorias OWASP para CWEs representativos"""
        owasp_cwe_mapping = {
            'A01:2025-Broken Access Control': 'CWE-862',
            'A02:2025-Security Misconfiguration': 'CWE-295',
            'A03:2025-Software Supply Chain Failures': 'CWE-502',
            'A04:2025-Cryptographic Failures': 'CWE-798',
            'A05:2025-Injection': 'CWE-89',
            'A06:2025-Insecure Design': 'CWE-20',
            'A07:2025-Authentication Failures': 'CWE-287',
            'A08:2025-Software and Data Integrity Failures': 'CWE-502',
            'A09:2025-Logging & Alerting Failures': 'CWE-778',
            'A10:2025-Mishandling of Exception Conditions': 'CWE-755'
        }
        return owasp_cwe_mapping.get(owasp_category, None)

    def calculate_cwe_metrics(self, data: Dict) -> Dict:
        """Calcula métricas CWE 360º"""
        cwe_metrics = {
            'cwe_issues': [],
            'cwe_summary': defaultdict(int),
            'cwe_by_severity': defaultdict(lambda: defaultdict(int)),
            'cwe_by_project': defaultdict(lambda: defaultdict(int)),
            'cwe_by_criticality': defaultdict(lambda: defaultdict(int)),
            'cwe_by_stage': defaultdict(lambda: defaultdict(int)),
            'cwe_by_detection_source': defaultdict(lambda: defaultdict(int)),
            'cwe_top_25_coverage': 0,
            'cwe_top_25_present': [],
            'cwe_identity_weight': 0,
            'cwe_critical_systems_count': 0,
            'mttr_by_cwe': defaultdict(list),
            'backlog_by_cwe': defaultdict(lambda: {'0-30': 0, '31-60': 0, '61-90': 0, '90+': 0}),
            'domain_conformity': {}
        }

        # Simular dados de projeto com criticidade, BU, etc.
        # Em produção real, isso viria de uma fonte externa ou configuração
        business_critical_projects = ['projeto-financeiro', 'projeto-comercial', 'projeto-autenticacao']

        print("\n🔍 Iniciando análise CWE...")
        total_issues = len(data.get('issues_details', []))
        print(f"   Total de issues para análise: {total_issues}")

        for issue in data.get('issues_details', []):
            rule = issue.get('rule', '')
            message = issue.get('message', '')
            component = issue.get('component', '')
            severity = issue.get('severity', 'INFO')
            project = issue.get('project', 'unknown')
            project_name = issue.get('projectName', issue.get('project', 'Desconhecido'))
            creation_date_str = issue.get('creationDate', '')
            tags = issue.get('tags', [])

            # Extrair CWE (primeiro das tags/mensagens, depois mapeamento OWASP)
            cwe_id = self.extract_cwe_from_rule(rule, message, tags)

            # Se não encontrou CWE diretamente, mapear da categoria OWASP
            if not cwe_id:
                owasp_category = issue.get('owasp_category', '')
                cwe_id = self.map_owasp_to_cwe(owasp_category)

            if not cwe_id:
                continue

            # Determinar criticidade de negócio
            is_critical = any(critical_proj in project.lower() for critical_proj in business_critical_projects)
            business_criticality = 'Alta' if is_critical else 'Média'

            # Simular stage de detecção (em produção real, viria de metadados)
            stage_detected = 'Dev' if 'test' in component.lower() else 'QA' if 'staging' in component.lower() else 'Prod'

            # Simular fonte de detecção
            detection_source = 'SAST' if any(lang in rule.lower() for lang in ['java', 'python', 'javascript']) else 'DAST'

            # Calcular idade da issue
            try:
                creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                days_old = (datetime.now(creation_date.tzinfo) - creation_date).days
            except:
                days_old = 0

            # Classificar idade
            if days_old <= 30:
                age_bucket = '0-30'
            elif days_old <= 60:
                age_bucket = '31-60'
            elif days_old <= 90:
                age_bucket = '61-90'
            else:
                age_bucket = '90+'

            # Registrar issue CWE
            cwe_issue = {
                'cwe_id': cwe_id,
                'cwe_name': CWE_TOP_25_2025.get(cwe_id, {}).get('name', 'Unknown'),
                'cwe_rank': CWE_TOP_25_2025.get(cwe_id, {}).get('rank', None),
                'is_top_25': cwe_id in CWE_TOP_25_2025,
                'severity': severity,
                'project': project,
                'project_name': project_name,
                'business_criticality': business_criticality,
                'stage_detected': stage_detected,
                'detection_source': detection_source,
                'days_old': days_old,
                'age_bucket': age_bucket,
                'category': CWE_TOP_25_2025.get(cwe_id, {}).get('category', 'Other'),
                'identity_related': CWE_TOP_25_2025.get(cwe_id, {}).get('identity_related', False)
            }

            cwe_metrics['cwe_issues'].append(cwe_issue)
            cwe_metrics['cwe_summary'][cwe_id] += 1
            cwe_metrics['cwe_by_severity'][cwe_id][severity] += 1
            cwe_metrics['cwe_by_project'][project][cwe_id] += 1
            cwe_metrics['cwe_by_criticality'][business_criticality][cwe_id] += 1
            cwe_metrics['cwe_by_stage'][cwe_id][stage_detected] += 1
            cwe_metrics['cwe_by_detection_source'][detection_source][cwe_id] += 1
            cwe_metrics['backlog_by_cwe'][cwe_id][age_bucket] += 1

        # Calcular cobertura CWE Top 25
        top_25_present = set()
        for cwe_issue in cwe_metrics['cwe_issues']:
            if cwe_issue['is_top_25']:
                top_25_present.add(cwe_issue['cwe_id'])

        cwe_metrics['cwe_top_25_present'] = sorted(list(top_25_present))
        cwe_metrics['cwe_top_25_coverage'] = len(top_25_present)

        # Calcular peso de identidade
        total_top_25_issues = sum(1 for issue in cwe_metrics['cwe_issues'] if issue['is_top_25'])
        identity_issues = sum(1 for issue in cwe_metrics['cwe_issues'] if issue['is_top_25'] and issue['identity_related'])
        cwe_metrics['cwe_identity_weight'] = (identity_issues / max(total_top_25_issues, 1)) * 100

        # Calcular issues em sistemas críticos
        cwe_metrics['cwe_critical_systems_count'] = sum(
            1 for issue in cwe_metrics['cwe_issues']
            if issue['is_top_25'] and issue['business_criticality'] == 'Alta'
        )

        # Calcular MTTR simulado (em produção real, viria de datas de resolução)
        for cwe_id in cwe_metrics['cwe_summary'].keys():
            if cwe_id in CWE_TOP_25_2025:
                # Simular MTTR (em dias) - em produção, calcular da data de resolução
                simulated_mttr = 30 + (CWE_TOP_25_2025[cwe_id]['rank'] * 2)
                cwe_metrics['mttr_by_cwe'][cwe_id] = simulated_mttr

        # Calcular conformidade por domínio
        for domain, cwe_list in CWE_DOMAIN_MAPPING.items():
            domain_issues = sum(cwe_metrics['cwe_summary'].get(cwe_id, 0) for cwe_id in cwe_list)
            total_possible = len(cwe_list) * 10  # Assumir 10 issues como baseline
            conformity = max(0, 100 - (domain_issues / total_possible) * 100)
            cwe_metrics['domain_conformity'][domain] = conformity

        # Converter defaultdicts para dicts regulares
        cwe_metrics['cwe_summary'] = dict(cwe_metrics['cwe_summary'])
        cwe_metrics['cwe_by_severity'] = {k: dict(v) for k, v in cwe_metrics['cwe_by_severity'].items()}
        cwe_metrics['cwe_by_project'] = {k: dict(v) for k, v in cwe_metrics['cwe_by_project'].items()}
        cwe_metrics['cwe_by_criticality'] = {k: dict(v) for k, v in cwe_metrics['cwe_by_criticality'].items()}
        cwe_metrics['cwe_by_stage'] = {k: dict(v) for k, v in cwe_metrics['cwe_by_stage'].items()}
        cwe_metrics['cwe_by_detection_source'] = {k: dict(v) for k, v in cwe_metrics['cwe_by_detection_source'].items()}
        cwe_metrics['backlog_by_cwe'] = {k: dict(v) for k, v in cwe_metrics['backlog_by_cwe'].items()}
        cwe_metrics['mttr_by_cwe'] = dict(cwe_metrics['mttr_by_cwe'])

        # Logs de debug
        print(f"   ✓ Issues CWE encontradas: {len(cwe_metrics['cwe_issues'])}")
        print(f"   ✓ CWEs únicos: {len(cwe_metrics['cwe_summary'])}")
        print(f"   ✓ CWEs Top 25 presentes: {cwe_metrics['cwe_top_25_coverage']}/25")
        if cwe_metrics['cwe_top_25_present']:
            print(f"   ✓ CWEs Top 25 identificados: {', '.join(cwe_metrics['cwe_top_25_present'][:5])}{'...' if len(cwe_metrics['cwe_top_25_present']) > 5 else ''}")

        return cwe_metrics

    def generate_dashboard_html(self, data: Dict) -> str:
        collection_date = datetime.fromisoformat(data['collection_date']).strftime('%d/%m/%Y %H:%M:%S')
        sonar_url = data.get('sonar_url', '#')
        
        # Carrega histórico de scans - apenas arquivos scan_*.json
        scan_history = self.get_scan_history()
        data['scan_history'] = scan_history
        
        data_json = json.dumps(data, ensure_ascii=False, default=str)
        
        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Executivo - SonarQube OWASP Intelligence</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@3.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        :root {{
            --primary-color: #667eea;
            --secondary-color: #764ba2;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
            --dark-color: #343a40;
            --light-color: #f8f9fa;
            --border-radius: 12px;
            --box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            --transition: all 0.3s ease;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        
        .dashboard-container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
            backdrop-filter: blur(5px);
        }}
        
        .modal-content {{
            background-color: white;
            margin: 2% auto;
            padding: 30px;
            border-radius: var(--border-radius);
            width: 95%;
            max-width: 1200px;
            max-height: 90vh;
            overflow-y: auto;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            position: relative;
        }}
        
        .modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--light-color);
        }}
        
        .modal-title {{
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--dark-color);
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .modal-close {{
            background: none;
            border: none;
            font-size: 2rem;
            cursor: pointer;
            color: #999;
            transition: var(--transition);
        }}
        
        .modal-close:hover {{
            color: var(--danger-color);
            transform: scale(1.1);
        }}
        
        .modal-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, var(--light-color) 0%, #e3f2fd 100%);
            border-radius: var(--border-radius);
        }}
        
        .modal-stat {{
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        
        .modal-stat-value {{
            font-size: 2rem;
            font-weight: 900;
            margin-bottom: 5px;
        }}
        
        .modal-stat-label {{
            font-size: 0.9rem;
            color: #666;
            font-weight: 600;
        }}
        
        .issues-list {{
            display: grid;
            gap: 20px;
        }}
        
        .issue-item {{
            background: linear-gradient(135deg, #fff 0%, #f8f9fa 100%);
            border-left: 5px solid;
            padding: 20px;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            transition: var(--transition);
        }}
        
        .issue-item:hover {{
            transform: translateY(-3px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.15);
        }}
        
        .issue-item.critical {{ border-left-color: #8B0000; }}
        .issue-item.high {{ border-left-color: #DC3545; }}
        .issue-item.medium {{ border-left-color: #FF9800; }}
        .issue-item.low {{ border-left-color: #FFC107; }}
        
        .issue-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }}
        
        .issue-title {{
            font-size: 1.1rem;
            font-weight: 700;
            color: var(--dark-color);
            flex: 1;
            margin-right: 15px;
        }}
        
        .issue-badges {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        
        .issue-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .issue-badge.severity-critical {{ background: #8B0000; color: white; }}
        .issue-badge.severity-major {{ background: #DC3545; color: white; }}
        .issue-badge.severity-minor {{ background: #FF9800; color: white; }}
        .issue-badge.severity-info {{ background: #FFC107; color: #333; }}
        .issue-badge.severity-blocker {{ background: #000000; color: white; }}
        
        .issue-details {{
            margin-bottom: 15px;
            color: #555;
            line-height: 1.6;
        }}
        
        .issue-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
            font-size: 0.9rem;
            color: #666;
        }}
        
        .issue-meta-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .issue-actions {{
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }}
        
        .issue-link {{
            background: var(--primary-color);
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            text-decoration: none;
            font-weight: 600;
            transition: var(--transition);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        
        .issue-link:hover {{
            background: var(--secondary-color);
            transform: translateY(-2px);
            color: white;
        }}
        
        .issue-link.danger {{
            background: var(--danger-color);
        }}
        
        .issue-link.danger:hover {{
            background: #c82333;
        }}
        
        .project-group {{
            margin-bottom: 30px;
            background: white;
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--box-shadow);
        }}
        
        .project-group-header {{
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .project-group-title {{
            font-size: 1.3rem;
            font-weight: 700;
        }}
        
        .project-group-count {{
            background: rgba(255,255,255,0.2);
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
        }}
        
        .project-group-content {{
            padding: 25px;
        }}
        
        .highlight-secrets {{
            border: 3px solid #FF9800;
            background: linear-gradient(135deg, #fff8e1 0%, #ffecb3 100%);
        }}
        
        .highlight-misconfig {{
            border: 3px solid #DC3545;
            background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
        }}
        
        .highlight-indicator {{
            position: absolute;
            top: 10px;
            right: 10px;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        
        .highlight-indicator.secrets {{
            background: #FF9800;
            color: white;
        }}
        
        .highlight-indicator.misconfig {{
            background: #DC3545;
            color: white;
        }}
        
        .coverage-indicator {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        
        .coverage-indicator.good {{
            background: rgba(40, 167, 69, 0.1);
            color: var(--success-color);
        }}
        
        .coverage-indicator.medium {{
            background: rgba(255, 193, 7, 0.1);
            color: #856404;
        }}
        
        .coverage-indicator.poor {{
            background: rgba(220, 53, 69, 0.1);
            color: var(--danger-color);
        }}
        
        .coverage-indicator.none {{
            background: rgba(108, 117, 125, 0.1);
            color: #6c757d;
        }}
        
        .header {{
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 30px;
            border-radius: var(--border-radius);
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 15px;
        }}
        
        .header .meta-info {{
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
            font-size: 0.95rem;
            opacity: 0.8;
        }}
        
        .nav-tabs {{
            background: white;
            border-radius: var(--border-radius);
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }}
        
        .tab-buttons {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }}
        
        .tab-btn {{
            background: var(--light-color);
            border: 2px solid transparent;
            padding: 12px 24px;
            border-radius: var(--border-radius);
            cursor: pointer;
            transition: var(--transition);
            font-weight: 600;
            color: var(--dark-color);
        }}
        
        .tab-btn.active {{
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }}
        
        .tab-btn:hover {{
            background: var(--primary-color);
            color: white;
            transform: translateY(-2px);
        }}
        
        .project-filter {{
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }}
        
        .project-filter select {{
            padding: 10px 15px;
            border: 2px solid #e0e0e0;
            border-radius: var(--border-radius);
            font-size: 1rem;
            background: white;
            min-width: 200px;
        }}
        
        .project-filter select:focus {{
            outline: none;
            border-color: var(--primary-color);
        }}
        
        .clear-filter-btn {{
            background: var(--danger-color);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: var(--border-radius);
            cursor: pointer;
            transition: var(--transition);
        }}
        
        .clear-filter-btn:hover {{
            background: #c82333;
            transform: translateY(-2px);
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .grid {{
            display: grid;
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .grid-2 {{ grid-template-columns: 1fr 1fr; }}
        .grid-3 {{ grid-template-columns: repeat(3, 1fr); }}
        .grid-4 {{ grid-template-columns: repeat(4, 1fr); }}
        .grid-5 {{ grid-template-columns: repeat(5, 1fr); }}
        .grid-auto {{ grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }}
        
        @media (max-width: 768px) {{
            .grid-2, .grid-3, .grid-4, .grid-5 {{ grid-template-columns: 1fr; }}
        }}
        
        .card {{
            background: white;
            border-radius: var(--border-radius);
            padding: 25px;
            box-shadow: var(--box-shadow);
            transition: var(--transition);
            border-left: 4px solid transparent;
            cursor: default;
            position: relative;
        }}
        
        .card.clickable {{
            cursor: pointer;
        }}
        
        .card.clickable:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }}
        
        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.12);
        }}
        
        .card.success {{ border-left-color: var(--success-color); }}
        .card.warning {{ border-left-color: var(--warning-color); }}
        .card.danger {{ border-left-color: var(--danger-color); }}
        .card.info {{ border-left-color: var(--info-color); }}
        
        .card-header {{
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid var(--light-color);
        }}
        
        .card-title {{
            font-size: 1.4rem;
            font-weight: 700;
            color: var(--dark-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .card-icon {{
            font-size: 1.2rem;
        }}
        
        .metric-card {{
            text-align: center;
            padding: 30px 20px;
        }}
        
        .metric-value {{
            font-size: 3rem;
            font-weight: 900;
            margin-bottom: 10px;
            display: block;
        }}
        
        .metric-label {{
            font-size: 1rem;
            color: #666;
            margin-bottom: 8px;
        }}
        
        .metric-change {{
            font-size: 0.9rem;
            font-weight: 600;
            padding: 4px 12px;
            border-radius: 20px;
        }}
        
        .metric-change.positive {{
            background: rgba(40, 167, 69, 0.1);
            color: var(--success-color);
        }}
        
        .metric-change.negative {{
            background: rgba(220, 53, 69, 0.1);
            color: var(--danger-color);
        }}
        
        .chart-container {{
            position: relative;
            height: 400px;
            margin-top: 20px;
        }}
        
        .chart-container.small {{ height: 300px; }}
        .chart-container.large {{ height: 500px; }}
        .chart-container.clickable {{ cursor: pointer; }}
        
        .insights-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
        }}
        
        .insight-card {{
            background: linear-gradient(135deg, white 0%, #f8f9fa 100%);
            border-radius: var(--border-radius);
            padding: 25px;
            box-shadow: var(--box-shadow);
            border-left: 5px solid;
        }}
        
        .insight-card.critical {{ border-left-color: #dc3545; }}
        .insight-card.high {{ border-left-color: #fd7e14; }}
        .insight-card.medium {{ border-left-color: #ffc107; }}
        .insight-card.low {{ border-left-color: #20c997; }}
        .insight-card.info {{ border-left-color: #6f42c1; }}
        
        .insight-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
        }}
        
        .insight-title {{
            font-size: 1.2rem;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        
        .insight-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .insight-badge.critical {{
            background: #dc3545;
            color: white;
        }}
        
        .insight-badge.high {{
            background: #fd7e14;
            color: white;
        }}
        
        .insight-badge.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .insight-description {{
            color: #555;
            margin-bottom: 15px;
            line-height: 1.6;
        }}
        
        .insight-actions {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        
        .insight-action {{
            background: rgba(102, 126, 234, 0.1);
            color: var(--primary-color);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-decoration: none;
            transition: var(--transition);
        }}
        
        .insight-action:hover {{
            background: var(--primary-color);
            color: white;
            transform: translateY(-2px);
        }}
        
        .project-detail {{
            background: white;
            border-radius: var(--border-radius);
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
            overflow: hidden;
        }}
        
        .project-detail-header {{
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 25px;
        }}
        
        .project-detail-title {{
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 10px;
        }}
        
        .project-detail-meta {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 0.9rem;
            opacity: 0.9;
        }}
        
        .project-detail-content {{
            padding: 30px;
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--box-shadow);
        }}
        
        .data-table th {{
            background: var(--primary-color);
            color: white;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 0.95rem;
        }}
        
        .data-table td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
            vertical-align: top;
        }}
        
        .data-table tr:hover {{
            background: #f8f9fa;
        }}
        
        .data-table tr:last-child td {{
            border-bottom: none;
        }}
        
        .status-badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        
        .status-badge.success {{
            background: rgba(40, 167, 69, 0.1);
            color: var(--success-color);
        }}
        
        .status-badge.danger {{
            background: rgba(220, 53, 69, 0.1);
            color: var(--danger-color);
        }}
        
        .status-badge.warning {{
            background: rgba(255, 193, 7, 0.1);
            color: #856404;
        }}
        
        .status-badge.info {{
            background: rgba(23, 162, 184, 0.1);
            color: var(--info-color);
        }}
        
        .progress-bar {{
            background: #e9ecef;
            border-radius: 10px;
            height: 8px;
            overflow: hidden;
            margin: 8px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            border-radius: 10px;
            transition: width 0.6s ease;
        }}
        
        .progress-fill.success {{ background: var(--success-color); }}
        .progress-fill.warning {{ background: var(--warning-color); }}
        .progress-fill.danger {{ background: var(--danger-color); }}
        .progress-fill.info {{ background: var(--info-color); }}
        
        .owasp-category {{
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 600;
            color: white;
            display: inline-block;
            margin: 2px;
        }}
        
        .risk-critical {{ background: #8B0000; color: white; }}
        .risk-high {{ background: #DC3545; color: white; }}
        .risk-medium {{ background: #FF9800; color: white; }}
        .risk-low {{ background: #FFC107; color: #333; }}
        .risk-safe {{ background: #28A745; color: white; }}
        
        .maturity-initial {{ background: #dc3545; color: white; }}
        .maturity-developing {{ background: #fd7e14; color: white; }}
        .maturity-defined {{ background: #ffc107; color: #333; }}
        .maturity-managed {{ background: #28a745; color: white; }}
        .maturity-optimized {{ background: #20c997; color: white; }}
        
        .loading {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}
        
        .loading i {{
            font-size: 3rem;
            margin-bottom: 20px;
            animation: spin 1s linear infinite;
        }}
        
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            color: #999;
            font-style: italic;
        }}
        
        .empty-state i {{
            font-size: 4rem;
            margin-bottom: 20px;
            color: #ddd;
        }}
        
        .text-center {{ text-align: center; }}
        .text-left {{ text-align: left; }}
        .text-right {{ text-align: right; }}
        .font-bold {{ font-weight: 700; }}
        .font-medium {{ font-weight: 500; }}
        .text-success {{ color: var(--success-color); }}
        .text-danger {{ color: var(--danger-color); }}
        .text-warning {{ color: var(--warning-color); }}
        .text-info {{ color: var(--info-color); }}
        .text-muted {{ color: #6c757d; }}
        
        .mb-0 {{ margin-bottom: 0; }}
        .mb-1 {{ margin-bottom: 8px; }}
        .mb-2 {{ margin-bottom: 16px; }}
        .mb-3 {{ margin-bottom: 24px; }}
        .mb-4 {{ margin-bottom: 32px; }}
        
        .mt-0 {{ margin-top: 0; }}
        .mt-1 {{ margin-top: 8px; }}
        .mt-2 {{ margin-top: 16px; }}
        .mt-3 {{ margin-top: 24px; }}
        .mt-4 {{ margin-top: 32px; }}
        
        @media (max-width: 768px) {{
            .dashboard-container {{
                padding: 10px;
            }}
            
            .header {{
                padding: 20px;
                text-align: center;
            }}
            
            .header h1 {{
                font-size: 2rem;
            }}
            
            .header .meta-info {{
                flex-direction: column;
                gap: 10px;
            }}
            
            .tab-buttons {{
                flex-direction: column;
            }}
            
            .project-filter {{
                flex-direction: column;
                align-items: stretch;
            }}
            
            .project-filter select {{
                min-width: auto;
            }}
            
            .metric-value {{
                font-size: 2.5rem;
            }}
            
            .insights-grid {{
                grid-template-columns: 1fr;
            }}
            
            .modal-content {{
                width: 98%;
                margin: 5% auto;
                padding: 20px;
            }}
            
            .modal-stats {{
                grid-template-columns: 1fr;
            }}
        }}
        
        .fade-in {{
            animation: fadeIn 0.5s ease-in;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .pulse {{
            animation: pulse 2s infinite;
        }}
        
        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}
        
        .critical-alert {{
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
            border: 3px solid #dc3545;
            animation: criticalPulse 2s infinite;
        }}
        
        @keyframes criticalPulse {{
            0%, 100% {{ box-shadow: 0 0 5px rgba(220, 53, 69, 0.5); }}
            50% {{ box-shadow: 0 0 20px rgba(220, 53, 69, 0.8); }}
        }}
        
        .critical-alert .card-title {{
            color: white;
        }}
        
        .critical-alert .metric-value {{
            color: #FFD700 !important;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .critical-alert .metric-label {{
            color: white;
        }}
        
        .critical-alert .metric-change {{
            background: rgba(255,215,0,0.2);
            color: #FFD700;
        }}
        
        ::-webkit-scrollbar {{
            width: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: #f1f1f1;
            border-radius: 10px;
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: var(--primary-color);
            border-radius: 10px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--secondary-color);
        }}
    </style>
</head>
<body>
    <div id="categoryModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title" id="modalTitle">Detalhes da Categoria</h3>
                <button class="modal-close" onclick="closeCategoryModal()">&times;</button>
            </div>
            <div id="categoryModalContent">
            </div>
        </div>
    </div>

    <div class="dashboard-container">
        <header class="header">
            <h1><i class="fas fa-shield-alt"></i> Dashboard Executivo - Intelligence SonarQube</h1>
            <div class="subtitle">Governança OWASP Top 10 2025 | Análise de Risco Avançada | Branches Principais</div>
            <div class="meta-info">
                <span><i class="fas fa-calendar-alt"></i> Atualizado: {collection_date}</span>
                <span><i class="fas fa-database"></i> Repositórios: {data.get('total_projects', 0)}/{data.get('total_repositories_expected', 209)}</span>
                <span><i class="fas fa-code-branch"></i> Branches: {', '.join(data.get('main_branches_filter', []))}</span>
                <span><i class="fas fa-shield-alt"></i> OWASP 2025 Compliant</span>
            </div>
        </header>
        
        <section class="nav-tabs">
            <div class="tab-buttons">
                <button class="tab-btn active" onclick="switchTab('overview')">
                    <i class="fas fa-tachometer-alt"></i> Overview Executivo
                </button>
                <button class="tab-btn" onclick="switchTab('insights')">
                    <i class="fas fa-brain"></i> Intelligence & Insights
                </button>
                <button class="tab-btn" onclick="switchTab('owasp')">
                    <i class="fas fa-shield-alt"></i> OWASP Analysis
                </button>
                <button class="tab-btn" onclick="switchTab('risks')">
                    <i class="fas fa-exclamation-triangle"></i> Risk Management
                </button>
                <button class="tab-btn" onclick="switchTab('projects')">
                    <i class="fas fa-project-diagram"></i> Project Details
                </button>
                <button class="tab-btn" onclick="switchTab('aggregate')">
                    <i class="fas fa-chart-line"></i> Aggregate Report
                </button>
                <button class="tab-btn" onclick="switchTab('cwe')">
                    <i class="fas fa-bug"></i> CWE Command Center
                </button>
            </div>

            <div class="project-filter">
                <label for="projectSelector"><i class="fas fa-filter"></i> <strong>Filtro Inteligente por Projeto:</strong></label>
                <select id="projectSelector" onchange="selectProject()">
                    <option value="">🌐 Visão Global - Todos os Projetos</option>
                </select>
                <button class="clear-filter-btn" onclick="clearProjectFilter()">
                    <i class="fas fa-times"></i> Limpar Filtro
                </button>
            </div>
        </section>
        
        <div id="overview-tab" class="tab-content active">
            <div class="grid grid-5">
                <div class="card metric-card success">
                    <span class="metric-value text-success" id="totalProjects">0</span>
                    <div class="metric-label">Projetos Monitorados</div>
                    <div class="metric-change" id="projectsCompletionChange">0% da meta</div>
                </div>
                
                <div class="card metric-card" id="coverageCard">
                    <span class="metric-value text-info" id="projectsWithCoverage">0</span>
                    <div class="metric-label">Projetos com Coverage</div>
                    <div class="metric-change" id="coveragePercentage">0%</div>
                </div>
                
                <div class="card metric-card danger" id="secretsCard">
                    <span class="metric-value text-danger" id="projectsWithSecrets">0</span>
                    <div class="metric-label">Projetos com Secrets</div>
                    <div class="metric-change negative" id="secretsPercentage">CRÍTICO</div>
                </div>
                
                <div class="card metric-card danger" id="misconfigsCard">
                    <span class="metric-value text-danger" id="projectsWithMisconfigs">0</span>
                    <div class="metric-label">Projetos com Misconfigs</div>
                    <div class="metric-change negative" id="misconfigsPercentage">CRÍTICO</div>
                </div>
                
                <div class="card metric-card info">
                    <span class="metric-value text-info" id="governanceScore">0</span>
                    <div class="metric-label">Score de Governança</div>
                    <div class="metric-change" id="governanceLevel">Inicial</div>
                </div>
            </div>
            
            <div class="grid grid-2">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-pie card-icon"></i>
                            Distribuição de Maturidade de Governança
                        </h3>
                    </div>
                    <div class="chart-container small">
                        <canvas id="maturityDistributionChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-check-circle card-icon"></i>
                            Status Quality Gate
                        </h3>
                    </div>
                    <div class="chart-container small">
                        <canvas id="qualityGateChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-shield-alt card-icon"></i>
                            Top 5 Categorias OWASP 2025
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="owaspTop5Chart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-scatter card-icon"></i>
                            Coverage vs Issues por Projeto
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="coverageVsIssuesChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="insights-tab" class="tab-content">
            <div class="insights-grid" id="insightsContainer">
            </div>
            
            <div class="grid grid-4 mt-4">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-line card-icon"></i>
                            Benchmark: Score de Governança
                        </h3>
                    </div>
                    <div id="benchmarkGovernance"></div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-key card-icon"></i>
                            Benchmark: Exposição de Secrets
                        </h3>
                    </div>
                    <div id="benchmarkSecrets"></div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-check-double card-icon"></i>
                            Benchmark: Quality Gate
                        </h3>
                    </div>
                    <div id="benchmarkQualityGate"></div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-vial card-icon"></i>
                            Benchmark: Coverage de Testes
                        </h3>
                    </div>
                    <div id="benchmarkCoverage"></div>
                </div>
            </div>
        </div>
        
        <div id="owasp-tab" class="tab-content">
            <div class="grid grid-auto" id="owaspCategoriesGrid">
            </div>
            
            <div class="grid grid-2 mt-4">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-bar card-icon"></i>
                            Issues por Categoria OWASP
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="owaspCategoriesChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-balance-scale card-icon"></i>
                            Comparação OWASP por Projeto
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="owaspProjectComparisonChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="risks-tab" class="tab-content">
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-exclamation-circle card-icon"></i>
                        Top 10 Projetos por Risco
                    </h3>
                </div>
                <div id="topRiskProjectsTable"></div>
            </div>
            
            <div class="grid grid-2">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-shield-alt card-icon"></i>
                            Issues por Categoria OWASP
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="issuesOwaspChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-code-branch card-icon"></i>
                            Distribuição por Branches Principais
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="branchDistributionChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="projects-tab" class="tab-content">
            <div id="projectDetailSection" class="project-detail" style="display: none;">
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-table card-icon"></i>
                        Resumo de Todos os Projetos
                    </h3>
                </div>
                <div id="projectsTableContainer"></div>
            </div>
        </div>
        
        <div id="aggregate-tab" class="tab-content">
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-chart-line card-icon"></i>
                        Aggregate Report - Análise Temporal OWASP Top 10 2025
                    </h3>
                </div>
                
                <div id="aggregateContent">
                    <div id="aggregatePlaceholder" style="padding: 40px; text-align: center;">
                        <i class="fas fa-database" style="font-size: 5rem; color: #667eea; margin-bottom: 20px; opacity: 0.6;"></i>
                        <h2 style="color: #343a40; margin-bottom: 20px;">Carregando Dados Históricos</h2>
                        <p style="color: #666; font-size: 1.1rem; max-width: 700px; margin: 0 auto;">
                            Processando arquivos <strong style="color: #667eea;">scan_*.json</strong> do diretório de histórico...
                        </p>
                    </div>
                    
                    <div id="aggregateCharts" style="display: none;">
                        <!-- Cards de Métricas -->
                        <div class="grid grid-4 mb-4">
                            <div class="card info">
                                <div class="metric-value text-info" id="aggTotalScans">0</div>
                                <div class="metric-label">Total de Scans</div>
                            </div>
                            <div class="card" id="aggIssuesCard">
                                <div class="metric-value" id="aggTotalIssues">0</div>
                                <div class="metric-label">Total de Issues OWASP</div>
                            </div>
                            <div class="card info">
                                <div class="metric-value text-info" id="aggPeriod">-</div>
                                <div class="metric-label">Período Analisado</div>
                            </div>
                            <div class="card" id="aggTrendCard">
                                <div class="metric-value" id="aggTrend">-</div>
                                <div class="metric-label">Tendência</div>
                            </div>
                        </div>
                        
                        <!-- Gráfico Principal -->
                        <div class="card mb-4">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-chart-area card-icon"></i>
                                    Evolução Temporal de Issues OWASP
                                </h3>
                            </div>
                            <div class="chart-container" style="height: 400px;">
                                <canvas id="aggMainTimelineChart"></canvas>
                            </div>
                        </div>
                        
                        <!-- Grid de Gráficos -->
                        <div class="grid grid-2 mb-4">
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="card-title">
                                        <i class="fas fa-shield-alt card-icon"></i>
                                        Top 10 Categorias OWASP
                                    </h3>
                                </div>
                                <div class="chart-container">
                                    <canvas id="aggOwaspBarChart"></canvas>
                                </div>
                            </div>
                            
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="card-title">
                                        <i class="fas fa-key card-icon"></i>
                                        Secrets & Misconfigurations
                                    </h3>
                                </div>
                                <div class="chart-container">
                                    <canvas id="aggSecretsLineChart"></canvas>
                                </div>
                            </div>
                        </div>
                        
                        <div class="grid grid-2 mb-4">
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="card-title">
                                        <i class="fas fa-exclamation-triangle card-icon"></i>
                                        Distribuição por Severidade (Último Scan)
                                    </h3>
                                </div>
                                <div class="chart-container">
                                    <canvas id="aggSeverityPieChart"></canvas>
                                </div>
                            </div>
                            
                            <div class="card">
                                <div class="card-header">
                                    <h3 class="card-title">
                                        <i class="fas fa-chart-bar card-icon"></i>
                                        Score de Governança
                                    </h3>
                                </div>
                                <div class="chart-container">
                                    <canvas id="aggGovernanceChart"></canvas>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Insights -->
                        <div class="card">
                            <div class="card-header">
                                <h3 class="card-title">
                                    <i class="fas fa-lightbulb card-icon"></i>
                                    Insights e Recomendações
                                </h3>
                            </div>
                            <div id="aggInsightsContainer" class="insights-grid" style="padding: 20px;">
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- CWE Strategic Command Center Tab -->
        <div id="cwe-tab" class="tab-content">
            <!-- Bloco 1: Visão Executiva CWE -->
            <div class="card mb-4">
                <div class="card-header">
                    <h2 class="card-title" style="font-size: 1.5rem;">
                        <i class="fas fa-bug"></i> CWE Strategic Command Center
                    </h2>
                    <p style="margin: 10px 0 0 0; color: #666;">Dashboard 360º focado em CWE Top 25 2025</p>
                </div>
            </div>

            <!-- KPIs Executivos -->
            <div class="grid grid-5 mb-4">
                <div class="card metric-card">
                    <span class="metric-value text-info" id="cweTop25Coverage">0/25</span>
                    <div class="metric-label">Cobertura CWE Top 25</div>
                    <div class="metric-change" id="cweTop25CoverageDesc">CWEs presentes</div>
                </div>

                <div class="card metric-card danger">
                    <span class="metric-value text-danger" id="cweCriticalSystemsCount">0</span>
                    <div class="metric-label">Issues em Sistemas Críticos</div>
                    <div class="metric-change negative">Alta prioridade</div>
                </div>

                <div class="card metric-card success">
                    <span class="metric-value text-success" id="cweResolvedPercent">0%</span>
                    <div class="metric-label">% Issues Resolvidas</div>
                    <div class="metric-change">Top 25</div>
                </div>

                <div class="card metric-card warning">
                    <span class="metric-value text-warning" id="cweMTTR">0</span>
                    <div class="metric-label">MTTR Médio (dias)</div>
                    <div class="metric-change">Critical/Blocker</div>
                </div>

                <div class="card metric-card info">
                    <span class="metric-value text-info" id="cweIdentityWeight">0%</span>
                    <div class="metric-label">Peso de Identidade</div>
                    <div class="metric-change">Auth/AuthZ</div>
                </div>
            </div>

            <!-- Gráfico 1: Distribuição de CWE Top 25 por Severidade -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-chart-bar card-icon"></i>
                        Gráfico 1: Distribuição de CWE Top 25 por Severidade
                    </h3>
                </div>
                <div class="chart-container">
                    <canvas id="cweBySeverityChart"></canvas>
                </div>
            </div>

            <!-- Bloco 2: Risco & Negócio -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title" style="font-size: 1.3rem;">
                        <i class="fas fa-exclamation-triangle"></i> Bloco 2: Risco & Negócio
                    </h3>
                </div>
            </div>

            <div class="grid grid-2 mb-4">
                <!-- Gráfico 2: Top 10 CWEs por nº de Vulnerabilidades -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-list-ol card-icon"></i>
                            Gráfico 2: Top 10 CWEs por Vulnerabilidades
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="cweTop10Chart"></canvas>
                    </div>
                </div>

                <!-- Gráfico 3: Heatmap CWE x Sistemas Críticos -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-fire card-icon"></i>
                            Gráfico 3: Heatmap CWE x Sistemas Críticos
                        </h3>
                    </div>
                    <div id="cweHeatmapContainer" style="padding: 20px; max-height: 400px; overflow-y: auto;">
                        <table id="cweHeatmapTable" class="data-table" style="font-size: 0.85rem;"></table>
                    </div>
                </div>
            </div>

            <!-- Gráfico 4: CWEs Impactando Sistemas Críticos -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-server card-icon"></i>
                        Gráfico 4: CWEs Impactando Sistemas Críticos
                    </h3>
                </div>
                <div class="chart-container">
                    <canvas id="cweCriticalSystemsChart"></canvas>
                </div>
            </div>

            <!-- KPI Concentração de Risco -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-bullseye card-icon"></i>
                        KPI: Concentração de Risco CWE
                    </h3>
                </div>
                <div style="padding: 20px;" id="cweRiskConcentration">
                </div>
            </div>

            <!-- Bloco 3: Governança & Efetividade -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title" style="font-size: 1.3rem;">
                        <i class="fas fa-balance-scale"></i> Bloco 3: Governança & Efetividade
                    </h3>
                </div>
            </div>

            <div class="grid grid-2 mb-4">
                <!-- Gráfico 5: MTTR por CWE Top 25 -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-clock card-icon"></i>
                            Gráfico 5: MTTR por CWE Top 25
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="cweMTTRChart"></canvas>
                    </div>
                </div>

                <!-- Gráfico 6: Backlog Envelhecido por CWE -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-hourglass-half card-icon"></i>
                            Gráfico 6: Backlog Envelhecido por CWE
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="cweBacklogChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Tabela: CWEs com maior nº de issues vencendo SLA -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-table card-icon"></i>
                        Tabela: CWEs com Issues Vencendo SLA
                    </h3>
                </div>
                <div id="cweSLATableContainer" style="padding: 20px;">
                    <table id="cweSLATable" class="data-table"></table>
                </div>
            </div>

            <!-- Gráfico 7: Conformidade de Controles por Família CWE -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-check-square card-icon"></i>
                        Gráfico 7: Conformidade de Controles por Domínio CWE
                    </h3>
                </div>
                <div class="chart-container">
                    <canvas id="cweDomainConformityChart"></canvas>
                </div>
            </div>

            <!-- Bloco 4: DevSecOps, IAM, Supply Chain & Cultura -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title" style="font-size: 1.3rem;">
                        <i class="fas fa-code-branch"></i> Bloco 4: DevSecOps, IAM, Supply Chain & Cultura
                    </h3>
                </div>
            </div>

            <div class="grid grid-2 mb-4">
                <!-- Gráfico 8: Stage de Detecção por CWE Top 25 -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-layer-group card-icon"></i>
                            Gráfico 8: Stage de Detecção por CWE
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="cweStageChart"></canvas>
                    </div>
                </div>

                <!-- Gráfico 9: Ferramenta de Detecção por CWE -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-tools card-icon"></i>
                            Gráfico 9: Ferramenta de Detecção por CWE
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="cweDetectionSourceChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Gráfico 10: CWEs de Identidade x Controles IAM -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-user-shield card-icon"></i>
                        Gráfico 10: CWEs de Identidade x Sistemas
                    </h3>
                </div>
                <div class="chart-container">
                    <canvas id="cweIdentityChart"></canvas>
                </div>
            </div>

            <div class="grid grid-2 mb-4">
                <!-- Gráfico 11: Origem do CWE (Código Próprio vs Terceiros) -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-code card-icon"></i>
                            Gráfico 11: Origem do CWE
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="cweOriginChart"></canvas>
                    </div>
                </div>

                <!-- Gráfico 12: CWEs por Time x Treinamento -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-users card-icon"></i>
                            Gráfico 12: CWEs por Time x Treinamento
                        </h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="cweTeamTrainingChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Painel de OKRs Estratégicos -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-bullseye card-icon"></i>
                        Painel de OKRs Estratégicos CWE
                    </h3>
                </div>
                <div id="cweOKRsContainer" style="padding: 20px;">
                </div>
            </div>
        </div>
    </div>

    <script>
        const dashboardData = {data_json};
        const sonarUrl = "{sonar_url}";
        let charts = {{}};
        let currentTab = 'overview';
        let selectedProjectKey = '';
        
        const owaspColors = {{
            'A01:2025-Broken Access Control': '#8B0000',
            'A02:2025-Security Misconfiguration': '#DC3545', 
            'A03:2025-Software Supply Chain Failures': '#FF6B6B',
            'A04:2025-Cryptographic Failures': '#FF9800',
            'A05:2025-Injection': '#FFC107',
            'A06:2025-Insecure Design': '#9C27B0',
            'A07:2025-Authentication Failures': '#3F51B5',
            'A08:2025-Software and Data Integrity Failures': '#009688',
            'A09:2025-Logging & Alerting Failures': '#607D8B',
            'A10:2025-Mishandling of Exception Conditions': '#795548',
            'OTHER': '#9E9E9E'
        }};
        
        document.addEventListener('DOMContentLoaded', function() {{
            console.log('Dashboard data loaded:', dashboardData);
            initializeDashboard();
            populateProjectSelector();
            updateOverviewMetrics();
            renderAllCharts();
        }});
        
        function initializeDashboard() {{
            document.querySelectorAll('.card').forEach(card => {{
                card.classList.add('fade-in');
            }});
        }}
        
        function switchTab(tabName) {{
            document.querySelectorAll('.tab-btn').forEach(btn => {{
                btn.classList.remove('active');
            }});
            event.target.classList.add('active');
            
            document.querySelectorAll('.tab-content').forEach(content => {{
                content.classList.remove('active');
            }});
            document.getElementById(tabName + '-tab').classList.add('active');
            
            currentTab = tabName;
            
            setTimeout(() => {{
                renderTabContent(tabName);
            }}, 100);
        }}
        
        function renderTabContent(tabName) {{
            switch(tabName) {{
                case 'overview':
                    renderOverviewCharts();
                    break;
                case 'insights':
                    renderInsights();
                    renderBenchmarks();
                    break;
                case 'owasp':
                    renderOWASPAnalysis();
                    break;
                case 'risks':
                    renderRiskManagement();
                    break;
                case 'projects':
                    renderProjectsTable();
                    break;
                case 'aggregate':
                    initAggregateReport();
                    break;
                case 'cwe':
                    renderCWECommandCenter();
                    break;
            }}
        }}

        function populateProjectSelector() {{
            const selector = document.getElementById('projectSelector');
            const projects = dashboardData.projects || [];
            
            while (selector.children.length > 1) {{
                selector.removeChild(selector.lastChild);
            }}
            
            const sortedProjects = projects.sort((a, b) => a.name.localeCompare(b.name));
            
            sortedProjects.forEach(project => {{
                const option = document.createElement('option');
                option.value = project.key;
                
                let icon = '📁';
                if (project.has_secrets && project.has_misconfigs) {{
                    icon = '🚨';
                }} else if (project.has_secrets) {{
                    icon = '🔐';
                }} else if (project.has_misconfigs) {{
                    icon = '⚙️';
                }} else if (project.average_coverage > 80) {{
                    icon = '✅';
                }} else if (project.average_coverage > 0) {{
                    icon = '📊';
                }}
                
                option.textContent = `${{icon}} ${{project.name}}`;
                selector.appendChild(option);
            }});
        }}
        
        function selectProject() {{
            const selector = document.getElementById('projectSelector');
            selectedProjectKey = selector.value;
            
            if (selectedProjectKey) {{
                switchTab('projects');
                renderProjectDetail(selectedProjectKey);
            }} else {{
                document.getElementById('projectDetailSection').style.display = 'none';
            }}
            
            updateOverviewMetrics();
            renderAllCharts();
        }}
        
        function clearProjectFilter() {{
            document.getElementById('projectSelector').value = '';
            selectedProjectKey = '';
            document.getElementById('projectDetailSection').style.display = 'none';
            updateOverviewMetrics();
            renderAllCharts();
        }}
        
        function getFilteredData() {{
            if (!selectedProjectKey) {{
                return dashboardData;
            }}
            
            const selectedProject = dashboardData.projects.find(p => p.key === selectedProjectKey);
            if (!selectedProject) return dashboardData;
            
            return {{
                ...dashboardData,
                projects: [selectedProject],
                projects_with_secrets: selectedProject.has_secrets ? 1 : 0,
                projects_with_misconfigs: selectedProject.has_misconfigs ? 1 : 0,
                projects_with_coverage: selectedProject.average_coverage > 0 ? 1 : 0,
            }};
        }}
        
        function updateOverviewMetrics() {{
            const data = getFilteredData();
            const governance = data.governance_metrics || {{}};
            
            document.getElementById('totalProjects').textContent = data.projects?.length || 0;
            document.getElementById('projectsWithCoverage').textContent = data.projects_with_coverage || 0;
            document.getElementById('projectsWithSecrets').textContent = data.projects_with_secrets || 0;
            document.getElementById('projectsWithMisconfigs').textContent = data.projects_with_misconfigs || 0;
            document.getElementById('governanceScore').textContent = (governance.score || 0).toFixed(1);
            
            const completion = data.total_repositories_expected > 0 ? 
                ((data.projects?.length || 0) / data.total_repositories_expected * 100).toFixed(1) : 0;
            document.getElementById('projectsCompletionChange').textContent = `${{completion}}% da meta`;
            
            const coveragePercentage = data.projects?.length > 0 ?
                ((data.projects_with_coverage || 0) / data.projects.length * 100).toFixed(1) : 0;
            document.getElementById('coveragePercentage').textContent = `${{coveragePercentage}}% configurado`;
            
            const secretsPercentage = data.projects?.length > 0 ?
                ((data.projects_with_secrets || 0) / data.projects.length * 100).toFixed(1) : 0;
            document.getElementById('secretsPercentage').textContent = 
                secretsPercentage > 0 ? `${{secretsPercentage}}% afetados` : 'Nenhum detectado';
            
            const misconfigsPercentage = data.projects?.length > 0 ?
                ((data.projects_with_misconfigs || 0) / data.projects.length * 100).toFixed(1) : 0;
            document.getElementById('misconfigsPercentage').textContent = 
                misconfigsPercentage > 0 ? `${{misconfigsPercentage}}% afetados` : 'Nenhum detectado';
            
            document.getElementById('governanceLevel').textContent = governance.level || 'Indefinido';
            
            const secretsCard = document.getElementById('secretsCard');
            if ((data.projects_with_secrets || 0) > 0) {{
                secretsCard.classList.add('critical-alert', 'pulse');
            }} else {{
                secretsCard.classList.remove('critical-alert', 'pulse');
                secretsCard.classList.add('success');
            }}
            
            const misconfigsCard = document.getElementById('misconfigsCard');
            if ((data.projects_with_misconfigs || 0) > 0) {{
                misconfigsCard.classList.add('critical-alert', 'pulse');
            }} else {{
                misconfigsCard.classList.remove('critical-alert', 'pulse');
                misconfigsCard.classList.add('success');
            }}
            
            const coverageCard = document.getElementById('coverageCard');
            const coverageRate = parseFloat(coveragePercentage);
            if (coverageRate >= 80) {{
                coverageCard.classList.add('success');
                coverageCard.classList.remove('warning', 'danger');
            }} else if (coverageRate >= 50) {{
                coverageCard.classList.add('warning');
                coverageCard.classList.remove('success', 'danger');
            }} else {{
                coverageCard.classList.add('danger');
                coverageCard.classList.remove('success', 'warning');
            }}
        }}
        
        function renderAllCharts() {{
            if (currentTab === 'overview') {{
                renderOverviewCharts();
            }}
            renderTabContent(currentTab);
        }}
        
        function renderOverviewCharts() {{
            renderMaturityDistributionChart();
            renderQualityGateChart();
            renderOWASPTop5Chart();
            renderCoverageVsIssuesChart();
        }}
        
        function renderCoverageVsIssuesChart() {{
            const ctx = document.getElementById('coverageVsIssuesChart');
            if (!ctx) return;
            
            if (charts.coverageVsIssues) {{
                charts.coverageVsIssues.destroy();
            }}
            
            const data = getFilteredData();
            const projects = data.projects || [];
            
            const chartData = projects.map(project => {{
                const totalIssues = Object.values(project.owasp_metrics || {{}}).reduce((a, b) => a + b, 0);
                const coverage = project.average_coverage || 0;
                
                let pointColor = '#28a745';
                if (project.has_secrets || project.has_misconfigs) {{
                    pointColor = '#dc3545';
                }} else if (totalIssues > 20) {{
                    pointColor = '#ffc107';
                }} else if (coverage < 50) {{
                    pointColor = '#fd7e14';
                }}
                
                return {{
                    x: coverage,
                    y: totalIssues,
                    label: project.name,
                    backgroundColor: pointColor,
                    borderColor: pointColor
                }};
            }});
            
            charts.coverageVsIssues = new Chart(ctx, {{
                type: 'scatter',
                data: {{
                    datasets: [{{
                        label: 'Projetos',
                        data: chartData,
                        backgroundColor: chartData.map(d => d.backgroundColor),
                        borderColor: chartData.map(d => d.borderColor),
                        pointRadius: 8,
                        pointHoverRadius: 10
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const point = context.raw;
                                    return `${{point.label}}: Coverage ${{point.x.toFixed(1)}}%, Issues ${{point.y}}`;
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            title: {{
                                display: true,
                                text: 'Coverage (%)'
                            }},
                            min: 0,
                            max: 100
                        }},
                        y: {{
                            title: {{
                                display: true,
                                text: 'Total de Issues OWASP'
                            }},
                            beginAtZero: true
                        }}
                    }}
                }}
            }});
        }}
        
        function renderOWASPAnalysis() {{
            renderOWASPCategoriesGrid();
            renderOWASPCategoriesChart();
            renderOWASPProjectComparisonChart();
        }}
        
        function renderOWASPCategoriesGrid() {{
            const container = document.getElementById('owaspCategoriesGrid');
            const data = getFilteredData();
            const owaspMetrics = data.owasp_metrics_global || {{}};
            const owaspMapping = dashboardData.owasp_top_10_2025 || {{}};
            
            let html = '';
            const sortedCategories = Object.keys(owaspMapping).sort();
            
            sortedCategories.forEach(category => {{
                const count = owaspMetrics[category] || 0;
                const categoryData = owaspMapping[category] || {{}};
                const color = categoryData.color || '#9E9E9E';
                const priority = category.match(/A(\\d+)/)?.[1] || '00';
                const icon = categoryData.icon || 'fa-shield-alt';
                const impact = categoryData.impact || 'Impacto de segurança';
                const isHighlight = categoryData.highlight || false;
                
                const cardClass = count > 0 ? 'danger' : 'success';
                const statusIcon = count > 0 ? 'fa-exclamation-triangle' : 'fa-check-circle';
                const statusText = count > 0 ? `${{count}} issues encontrados` : 'Nenhum issue';
                
                const categoryIssues = (dashboardData.issues_details || []).filter(s => s.owasp_category === category);
                const hasIssues = categoryIssues.length > 0;
                
                let highlightClass = '';
                let highlightIndicator = '';
                
                if (category === 'A04:2025-Cryptographic Failures' && hasIssues) {{
                    highlightClass = 'highlight-secrets';
                    highlightIndicator = '<div class="highlight-indicator secrets">🔐 SECRETS</div>';
                }} else if (category === 'A02:2025-Security Misconfiguration' && hasIssues) {{
                    highlightClass = 'highlight-misconfig';
                    highlightIndicator = '<div class="highlight-indicator misconfig">⚙️ MISCONFIG</div>';
                }}
                
                html += `
                    <div class="card ${{cardClass}} ${{hasIssues ? 'clickable' : ''}} ${{highlightClass}}" 
                         ${{hasIssues ? `onclick="showCategoryModal('${{category}}')"` : ''}}
                         style="position: relative;">
                        ${{highlightIndicator}}
                        <div class="card-header">
                            <h4 class="card-title">
                                <span style="color: ${{color}};">
                                    <i class="fas ${{icon}}"></i> A${{priority.padStart(2, '0')}}
                                </span>
                                <div style="font-size: 0.9rem; margin-top: 5px;">${{category.replace('A0' + priority + ':2025-', '')}}</div>
                            </h4>
                            <div class="text-right">
                                <div class="metric-value" style="color: ${{color}}; font-size: 2rem;">${{count}}</div>
                                <i class="fas ${{statusIcon}} text-${{cardClass === 'danger' ? 'danger' : 'success'}}"></i>
                            </div>
                        </div>
                        <div style="margin-bottom: 15px; color: #666; line-height: 1.4;">
                            <strong>Descrição:</strong> ${{categoryData.description || 'Sem descrição disponível'}}<br>
                            <strong>Impacto:</strong> ${{impact}}
                        </div>
                        <div class="status-badge ${{cardClass === 'danger' ? 'danger' : 'success'}}">
                            <i class="fas ${{statusIcon}}"></i>
                            ${{statusText}}
                        </div>
                        ${{hasIssues ? `
                            <div style="margin-top: 15px; padding: 12px; background: rgba(${{category.includes('Cryptographic') ? '255,152,0' : '220,53,69'}},0.1); border-radius: 8px; border-left: 4px solid ${{color}};">
                                <i class="fas fa-${{category.includes('Cryptographic') ? 'key' : 'cogs'}} text-${{category.includes('Cryptographic') ? 'warning' : 'danger'}}"></i>
                                <strong class="text-${{category.includes('Cryptographic') ? 'warning' : 'danger'}}">${{categoryIssues.length}} issue(s) nesta categoria crítica!</strong>
                                <div style="font-size: 0.85em; margin-top: 4px; font-weight: 600;">
                                    <i class="fas fa-mouse-pointer"></i> Clique para análise detalhada e links para correção
                                </div>
                            </div>
                        ` : ''}}
                    </div>
                `;
            }});
            
            container.innerHTML = html;
        }}
        
        function showCategoryModal(owaspCategory) {{
            const issues = dashboardData.issues_details.filter(s => s.owasp_category === owaspCategory);
            if (issues.length === 0) return;
            
            const modal = document.getElementById('categoryModal');
            const modalTitle = document.getElementById('modalTitle');
            const modalContent = document.getElementById('categoryModalContent');
            
            const categoryData = dashboardData.owasp_top_10_2025[owaspCategory] || {{}};
            const categoryIcon = categoryData.icon || 'fa-shield-alt';
            const categoryColor = categoryData.color || '#666';
            
            modalTitle.innerHTML = `
                <i class="fas ${{categoryIcon}}" style="color: ${{categoryColor}};"></i>
                ${{owaspCategory}}
            `;
            
            const severityStats = {{}};
            const projectStats = {{}};
            const branchStats = {{}};
            
            issues.forEach(issue => {{
                severityStats[issue.severity] = (severityStats[issue.severity] || 0) + 1;
                projectStats[issue.projectName] = (projectStats[issue.projectName] || 0) + 1;
                branchStats[issue.branchName] = (branchStats[issue.branchName] || 0) + 1;
            }});
            
            const isSecrets = owaspCategory === 'A04:2025-Cryptographic Failures';
            const isMisconfig = owaspCategory === 'A02:2025-Security Misconfiguration';
            
            let specialAlert = '';
            if (isSecrets) {{
                specialAlert = `
                    <div style="margin-bottom: 25px; padding: 20px; background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); border-radius: 12px; border-left: 6px solid #FF9800;">
                        <h4 style="margin-bottom: 15px; color: #856404;">
                            <i class="fas fa-key"></i>
                            🔐 ALERTA DE SEGURANÇA CRÍTICO - SECRETS EXPOSTOS
                        </h4>
                        <p style="margin-bottom: 10px; color: #856404; font-weight: 600;">
                            Esta categoria contém <strong>${{issues.length}} secret(s) expostos</strong> que representam <strong>risco CRÍTICO</strong> de vazamento de credenciais e dados sensíveis.
                        </p>
                        <div style="background: rgba(255,152,0,0.2); padding: 10px; border-radius: 6px; margin-top: 10px;">
                            <strong>⚡ AÇÃO IMEDIATA NECESSÁRIA:</strong><br>
                            1. Revogar todas as credenciais expostas<br>
                            2. Gerar novas credenciais<br>
                            3. Implementar secret scanning no CI/CD
                        </div>
                    </div>
                `;
            }} else if (isMisconfig) {{
                specialAlert = `
                    <div style="margin-bottom: 25px; padding: 20px; background: linear-gradient(135deg, #f8d7da 0%, #f1aeb5 100%); border-radius: 12px; border-left: 6px solid #DC3545;">
                        <h4 style="margin-bottom: 15px; color: #721c24;">
                            <i class="fas fa-cogs"></i>
                            ⚙️ ALERTA DE CONFIGURAÇÃO CRÍTICA
                        </h4>
                        <p style="margin-bottom: 10px; color: #721c24; font-weight: 600;">
                            Esta categoria contém <strong>${{issues.length}} configuração(ões) incorreta(s)</strong> que podem <strong>expor o sistema</strong> a ataques.
                        </p>
                        <div style="background: rgba(220,53,69,0.2); padding: 10px; border-radius: 6px; margin-top: 10px;">
                            <strong>⚡ AÇÃO IMEDIATA NECESSÁRIA:</strong><br>
                            1. Revisar configurações de SSL/TLS<br>
                            2. Validar certificados e criptografia<br>
                            3. Implementar configurações seguras por padrão
                        </div>
                    </div>
                `;
            }} else {{
                specialAlert = `
                    <div style="margin-bottom: 25px; padding: 20px; background: rgba(23,162,184,0.1); border-radius: 12px; border-left: 6px solid ${{categoryColor}};">
                        <h4 style="margin-bottom: 15px; color: ${{categoryColor}};">
                            <i class="fas ${{categoryIcon}}"></i>
                            ${{issues.length}} Issue(s) Detectados nesta Categoria
                        </h4>
                        <p style="margin-bottom: 10px; color: #0c5460; font-weight: 600;">
                            <strong>Impacto:</strong> ${{categoryData.impact || 'Risco de segurança identificado'}}
                        </p>
                        <p style="margin-bottom: 0; color: #0c5460;">
                            Use os links diretos abaixo para corrigir cada issue no SonarQube.
                        </p>
                    </div>
                `;
            }}
            
            let html = specialAlert + `
                <div class="modal-stats">
                    <div class="modal-stat">
                        <div class="modal-stat-value text-primary">${{issues.length}}</div>
                        <div class="modal-stat-label">Total Issues</div>
                    </div>
                    <div class="modal-stat">
                        <div class="modal-stat-value text-info">${{Object.keys(projectStats).length}}</div>
                        <div class="modal-stat-label">Projetos Afetados</div>
                    </div>
                    <div class="modal-stat">
                        <div class="modal-stat-value text-warning">${{Object.keys(branchStats).length}}</div>
                        <div class="modal-stat-label">Branches Afetadas</div>
                    </div>
                    <div class="modal-stat">
                        <div class="modal-stat-value text-danger">${{severityStats['BLOCKER'] || 0}}</div>
                        <div class="modal-stat-label">Blockers</div>
                    </div>
                </div>
            `;
            
            const issuesByProject = {{}};
            issues.forEach(issue => {{
                if (!issuesByProject[issue.projectName]) {{
                    issuesByProject[issue.projectName] = [];
                }}
                issuesByProject[issue.projectName].push(issue);
            }});
            
            html += '<div class="issues-list">';
            
            Object.entries(issuesByProject).forEach(([projectName, projectIssues]) => {{
                html += `
                    <div class="project-group">
                        <div class="project-group-header">
                            <div class="project-group-title">
                                <i class="fas fa-project-diagram"></i> ${{projectName}}
                            </div>
                            <div class="project-group-count">${{projectIssues.length}} issue(s)</div>
                        </div>
                        <div class="project-group-content">
                `;
                
                projectIssues.forEach(issue => {{
                    const issueUrl = `${{sonarUrl}}/project/issues?id=${{issue.projectKey}}&open=${{issue.key}}&branch=${{issue.branchName}}`;
                    const ruleUrl = `${{sonarUrl}}/coding_rules?open=${{issue.rule}}`;
                    const creationDate = issue.creationDate ? new Date(issue.creationDate).toLocaleDateString('pt-BR') : 'N/A';
                    const riskLevel = issue.risk_level || 'MEDIUM';
                    
                    html += `
                        <div class="issue-item ${{riskLevel.toLowerCase()}}">
                            <div class="issue-header">
                                <div class="issue-title">${{issue.message}}</div>
                                <div class="issue-badges">
                                    <span class="issue-badge severity-${{issue.severity.toLowerCase()}}">${{issue.severity}}</span>
                                    <span class="issue-badge severity-${{issue.risk_level.toLowerCase()}}">${{issue.risk_level}} RISK</span>
                                </div>
                            </div>
                            
                            <div class="issue-details">
                                <strong>Análise:</strong> Este issue foi classificado como <strong>${{owaspCategory}}</strong> e requer correção para manter a segurança da aplicação.
                                ${{isSecrets ? '<br><strong style="color: #856404;">⚠️ CRÍTICO: Este issue expõe credenciais ou dados sensíveis!</strong>' : ''}}
                                ${{isMisconfig ? '<br><strong style="color: #721c24;">⚠️ CRÍTICO: Este issue representa uma configuração insegura!</strong>' : ''}}
                            </div>
                            
                            <div class="issue-meta">
                                <div class="issue-meta-item">
                                    <i class="fas fa-code-branch"></i>
                                    <span>Branch: <strong>${{issue.branchName}}</strong></span>
                                </div>
                                <div class="issue-meta-item">
                                    <i class="fas fa-file-code"></i>
                                    <span>Arquivo: <strong>${{issue.component}}</strong></span>
                                </div>
                                <div class="issue-meta-item">
                                    <i class="fas fa-hashtag"></i>
                                    <span>Linha: <strong>${{issue.line || 'N/A'}}</strong></span>
                                </div>
                                <div class="issue-meta-item">
                                    <i class="fas fa-calendar-alt"></i>
                                    <span>Detectado: <strong>${{creationDate}}</strong></span>
                                </div>
                                <div class="issue-meta-item">
                                    <i class="fas fa-shield-alt"></i>
                                    <span>Regra: <strong>${{issue.rule}}</strong></span>
                                </div>
                                <div class="issue-meta-item">
                                    <i class="fas fa-bug"></i>
                                    <span>Tipo: <strong>${{issue.type}}</strong></span>
                                </div>
                            </div>
                            
                            <div class="issue-actions">
                                <a href="${{issueUrl}}" target="_blank" class="issue-link danger">
                                    <i class="fas fa-external-link-alt"></i>
                                    ${{isSecrets ? 'URGENTE - Corrigir Secret' : isMisconfig ? 'URGENTE - Corrigir Config' : 'Corrigir no SonarQube'}}
                                </a>
                                <a href="${{ruleUrl}}" target="_blank" class="issue-link">
                                    <i class="fas fa-book"></i>
                                    Ver Documentação da Regra
                                </a>
                            </div>
                        </div>
                    `;
                }});
                
                html += '</div></div>';
            }});
            
            html += '</div>';
            
            modalContent.innerHTML = html;
            modal.style.display = 'block';
        }}
        
        function closeCategoryModal() {{
            document.getElementById('categoryModal').style.display = 'none';
        }}
        
        window.onclick = function(event) {{
            const modal = document.getElementById('categoryModal');
            if (event.target === modal) {{
                modal.style.display = 'none';
            }}
        }}
        
        function renderInsights() {{
            const container = document.getElementById('insightsContainer');
            const insights = dashboardData.insights || {{}};
            
            let html = '';
            
            const mainBranches = ['main', 'master', 'develop', 'developer'];
            const secretsVulnerabilities = (dashboardData.issues_details || []).filter(issue => {{
                const isSecret = issue.rule && issue.rule.toLowerCase().includes('secrets:');
                const isVulnerability = issue.type === 'VULNERABILITY';
                const isMainBranch = mainBranches.includes(issue.branchName?.toLowerCase());
                return isSecret && isVulnerability && isMainBranch;
            }});
            
            if (secretsVulnerabilities.length > 0) {{
                const secretsByProject = {{}};
                secretsVulnerabilities.forEach(secret => {{
                    if (!secretsByProject[secret.projectName]) {{
                        secretsByProject[secret.projectName] = [];
                    }}
                    secretsByProject[secret.projectName].push(secret);
                }});
                
                Object.entries(secretsByProject).forEach(([projectName, secrets]) => {{
                    const projectKey = secrets[0].projectKey;
                    const criticalSecrets = secrets.filter(s => s.severity === 'BLOCKER' || s.severity === 'CRITICAL');
                    
                    html += `
                        <div class="insight-card critical">
                            <div class="insight-header">
                                <div>
                                    <div class="insight-title">🔐 ${{secrets.length}} Secrets Expostos (VULNERABILITY) - ${{projectName}}</div>
                                    <div class="insight-description">
                                        <strong>Projeto:</strong> ${{projectName}}<br>
                                        <strong>Branches Afetadas:</strong> ${{[...new Set(secrets.map(s => s.branchName))].join(', ')}}<br>
                                        <strong>Severidade Crítica:</strong> ${{criticalSecrets.length}} issue(s)<br>
                                        <strong>⚠️ AÇÃO IMEDIATA:</strong> Revogar todas as credenciais expostas e implementar secret scanning no CI/CD
                                    </div>
                                </div>
                                <div class="insight-badge critical">CRÍTICO</div>
                            </div>
                            <div class="insight-details" style="margin-top: 15px;">
                                <h5 style="margin-bottom: 10px;"><i class="fas fa-list"></i> Issues Detectados:</h5>
                    `;
                    
                    secrets.forEach(secret => {{
                        const issueUrl = `${{sonarUrl}}/project/issues?id=${{secret.projectKey}}&open=${{secret.key}}&branch=${{secret.branchName}}`;
                        html += `
                            <div style="padding: 10px; margin-bottom: 8px; background: rgba(255,255,255,0.1); border-left: 3px solid #FFD700; border-radius: 4px;">
                                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 5px;">
                                    <strong style="color: #FFD700;">${{secret.rule}}</strong>
                                    <span class="issue-badge severity-${{secret.severity.toLowerCase()}}" style="font-size: 0.7rem;">${{secret.severity}}</span>
                                </div>
                                <div style="font-size: 0.9em; margin-bottom: 5px;">${{secret.message}}</div>
                                <div style="font-size: 0.85em; color: rgba(255,255,255,0.8); margin-bottom: 8px;">
                                    <i class="fas fa-code-branch"></i> ${{secret.branchName}} | 
                                    <i class="fas fa-file-code"></i> ${{secret.component}} |
                                    <i class="fas fa-hashtag"></i> Linha ${{secret.line || 'N/A'}}
                                </div>
                                <a href="${{issueUrl}}" target="_blank" style="display: inline-block; background: #FFD700; color: #000; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 0.85em; font-weight: 600;">
                                    <i class="fas fa-external-link-alt"></i> URGENTE - Corrigir Agora
                                </a>
                            </div>
                        `;
                    }});
                    
                    html += `
                            </div>
                            <div class="insight-actions">
                                <button onclick="showCategoryModal('A04:2025-Cryptographic Failures')" class="insight-action" style="background: var(--danger-color); color: white; border: none; cursor: pointer; padding: 10px 16px;">
                                    🔍 Ver Análise Completa OWASP A04
                                </button>
                            </div>
                        </div>
                    `;
                }});
            }} else {{
                html += `
                    <div class="insight-card low">
                        <div class="insight-header">
                            <div>
                                <div class="insight-title">✅ Nenhum Secret (VULNERABILITY) Detectado</div>
                                <div class="insight-description">
                                    Não foram encontrados secrets do tipo VULNERABILITY nas branches principais (main, master, develop, developer).
                                    Continue mantendo as boas práticas de segurança!
                                </div>
                            </div>
                            <div class="insight-badge low">OK</div>
                        </div>
                    </div>
                `;
            }}
            
            (insights.opportunities || []).forEach(opportunity => {{
                html += `
                    <div class="insight-card info">
                        <div class="insight-header">
                            <div>
                                <div class="insight-title">${{opportunity.title}}</div>
                                <div class="insight-description">${{opportunity.description}}</div>
                            </div>
                            <div class="insight-badge medium">OPPORTUNITY</div>
                        </div>
                        <div class="insight-actions">
                            <span class="insight-action">🎯 ${{opportunity.benefit}}</span>
                            <span class="insight-action">⏱️ Esforço: ${{opportunity.effort}}</span>
                        </div>
                    </div>
                `;
            }});
            
            (insights.recommendations || []).forEach(rec => {{
                html += `
                    <div class="insight-card low">
                        <div class="insight-header">
                            <div>
                                <div class="insight-title">#${{rec.priority}} ${{rec.title}}</div>
                                <div class="insight-description">${{rec.description}}</div>
                            </div>
                            <div class="insight-badge low">REC</div>
                        </div>
                        <div class="insight-actions">
                            <span class="insight-action">📅 ${{rec.timeline}}</span>
                            <span class="insight-action">💰 ${{rec.roi}}</span>
                        </div>
                    </div>
                `;
            }});
            
            if (html === '') {{
                html = '<div class="empty-state"><i class="fas fa-lightbulb"></i><br>Nenhum insight disponível</div>';
            }}
            
            container.innerHTML = html;
        }}
        
        function renderBenchmarks() {{
            const insights = dashboardData.insights || {{}};
            const benchmarks = insights.benchmarks || {{}};
            
            const govBench = benchmarks.governance_score || {{}};
            renderBenchmarkCard('benchmarkGovernance', {{
                current: govBench.current || 0,
                industry: govBench.industry_avg || 65,
                bestPractice: govBench.best_practice || 85,
                status: govBench.status,
                unit: '/100',
                label: 'Score Atual'
            }});
            
            const secretsBench = benchmarks.secrets_ratio || {{}};
            renderBenchmarkCard('benchmarkSecrets', {{
                current: secretsBench.current || 0,
                industry: secretsBench.industry_avg || 15,
                bestPractice: secretsBench.best_practice || 5,
                status: secretsBench.status,
                unit: '%',
                label: 'Taxa Atual',
                inverse: true
            }});
            
            const qgBench = benchmarks.qg_pass_rate || {{}};
            renderBenchmarkCard('benchmarkQualityGate', {{
                current: qgBench.current || 0,
                industry: qgBench.industry_avg || 75,
                bestPractice: qgBench.best_practice || 95,
                status: qgBench.status,
                unit: '%',
                label: 'Taxa Atual'
            }});
            
            const coverageBench = benchmarks.coverage_ratio || {{}};
            renderBenchmarkCard('benchmarkCoverage', {{
                current: coverageBench.current || 0,
                industry: coverageBench.industry_avg || 70,
                bestPractice: coverageBench.best_practice || 90,
                status: coverageBench.status,
                unit: '%',
                label: 'Taxa Atual'
            }});
        }}
        
        function renderBenchmarkCard(containerId, data) {{
            const container = document.getElementById(containerId);
            if (!container) return;
            
            const isGood = data.inverse ? 
                data.current <= data.bestPractice : 
                data.current >= data.industry;
                
            const statusColor = isGood ? 'success' : 'danger';
            const statusIcon = isGood ? 'fa-check-circle' : 'fa-exclamation-circle';
            
            container.innerHTML = `
                <div class="metric-card">
                    <span class="metric-value text-${{statusColor}}">${{data.current.toFixed(1)}}${{data.unit}}</span>
                    <div class="metric-label">${{data.label}}</div>
                    <div class="progress-bar">
                        <div class="progress-fill ${{statusColor}}" style="width: ${{Math.min((data.current / data.bestPractice) * 100, 100)}}%"></div>
                    </div>
                    <div class="mt-2">
                        <small class="text-muted">Indústria: ${{data.industry}}${{data.unit}} | Best Practice: ${{data.bestPractice}}${{data.unit}}</small>
                    </div>
                    <div class="metric-change ${{isGood ? 'positive' : 'negative'}}">
                        <i class="fas ${{statusIcon}}"></i>
                        ${{isGood ? 'Dentro do esperado' : 'Necessita melhoria'}}
                    </div>
                </div>
            `;
        }}
        
        document.addEventListener('DOMContentLoaded', function() {{
            setTimeout(() => {{
                renderTabContent('insights');
            }}, 500);
        }});
        
        document.addEventListener('keydown', function(event) {{
            if (event.key === 'Escape') {{
                closeCategoryModal();
            }}
        }});
        
        function renderMaturityDistributionChart() {{
            const ctx = document.getElementById('maturityDistributionChart');
            if (!ctx) return;
            
            if (charts.maturityDistribution) {{
                charts.maturityDistribution.destroy();
            }}
            
            const data = getFilteredData();
            const projects = data.projects || [];
            
            const maturityCounts = {{
                'INITIAL': 0,
                'DEVELOPING': 0,
                'DEFINED': 0,
                'MANAGED': 0,
                'OPTIMIZED': 0
            }};
            
            projects.forEach(project => {{
                const level = project.governance_maturity?.level || 'INITIAL';
                if (maturityCounts[level] !== undefined) {{
                    maturityCounts[level]++;
                }}
            }});
            
            charts.maturityDistribution = new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Inicial', 'Em Desenvolvimento', 'Definido', 'Gerenciado', 'Otimizado'],
                    datasets: [{{
                        data: [
                            maturityCounts.INITIAL,
                            maturityCounts.DEVELOPING,
                            maturityCounts.DEFINED,
                            maturityCounts.MANAGED,
                            maturityCounts.OPTIMIZED
                        ],
                        backgroundColor: [
                            '#dc3545',
                            '#fd7e14',
                            '#ffc107',
                            '#28a745',
                            '#20c997'
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 15,
                                font: {{
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? ((context.parsed / total) * 100).toFixed(1) : 0;
                                    return `${{context.label}}: ${{context.parsed}} (${{percentage}}%)`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderQualityGateChart() {{
            const ctx = document.getElementById('qualityGateChart');
            if (!ctx) return;
            
            if (charts.qualityGate) {{
                charts.qualityGate.destroy();
            }}
            
            const data = getFilteredData();
            
            charts.qualityGate = new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Aprovado', 'Reprovado', 'Sem QG'],
                    datasets: [{{
                        data: [
                            data.projects_main_passed || 0,
                            data.projects_main_failed || 0,
                            data.projects_main_none || 0
                        ],
                        backgroundColor: [
                            '#28a745',
                            '#dc3545',
                            '#6c757d'
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 15,
                                font: {{
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? ((context.parsed / total) * 100).toFixed(1) : 0;
                                    return `${{context.label}}: ${{context.parsed}} (${{percentage}}%)`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderOWASPTop5Chart() {{
            const ctx = document.getElementById('owaspTop5Chart');
            if (!ctx) return;
            
            if (charts.owaspTop5) {{
                charts.owaspTop5.destroy();
            }}
            
            const data = getFilteredData();
            const owaspMetrics = data.owasp_metrics_global || {{}};
            
            const sortedCategories = Object.entries(owaspMetrics)
                .filter(([cat, count]) => cat !== 'OTHER' && count > 0)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);
            
            const labels = sortedCategories.map(([cat]) => {{
                const shortName = cat.replace(/A0\\d+:2025-/, '');
                return shortName.length > 25 ? shortName.substring(0, 25) + '...' : shortName;
            }});
            
            const values = sortedCategories.map(([, count]) => count);
            const colors = sortedCategories.map(([cat]) => owaspColors[cat] || '#9E9E9E');
            
            charts.owaspTop5 = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Issues',
                        data: values,
                        backgroundColor: colors,
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return sortedCategories[context[0].dataIndex][0];
                                }},
                                label: function(context) {{
                                    return `Issues: ${{context.parsed.x}}`;
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            ticks: {{
                                precision: 0
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderOWASPCategoriesChart() {{
            const ctx = document.getElementById('owaspCategoriesChart');
            if (!ctx) return;
            
            if (charts.owaspCategories) {{
                charts.owaspCategories.destroy();
            }}
            
            const data = getFilteredData();
            const owaspMetrics = data.owasp_metrics_global || {{}};
            const owaspMapping = dashboardData.owasp_top_10_2025 || {{}};
            
            const sortedCategories = Object.keys(owaspMapping)
                .filter(cat => cat !== 'OTHER')
                .sort();
            
            const labels = sortedCategories.map(cat => {{
                const priority = cat.match(/A(\\d+)/)?.[1] || '00';
                return `A${{priority}}`;
            }});
            
            const values = sortedCategories.map(cat => owaspMetrics[cat] || 0);
            const colors = sortedCategories.map(cat => owaspColors[cat] || '#9E9E9E');
            
            charts.owaspCategories = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Total de Issues',
                        data: values,
                        backgroundColor: colors,
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return sortedCategories[context[0].dataIndex];
                                }},
                                label: function(context) {{
                                    return `Issues: ${{context.parsed.y}}`;
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                precision: 0
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderOWASPProjectComparisonChart() {{
            const ctx = document.getElementById('owaspProjectComparisonChart');
            if (!ctx) return;
            
            if (charts.owaspProjectComparison) {{
                charts.owaspProjectComparison.destroy();
            }}
            
            const data = getFilteredData();
            const projects = data.projects || [];
            
            const projectsWithIssues = projects
                .map(p => ({{
                    name: p.name,
                    total: Object.values(p.owasp_metrics || {{}}).reduce((a, b) => a + b, 0),
                    metrics: p.owasp_metrics || {{}}
                }}))
                .filter(p => p.total > 0)
                .sort((a, b) => b.total - a.total)
                .slice(0, 10);
            
            if (projectsWithIssues.length === 0) {{
                ctx.parentElement.innerHTML = '<div class="empty-state"><i class="fas fa-chart-bar"></i><br>Nenhum dado disponível</div>';
                return;
            }}
            
            const labels = projectsWithIssues.map(p => {{
                const name = p.name;
                return name.length > 20 ? name.substring(0, 20) + '...' : name;
            }});
            
            charts.owaspProjectComparison = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Total Issues',
                        data: projectsWithIssues.map(p => p.total),
                        backgroundColor: '#667eea',
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return projectsWithIssues[context[0].dataIndex].name;
                                }},
                                label: function(context) {{
                                    return `Total Issues: ${{context.parsed.x}}`;
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            ticks: {{
                                precision: 0
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderRiskManagement() {{
            renderTopRiskProjectsTable();
            renderIssuesOwaspChart();
            renderBranchDistributionChart();
        }}
        
        function renderTopRiskProjectsTable() {{
            const container = document.getElementById('topRiskProjectsTable');
            if (!container) return;
            
            const data = getFilteredData();
            const projects = data.projects || [];
            
            const projectRisks = projects.map(project => {{
                const totalIssues = Object.values(project.owasp_metrics || {{}}).reduce((a, b) => a + b, 0);
                const secretsWeight = project.has_secrets ? 50 : 0;
                const misconfigWeight = project.has_misconfigs ? 30 : 0;
                const coveragePenalty = project.average_coverage < 50 ? 20 : 0;
                
                const riskScore = totalIssues + secretsWeight + misconfigWeight + coveragePenalty;
                
                let riskLevel = 'LOW';
                if (riskScore > 100) riskLevel = 'CRITICAL';
                else if (riskScore > 50) riskLevel = 'HIGH';
                else if (riskScore > 20) riskLevel = 'MEDIUM';
                
                return {{
                    name: project.name,
                    key: project.key,
                    totalIssues,
                    hasSecrets: project.has_secrets,
                    hasMisconfigs: project.has_misconfigs,
                    coverage: project.average_coverage,
                    riskScore,
                    riskLevel,
                    governanceScore: project.governance_maturity?.score || 0
                }};
            }})
            .sort((a, b) => b.riskScore - a.riskScore)
            .slice(0, 10);
            
            if (projectRisks.length === 0) {{
                container.innerHTML = '<div class="empty-state"><i class="fas fa-shield-alt"></i><br>Nenhum projeto com risco identificado</div>';
                return;
            }}
            
            let html = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Projeto</th>
                            <th>Nível de Risco</th>
                            <th>Score de Risco</th>
                            <th>Issues OWASP</th>
                            <th>Secrets</th>
                            <th>Misconfigs</th>
                            <th>Coverage</th>
                            <th>Governança</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            projectRisks.forEach((project, index) => {{
                const riskClass = project.riskLevel.toLowerCase();
                const coverageClass = project.coverage > 80 ? 'good' : project.coverage > 50 ? 'medium' : project.coverage > 0 ? 'poor' : 'none';
                
                html += `
                    <tr>
                        <td><strong>${{index + 1}}</strong></td>
                        <td><strong>${{project.name}}</strong></td>
                        <td><span class="status-badge risk-${{riskClass}}">${{project.riskLevel}}</span></td>
                        <td><strong>${{project.riskScore.toFixed(0)}}</strong></td>
                        <td>${{project.totalIssues}}</td>
                        <td>${{project.hasSecrets ? '<span class="text-danger"><i class="fas fa-key"></i> SIM</span>' : '<span class="text-success"><i class="fas fa-check"></i> Não</span>'}}</td>
                        <td>${{project.hasMisconfigs ? '<span class="text-danger"><i class="fas fa-cogs"></i> SIM</span>' : '<span class="text-success"><i class="fas fa-check"></i> Não</span>'}}</td>
                        <td>
                            <span class="coverage-indicator ${{coverageClass}}">
                                <i class="fas fa-chart-pie"></i>
                                ${{project.coverage > 0 ? project.coverage.toFixed(1) + '%' : 'N/A'}}
                            </span>
                        </td>
                        <td>${{project.governanceScore.toFixed(1)}}/100</td>
                    </tr>
                `;
            }});
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }}
        
        function renderIssuesOwaspChart() {{
            const ctx = document.getElementById('issuesOwaspChart');
            if (!ctx) return;
            
            if (charts.issuesOwasp) {{
                charts.issuesOwasp.destroy();
            }}
            
            const data = getFilteredData();
            const owaspMetrics = data.owasp_metrics_global || {{}};
            const owaspMapping = dashboardData.owasp_top_10_2025 || {{}};
            
            const categories = Object.keys(owaspMapping)
                .filter(cat => cat !== 'OTHER')
                .sort();
            
            const labels = categories.map(cat => {{
                const priority = cat.match(/A(\\d+)/)?.[1] || '00';
                return `A${{priority}}`;
            }});
            
            const values = categories.map(cat => owaspMetrics[cat] || 0);
            const colors = categories.map(cat => owaspColors[cat] || '#9E9E9E');
            
            charts.issuesOwasp = new Chart(ctx, {{
                type: 'polarArea',
                data: {{
                    labels: labels,
                    datasets: [{{
                        data: values,
                        backgroundColor: colors.map(c => c + '80'),
                        borderColor: colors,
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'right',
                            labels: {{
                                padding: 10,
                                font: {{
                                    size: 11
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return categories[context[0].dataIndex];
                                }},
                                label: function(context) {{
                                    return `Issues: ${{context.parsed.r}}`;
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        r: {{
                            beginAtZero: true,
                            ticks: {{
                                precision: 0
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderBranchDistributionChart() {{
            const ctx = document.getElementById('branchDistributionChart');
            if (!ctx) return;
            
            if (charts.branchDistribution) {{
                charts.branchDistribution.destroy();
            }}
            
            const data = getFilteredData();
            const projects = data.projects || [];
            
            const branchCounts = {{}};
            projects.forEach(project => {{
                (project.branches || []).forEach(branch => {{
                    const branchName = branch.name;
                    branchCounts[branchName] = (branchCounts[branchName] || 0) + 1;
                }});
            }});
            
            const sortedBranches = Object.entries(branchCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);
            
            if (sortedBranches.length === 0) {{
                ctx.parentElement.innerHTML = '<div class="empty-state"><i class="fas fa-code-branch"></i><br>Nenhuma branch encontrada</div>';
                return;
            }}
            
            charts.branchDistribution = new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: sortedBranches.map(([name]) => name),
                    datasets: [{{
                        data: sortedBranches.map(([, count]) => count),
                        backgroundColor: [
                            '#667eea',
                            '#764ba2',
                            '#f093fb',
                            '#4facfe',
                            '#00f2fe',
                            '#43e97b',
                            '#38f9d7',
                            '#fa709a',
                            '#fee140',
                            '#30cfd0'
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{
                                padding: 15,
                                font: {{
                                    size: 12
                                }}
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? ((context.parsed / total) * 100).toFixed(1) : 0;
                                    return `${{context.label}}: ${{context.parsed}} projetos (${{percentage}}%)`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderProjectsTable() {{
            const container = document.getElementById('projectsTableContainer');
            if (!container) return;
            
            const data = getFilteredData();
            const projects = data.projects || [];
            
            if (projects.length === 0) {{
                container.innerHTML = '<div class="empty-state"><i class="fas fa-project-diagram"></i><br>Nenhum projeto encontrado</div>';
                return;
            }}
            
            let html = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Projeto</th>
                            <th>Branches</th>
                            <th>QG Status</th>
                            <th>Issues OWASP</th>
                            <th>Secrets</th>
                            <th>Misconfigs</th>
                            <th>Coverage</th>
                            <th>Governança</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            projects.forEach(project => {{
                const totalIssues = Object.values(project.owasp_metrics || {{}}).reduce((a, b) => a + b, 0);
                const qgStatus = project.main_qg_status || 'NONE';
                const qgClass = qgStatus === 'OK' ? 'success' : qgStatus === 'ERROR' ? 'danger' : 'info';
                const qgIcon = qgStatus === 'OK' ? 'fa-check-circle' : qgStatus === 'ERROR' ? 'fa-times-circle' : 'fa-question-circle';
                const coverageClass = project.average_coverage > 80 ? 'good' : project.average_coverage > 50 ? 'medium' : project.average_coverage > 0 ? 'poor' : 'none';
                const govLevel = project.governance_maturity?.level || 'INITIAL';
                const govClass = govLevel.toLowerCase();
                
                html += `
                    <tr>
                        <td><strong>${{project.name}}</strong></td>
                        <td>${{project.branches?.length || 0}}</td>
                        <td><span class="status-badge ${{qgClass}}"><i class="fas ${{qgIcon}}"></i> ${{qgStatus}}</span></td>
                        <td>${{totalIssues}}</td>
                        <td>${{project.has_secrets ? '<span class="text-danger"><i class="fas fa-key"></i> ${{project.secrets_count}}</span>' : '<span class="text-success"><i class="fas fa-check"></i> 0</span>'}}</td>
                        <td>${{project.has_misconfigs ? '<span class="text-danger"><i class="fas fa-cogs"></i> ${{project.misconfigs_count}}</span>' : '<span class="text-success"><i class="fas fa-check"></i> 0</span>'}}</td>
                        <td>
                            <span class="coverage-indicator ${{coverageClass}}">
                                <i class="fas fa-chart-pie"></i>
                                ${{project.average_coverage > 0 ? project.average_coverage.toFixed(1) + '%' : 'N/A'}}
                            </span>
                        </td>
                        <td><span class="status-badge maturity-${{govClass}}">${{govLevel}}</span></td>
                    </tr>
                `;
            }});
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }}
        
        function renderProjectDetail(projectKey) {{
            const project = dashboardData.projects.find(p => p.key === projectKey);
            if (!project) return;
            
            const detailSection = document.getElementById('projectDetailSection');
            detailSection.style.display = 'block';
            
            const totalIssues = Object.values(project.owasp_metrics || {{}}).reduce((a, b) => a + b, 0);
            const qgStatus = project.main_qg_status || 'NONE';
            const qgClass = qgStatus === 'OK' ? 'success' : qgStatus === 'ERROR' ? 'danger' : 'info';
            
            let html = `
                <div class="project-detail-header">
                    <h2 class="project-detail-title">${{project.name}}</h2>
                    <div class="project-detail-meta">
                        <span><i class="fas fa-key"></i> ${{project.key}}</span>
                        <span><i class="fas fa-code-branch"></i> ${{project.branches?.length || 0}} branches</span>
                        <span><i class="fas fa-shield-alt"></i> ${{totalIssues}} issues OWASP</span>
                        <span class="status-badge ${{qgClass}}"><i class="fas fa-check-circle"></i> QG: ${{qgStatus}}</span>
                    </div>
                </div>
                <div class="project-detail-content">
                    <div class="grid grid-4 mb-4">
                        <div class="card ${{project.has_secrets ? 'danger' : 'success'}}">
                            <div class="metric-value ${{project.has_secrets ? 'text-danger' : 'text-success'}}">${{project.secrets_count || 0}}</div>
                            <div class="metric-label">Secrets Expostos</div>
                        </div>
                        <div class="card ${{project.has_misconfigs ? 'danger' : 'success'}}">
                            <div class="metric-value ${{project.has_misconfigs ? 'text-danger' : 'text-success'}}">${{project.misconfigs_count || 0}}</div>
                            <div class="metric-label">Misconfigurations</div>
                        </div>
                        <div class="card info">
                            <div class="metric-value text-info">${{project.average_coverage > 0 ? project.average_coverage.toFixed(1) + '%' : 'N/A'}}</div>
                            <div class="metric-label">Coverage Médio</div>
                        </div>
                        <div class="card info">
                            <div class="metric-value text-info">${{(project.governance_maturity?.score || 0).toFixed(1)}}</div>
                            <div class="metric-label">Score de Governança</div>
                        </div>
                    </div>
            `;
            
            html += '<h3 class="mb-3"><i class="fas fa-code-branch"></i> Branches Monitoradas</h3>';
            (project.branches || []).forEach(branch => {{
                const branchIssues = Object.values(branch.owasp_metrics || {{}}).reduce((a, b) => a + b, 0);
                html += `
                    <div class="card mb-3">
                        <h4><i class="fas fa-code-branch"></i> ${{branch.name}} ${{branch.is_main ? '(Principal)' : ''}}</h4>
                        <div class="grid grid-4 mt-3">
                            <div><strong>Issues:</strong> ${{branchIssues}}</div>
                            <div><strong>Blockers:</strong> ${{branch.blocker_issues?.length || 0}}</div>
                            <div><strong>Secrets:</strong> ${{branch.secrets_issues?.length || 0}}</div>
                            <div><strong>Misconfigs:</strong> ${{branch.misconfig_issues?.length || 0}}</div>
                        </div>
                    </div>
                `;
            }});
            
            html += '</div>';
            detailSection.innerHTML = html;
        }}
        
        // ============================================================================
        // AGGREGATE REPORT - ANÁLISE TEMPORAL
        // ============================================================================
        
        let aggHistoricalData = [];
        let aggChartInstances = {{}};
        
        function initAggregateReport() {{
            console.log('Inicializando Aggregate Report...');
            loadAggregateData();
        }}
        
        function loadAggregateData() {{
            try {{
                const scans = dashboardData.scan_history || [];
                console.log(`Total de arquivos scan_*.json encontrados: ${{scans.length}}`);
                
                if (!scans || scans.length === 0) {{
                    document.getElementById('aggregatePlaceholder').innerHTML = `
                        <i class="fas fa-exclamation-circle" style="font-size: 5rem; color: #dc3545; margin-bottom: 20px;"></i>
                        <h2 style="color: #343a40;">Sem Dados Históricos</h2>
                        <p style="color: #666;">Nenhum arquivo scan_*.json encontrado.</p>
                    `;
                    return;
                }}
                
                if (scans.length < 2) {{
                    document.getElementById('aggregatePlaceholder').innerHTML = `
                        <i class="fas fa-info-circle" style="font-size: 5rem; color: #17a2b8; margin-bottom: 20px;"></i>
                        <h2 style="color: #343a40;">Dados Insuficientes</h2>
                        <p style="color: #666;">Encontrado apenas ${{scans.length}} scan. São necessários pelo menos 2 scans.</p>
                    `;
                    return;
                }}
                
                aggHistoricalData = scans.map(scan => ({{
                    timestamp: scan.timestamp,
                    date: new Date(scan.timestamp),
                    filename: scan.filename,
                    data: scan.data
                }})).sort((a, b) => a.date - b.date);
                
                console.log(`Dados processados: ${{aggHistoricalData.length}} scans`);
                
                document.getElementById('aggregatePlaceholder').style.display = 'none';
                document.getElementById('aggregateCharts').style.display = 'block';
                
                renderAggregateAll();
                
            }} catch (error) {{
                console.error('Erro ao carregar dados:', error);
                document.getElementById('aggregatePlaceholder').innerHTML = `
                    <i class="fas fa-exclamation-triangle" style="font-size: 5rem; color: #ffc107; margin-bottom: 20px;"></i>
                    <h2 style="color: #343a40;">Erro ao Carregar Dados</h2>
                    <p style="color: #666;">${{error.message}}</p>
                `;
            }}
        }}
        
        function calcTotalIssues(data) {{
            let total = 0;
            (data.projects || []).forEach(proj => {{
                (proj.branches || []).forEach(branch => {{
                    if (branch.owasp_metrics) {{
                        total += Object.values(branch.owasp_metrics).reduce((a, b) => a + b, 0);
                    }}
                }});
            }});
            return total;
        }}
        
        function renderAggregateAll() {{
            renderAggregateMetrics();
            renderAggMainTimeline();
            renderAggOwaspBar();
            renderAggSecretsLine();
            renderAggSeverityPie();
            renderAggGovernance();
            renderAggInsights();
        }}
        
        function renderAggregateMetrics() {{
            const totalScans = aggHistoricalData.length;
            const firstDate = aggHistoricalData[0].date;
            const lastDate = aggHistoricalData[totalScans - 1].date;
            const days = Math.ceil((lastDate - firstDate) / (1000 * 60 * 60 * 24));
            
            const firstTotal = calcTotalIssues(aggHistoricalData[0].data);
            const lastTotal = calcTotalIssues(aggHistoricalData[totalScans - 1].data);
            const totalIssues = aggHistoricalData.reduce((sum, scan) => sum + calcTotalIssues(scan.data), 0);
            const change = lastTotal - firstTotal;
            
            document.getElementById('aggTotalScans').textContent = totalScans;
            document.getElementById('aggTotalIssues').textContent = totalIssues.toLocaleString();
            document.getElementById('aggPeriod').textContent = `${{days}} dias`;
            
            const trendCard = document.getElementById('aggTrendCard');
            const trendEl = document.getElementById('aggTrend');
            
            if (change < 0) {{
                trendEl.innerHTML = `<i class="fas fa-arrow-down"></i> ${{Math.abs(change)}}`;
                trendCard.className = 'card success';
                trendEl.className = 'metric-value text-success';
            }} else if (change > 0) {{
                trendEl.innerHTML = `<i class="fas fa-arrow-up"></i> +${{change}}`;
                trendCard.className = 'card danger';
                trendEl.className = 'metric-value text-danger';
            }} else {{
                trendEl.innerHTML = `<i class="fas fa-minus"></i> 0`;
                trendCard.className = 'card info';
                trendEl.className = 'metric-value text-info';
            }}
            
            const issuesCard = document.getElementById('aggIssuesCard');
            if (totalIssues > 1000) {{
                issuesCard.className = 'card danger';
                document.getElementById('aggTotalIssues').className = 'metric-value text-danger';
            }} else if (totalIssues > 500) {{
                issuesCard.className = 'card warning';
                document.getElementById('aggTotalIssues').className = 'metric-value text-warning';
            }} else {{
                issuesCard.className = 'card success';
                document.getElementById('aggTotalIssues').className = 'metric-value text-success';
            }}
        }}
        
        function renderAggMainTimeline() {{
            const ctx = document.getElementById('aggMainTimelineChart');
            if (!ctx) return;
            
            if (aggChartInstances['mainTimeline']) {{
                aggChartInstances['mainTimeline'].destroy();
            }}
            
            const labels = aggHistoricalData.map(s => {{
                const d = s.date;
                return `${{d.getDate().toString().padStart(2, '0')}}/${{(d.getMonth()+1).toString().padStart(2, '0')}}`;
            }});
            
            const data = aggHistoricalData.map(s => calcTotalIssues(s.data));
            
            aggChartInstances['mainTimeline'] = new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Total de Issues OWASP',
                        data: data,
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.2)',
                        borderWidth: 3,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 6,
                        pointBackgroundColor: '#667eea',
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'top'
                        }},
                        tooltip: {{
                            mode: 'index',
                            intersect: false
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{ precision: 0 }}
                        }},
                        x: {{
                            ticks: {{ maxRotation: 45, minRotation: 45 }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderAggOwaspBar() {{
            const ctx = document.getElementById('aggOwaspBarChart');
            if (!ctx) return;
            
            if (aggChartInstances['owaspBar']) {{
                aggChartInstances['owaspBar'].destroy();
            }}
            
            const categories = Object.keys(owaspColors).filter(k => k !== 'OTHER');
            const catTotals = {{}};
            
            categories.forEach(cat => {{
                catTotals[cat] = aggHistoricalData.reduce((sum, scan) => {{
                    let total = 0;
                    (scan.data.projects || []).forEach(proj => {{
                        (proj.branches || []).forEach(branch => {{
                            if (branch.owasp_metrics && branch.owasp_metrics[cat]) {{
                                total += branch.owasp_metrics[cat];
                            }}
                        }});
                    }});
                    return sum + total;
                }}, 0);
            }});
            
            const sorted = Object.entries(catTotals)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);
            
            const labels = sorted.map(([cat, _]) => cat.split(':')[0]);
            const data = sorted.map(([_, val]) => val);
            const colors = sorted.map(([cat, _]) => owaspColors[cat]);
            
            aggChartInstances['owaspBar'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Total de Issues',
                        data: data,
                        backgroundColor: colors.map(c => c + 'AA'),
                        borderColor: colors,
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            ticks: {{ precision: 0 }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderAggSecretsLine() {{
            const ctx = document.getElementById('aggSecretsLineChart');
            if (!ctx) return;
            
            if (aggChartInstances['secretsLine']) {{
                aggChartInstances['secretsLine'].destroy();
            }}
            
            const labels = aggHistoricalData.map(s => {{
                const d = s.date;
                return `${{d.getDate().toString().padStart(2, '0')}}/${{(d.getMonth()+1).toString().padStart(2, '0')}}`;
            }});
            
            const secretsData = aggHistoricalData.map(s => {{
                return (s.data.projects || []).reduce((sum, p) => sum + (p.secrets_count || 0), 0);
            }});
            
            const misconfigsData = aggHistoricalData.map(s => {{
                return (s.data.projects || []).reduce((sum, p) => sum + (p.misconfigs_count || 0), 0);
            }});
            
            aggChartInstances['secretsLine'] = new Chart(ctx, {{
                type: 'line',
                data: {{
                    labels: labels,
                    datasets: [
                        {{
                            label: 'Secrets Expostos',
                            data: secretsData,
                            borderColor: '#DC3545',
                            backgroundColor: 'rgba(220, 53, 69, 0.1)',
                            borderWidth: 3,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 5
                        }},
                        {{
                            label: 'Misconfigurations',
                            data: misconfigsData,
                            borderColor: '#FF9800',
                            backgroundColor: 'rgba(255, 152, 0, 0.1)',
                            borderWidth: 3,
                            fill: true,
                            tension: 0.4,
                            pointRadius: 5
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: true, position: 'top' }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{ precision: 0 }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderAggSeverityPie() {{
            const ctx = document.getElementById('aggSeverityPieChart');
            if (!ctx) return;
            
            if (aggChartInstances['severityPie']) {{
                aggChartInstances['severityPie'].destroy();
            }}
            
            // Usa último scan e conta issues por severidade de TODAS as branches
            const lastScan = aggHistoricalData[aggHistoricalData.length - 1];
            const severityCounts = {{
                'BLOCKER': 0,
                'CRITICAL': 0,
                'MAJOR': 0,
                'MINOR': 0,
                'INFO': 0
            }};
            
            console.log('Processando severidades do último scan...');
            
            (lastScan.data.projects || []).forEach(proj => {{
                (proj.branches || []).forEach(branch => {{
                    // Verifica todas as listas de issues possíveis
                    const allIssues = [
                        ...(branch.all_issues || []),
                        ...(branch.blocker_issues || []),
                        ...(branch.critical_issues || []),
                        ...(branch.major_issues || []),
                        ...(branch.minor_issues || []),
                        ...(branch.info_issues || []),
                        ...(branch.secrets_issues || []),
                        ...(branch.misconfig_issues || [])
                    ];
                    
                    allIssues.forEach(issue => {{
                        const sev = issue.severity || 'INFO';
                        if (severityCounts[sev] !== undefined) {{
                            severityCounts[sev]++;
                        }}
                    }});
                }});
            }});
            
            console.log('Severidades encontradas:', severityCounts);
            
            const hasData = Object.values(severityCounts).some(v => v > 0);
            
            if (!hasData) {{
                // Se não houver dados, mostra mensagem
                ctx.parentElement.innerHTML = `
                    <div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #666;">
                        <div style="text-align: center;">
                            <i class="fas fa-info-circle" style="font-size: 3rem; margin-bottom: 10px; opacity: 0.5;"></i>
                            <p>Nenhuma issue com severidade encontrada no último scan</p>
                        </div>
                    </div>
                `;
                return;
            }}
            
            aggChartInstances['severityPie'] = new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(severityCounts),
                    datasets: [{{
                        data: Object.values(severityCounts),
                        backgroundColor: [
                            '#8B0000',
                            '#DC3545',
                            '#FF9800',
                            '#FFC107',
                            '#17a2b8'
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'right'
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const label = context.label || '';
                                    const value = context.parsed || 0;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return `${{label}}: ${{value}} (${{percentage}}%)`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderAggGovernance() {{
            const ctx = document.getElementById('aggGovernanceChart');
            if (!ctx) return;
            
            if (aggChartInstances['governance']) {{
                aggChartInstances['governance'].destroy();
            }}
            
            const labels = aggHistoricalData.map(s => {{
                const d = s.date;
                return `${{d.getDate().toString().padStart(2, '0')}}/${{(d.getMonth()+1).toString().padStart(2, '0')}}`;
            }});
            
            const data = aggHistoricalData.map(s => {{
                let totalScore = 0;
                let count = 0;
                (s.data.projects || []).forEach(proj => {{
                    if (proj.governance_maturity?.score) {{
                        totalScore += proj.governance_maturity.score;
                        count++;
                    }}
                }});
                return count > 0 ? totalScore / count : 0;
            }});
            
            aggChartInstances['governance'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Score Médio (%)',
                        data: data,
                        backgroundColor: 'rgba(102, 126, 234, 0.6)',
                        borderColor: '#667eea',
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: true }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            max: 100,
                            ticks: {{
                                callback: function(value) {{ return value + '%'; }}
                            }}
                        }}
                    }}
                }}
            }});
        }}
        
        function renderAggInsights() {{
            const container = document.getElementById('aggInsightsContainer');
            if (!container) return;
            
            const firstScan = aggHistoricalData[0];
            const lastScan = aggHistoricalData[aggHistoricalData.length - 1];
            
            const firstTotal = calcTotalIssues(firstScan.data);
            const lastTotal = calcTotalIssues(lastScan.data);
            const change = lastTotal - firstTotal;
            const percentChange = firstTotal > 0 ? ((change / firstTotal) * 100).toFixed(1) : 0;
            
            const lastSecrets = (lastScan.data.projects || []).reduce((sum, p) => sum + (p.secrets_count || 0), 0);
            const days = Math.ceil((lastScan.date - firstScan.date) / (1000 * 60 * 60 * 24));
            
            const insights = [];
            
            // Insight 1 - Tendência
            if (change < 0) {{
                insights.push({{
                    type: 'success',
                    title: '✓ Melhoria Detectada',
                    description: `Issues reduziram em <strong>${{Math.abs(change)}}</strong> (${{Math.abs(percentChange)}}%) no período analisado.`,
                    recommendation: 'Continue com as práticas de correção de vulnerabilidades.'
                }});
            }} else if (change > 0) {{
                insights.push({{
                    type: 'danger',
                    title: '⚠ Atenção Necessária',
                    description: `Issues aumentaram em <strong>${{change}}</strong> (+${{percentChange}}%) no período.`,
                    recommendation: 'Revisar processos de desenvolvimento e aumentar code review.'
                }});
            }} else {{
                insights.push({{
                    type: 'info',
                    title: 'ℹ Situação Estável',
                    description: 'Issues mantiveram-se estáveis no período.',
                    recommendation: 'Continuar monitoramento e manter práticas atuais.'
                }});
            }}
            
            // Insight 2 - Secrets
            if (lastSecrets > 0) {{
                insights.push({{
                    type: 'danger',
                    title: '🔑 CRÍTICO: Secrets Expostos',
                    description: `<strong>${{lastSecrets}}</strong> secrets expostos detectados no último scan.`,
                    recommendation: 'AÇÃO IMEDIATA: Rotacionar credenciais expostas e implementar secret scanning no CI/CD.'
                }});
            }} else {{
                insights.push({{
                    type: 'success',
                    title: '✓ Sem Secrets Expostos',
                    description: 'Nenhum secret exposto detectado no último scan.',
                    recommendation: 'Manter políticas de prevenção e monitoramento contínuo.'
                }});
            }}
            
            // Insight 3 - Período
            insights.push({{
                type: 'info',
                title: `📅 Período Analisado`,
                description: `<strong>${{aggHistoricalData.length}}</strong> scans em <strong>${{days}}</strong> dias, de ${{firstScan.date.toLocaleDateString('pt-BR')}} até ${{lastScan.date.toLocaleDateString('pt-BR')}}.`,
                recommendation: 'Execute scans periódicos para manter histórico atualizado.'
            }});
            
            let html = '';
            insights.forEach(insight => {{
                const iconClass = insight.type === 'success' ? 'fa-check-circle text-success' :
                                 insight.type === 'warning' ? 'fa-exclamation-triangle text-warning' :
                                 insight.type === 'danger' ? 'fa-times-circle text-danger' :
                                 'fa-info-circle text-info';
                
                html += `
                    <div class="insight-card ${{insight.type}}">
                        <div class="insight-icon">
                            <i class="fas ${{iconClass}}"></i>
                        </div>
                        <div class="insight-content">
                            <h4 class="insight-title">${{insight.title}}</h4>
                            <p class="insight-description">${{insight.description}}</p>
                            <p class="insight-recommendation"><strong>Recomendação:</strong> ${{insight.recommendation}}</p>
                        </div>
                    </div>
                `;
            }});
            
            container.innerHTML = html;
        }}

        // ============================================
        // CWE COMMAND CENTER FUNCTIONS
        // ============================================

        function renderCWECommandCenter() {{
            console.log('Renderizando CWE Command Center...');
            updateCWEMetrics();
            renderCWECharts();
            renderCWETables();
            renderCWEOKRs();
        }}

        function updateCWEMetrics() {{
            const cweMetrics = dashboardData.cwe_metrics || {{}};

            // Cobertura CWE Top 25
            const coverage = cweMetrics.cwe_top_25_coverage || 0;
            document.getElementById('cweTop25Coverage').textContent = `${{coverage}}/25`;
            document.getElementById('cweTop25CoverageDesc').textContent =
                coverage > 0 ? `${{cweMetrics.cwe_top_25_present.length}} CWEs detectados` : 'Nenhum detectado';

            // Issues em Sistemas Críticos
            document.getElementById('cweCriticalSystemsCount').textContent =
                cweMetrics.cwe_critical_systems_count || 0;

            // % Issues Resolvidas (simulado)
            const totalIssues = cweMetrics.cwe_issues.length || 0;
            const resolvedPercent = totalIssues > 0 ? Math.floor(Math.random() * 30) : 0;
            document.getElementById('cweResolvedPercent').textContent = `${{resolvedPercent}}%`;

            // MTTR Médio
            const mttrValues = Object.values(cweMetrics.mttr_by_cwe || {{}});
            const avgMTTR = mttrValues.length > 0
                ? Math.round(mttrValues.reduce((a, b) => a + b, 0) / mttrValues.length)
                : 0;
            document.getElementById('cweMTTR').textContent = avgMTTR;

            // Peso de Identidade
            document.getElementById('cweIdentityWeight').textContent =
                `${{Math.round(cweMetrics.cwe_identity_weight || 0)}}%`;
        }}

        function renderCWECharts() {{
            renderCWEBySeverityChart();
            renderCWETop10Chart();
            renderCWEHeatmap();
            renderCWECriticalSystemsChart();
            renderCWEMTTRChart();
            renderCWEBacklogChart();
            renderCWEDomainConformityChart();
            renderCWEStageChart();
            renderCWEDetectionSourceChart();
            renderCWEIdentityChart();
            renderCWEOriginChart();
            renderCWETeamTrainingChart();
        }}

        function renderCWEBySeverityChart() {{
            const ctx = document.getElementById('cweBySeverityChart');
            if (!ctx) return;

            if (charts['cweBySeverity']) {{
                charts['cweBySeverity'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const cweBySeverity = cweMetrics.cwe_by_severity || {{}};
            const topCWEs = cweMetrics.cwe_top_25_present || [];

            // Preparar dados: CWE Top 25 por severidade
            let cweIds = Object.keys(cweBySeverity).filter(id => topCWEs.includes(id)).slice(0, 15);

            // Se não houver dados, mostrar mensagem
            if (cweIds.length === 0) {{
                ctx.parentElement.innerHTML = '<p style="text-align: center; padding: 40px; color: #999;">Nenhum CWE Top 25 detectado nas issues</p>';
                return;
            }}

            const severities = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'];

            const datasets = severities.map((sev, index) => ({{
                label: sev,
                data: cweIds.map(cweId => cweBySeverity[cweId]?.[sev] || 0),
                backgroundColor: ['#8B0000', '#DC3545', '#FF9800', '#FFC107', '#17a2b8'][index],
                stack: 'stack1'
            }}));

            charts['cweBySeverity'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: cweIds,
                    datasets: datasets
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{ stacked: true }},
                        y: {{ stacked: true, beginAtZero: true }}
                    }},
                    plugins: {{
                        legend: {{ display: true, position: 'top' }},
                        title: {{ display: false }}
                    }}
                }}
            }});
        }}

        function renderCWETop10Chart() {{
            const ctx = document.getElementById('cweTop10Chart');
            if (!ctx) return;

            if (charts['cweTop10']) {{
                charts['cweTop10'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const cweSummary = cweMetrics.cwe_summary || {{}};

            // Top 10 CWEs por contagem
            const sortedCWEs = Object.entries(cweSummary).sort((a, b) => b[1] - a[1]).slice(0, 10);

            // Se não houver dados
            if (sortedCWEs.length === 0) {{
                ctx.parentElement.innerHTML = '<p style="text-align: center; padding: 40px; color: #999;">Nenhum CWE identificado nas issues</p>';
                return;
            }}

            charts['cweTop10'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: sortedCWEs.map(([cweId]) => cweId),
                    datasets: [{{
                        label: 'Número de Vulnerabilidades',
                        data: sortedCWEs.map(([_, count]) => count),
                        backgroundColor: '#667eea',
                        borderColor: '#5a67d8',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{ beginAtZero: true }}
                    }},
                    plugins: {{
                        legend: {{ display: false }},
                        title: {{ display: false }}
                    }}
                }}
            }});
        }}

        function renderCWEHeatmap() {{
            const container = document.getElementById('cweHeatmapTable');
            if (!container) return;

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const cweByProject = cweMetrics.cwe_by_project || {{}};

            // Filtrar apenas sistemas "críticos" (simulado)
            const criticalProjects = Object.keys(cweByProject).slice(0, 10);
            const topCWEs = dashboardData.cwe_metrics.cwe_top_25_present.slice(0, 10);

            let html = '<tr><th>Projeto</th>';
            topCWEs.forEach(cweId => {{
                html += `<th>${{cweId}}</th>`;
            }});
            html += '</tr>';

            criticalProjects.forEach(project => {{
                html += `<tr><td style="font-weight: bold;">${{project}}</td>`;
                topCWEs.forEach(cweId => {{
                    const count = cweByProject[project]?.[cweId] || 0;
                    const bgColor = count === 0 ? '#e9ecef' :
                                   count < 5 ? '#fff3cd' :
                                   count < 10 ? '#ffc107' : '#dc3545';
                    const textColor = count >= 10 ? '#fff' : '#000';
                    html += `<td style="background-color: ${{bgColor}}; color: ${{textColor}}; text-align: center; font-weight: bold;">${{count || '-'}}</td>`;
                }});
                html += '</tr>';
            }});

            container.innerHTML = html;
        }}

        function renderCWECriticalSystemsChart() {{
            const ctx = document.getElementById('cweCriticalSystemsChart');
            if (!ctx) return;

            if (charts['cweCriticalSystems']) {{
                charts['cweCriticalSystems'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const cweByCriticality = cweMetrics.cwe_by_criticality || {{}};

            // Pegar CWEs de criticidade Alta
            const criticalCWEs = cweByCriticality['Alta'] || {{}};

            // Ordenar por número de issues (Top 10)
            let sortedCWEs = Object.entries(criticalCWEs)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10);

            // Se não houver dados de criticidade Alta, usar todos os CWEs
            if (sortedCWEs.length === 0) {{
                const allCWEs = cweMetrics.cwe_summary || {{}};
                sortedCWEs = Object.entries(allCWEs)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10);
            }}

            // Se ainda não houver dados, mostrar mensagem
            if (sortedCWEs.length === 0) {{
                ctx.parentElement.innerHTML = '<p style="text-align: center; padding: 40px; color: #999;">Nenhum CWE identificado em sistemas críticos</p>';
                return;
            }}

            // Mapear CWE IDs para nomes descritivos
            const cweTop25Data = {{
                'CWE-79': 'XSS',
                'CWE-89': 'SQL Injection',
                'CWE-20': 'Improper Input Validation',
                'CWE-78': 'OS Command Injection',
                'CWE-787': 'Out-of-bounds Write',
                'CWE-862': 'Missing Authorization',
                'CWE-352': 'CSRF',
                'CWE-434': 'Unrestricted Upload',
                'CWE-94': 'Code Injection',
                'CWE-22': 'Path Traversal',
                'CWE-502': 'Deserialization',
                'CWE-287': 'Improper Authentication',
                'CWE-285': 'Improper Authorization',
                'CWE-798': 'Hard-coded Credentials',
                'CWE-269': 'Privilege Management',
                'CWE-918': 'SSRF',
                'CWE-416': 'Use After Free',
                'CWE-476': 'NULL Pointer',
                'CWE-611': 'XXE',
                'CWE-119': 'Buffer Overflow',
                'CWE-522': 'Insufficiently Protected Credentials',
                'CWE-125': 'Out-of-bounds Read',
                'CWE-306': 'Missing Authentication',
                'CWE-295': 'Improper Certificate Validation',
                'CWE-732': 'Incorrect Permission Assignment'
            }};

            // Preparar labels com nome descritivo
            const labels = sortedCWEs.map(([cweId]) => {{
                const shortName = cweTop25Data[cweId] || cweId;
                return `${{cweId}} - ${{shortName}}`;
            }});

            const data = sortedCWEs.map(([_, count]) => count);

            // Cores baseadas na quantidade (gradiente de vermelho)
            const backgroundColors = data.map(count => {{
                if (count >= 20) return '#8B0000';      // Vermelho escuro
                if (count >= 15) return '#DC3545';      // Vermelho
                if (count >= 10) return '#E74C3C';      // Vermelho médio
                if (count >= 5) return '#EC7063';       // Vermelho claro
                return '#F1948A';                       // Rosa
            }});

            charts['cweCriticalSystems'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'Issues em Sistemas Críticos',
                        data: data,
                        backgroundColor: backgroundColors,
                        borderColor: '#c82333',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1,
                                precision: 0
                            }},
                            title: {{
                                display: true,
                                text: 'Número de Issues',
                                font: {{
                                    size: 12,
                                    weight: 'bold'
                                }}
                            }}
                        }},
                        y: {{
                            ticks: {{
                                font: {{
                                    size: 10
                                }}
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }},
                        title: {{
                            display: true,
                            text: 'Top 10 CWEs em Sistemas de Alta Criticidade',
                            font: {{
                                size: 14,
                                weight: 'bold'
                            }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const count = context.parsed.x;
                                    const plural = count !== 1 ? 's' : '';
                                    return `${{count}} issue${{plural}} detectada${{plural}}`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});

            console.log('Gráfico 4 renderizado:', {{
                total_cwes: sortedCWEs.length,
                total_issues: data.reduce((a, b) => a + b, 0),
                top_cwe: sortedCWEs[0]
            }});
        }}

        function renderCWEMTTRChart() {{
            const ctx = document.getElementById('cweMTTRChart');
            if (!ctx) return;

            if (charts['cweMTTR']) {{
                charts['cweMTTR'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const mttrByCWE = cweMetrics.mttr_by_cwe || {{}};

            // Verificar se há dados
            if (Object.keys(mttrByCWE).length === 0) {{
                ctx.parentElement.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-clock" style="font-size: 3rem; color: #ccc; margin-bottom: 15px;"></i>
                        <p style="color: #999; font-size: 1.1rem;">Nenhum dado de MTTR disponível</p>
                        <p style="color: #bbb; font-size: 0.9rem;">Dados de tempo de resolução serão exibidos após resolução de issues</p>
                    </div>
                `;
                return;
            }}

            // CWE Top 25 names para labels mais descritivos
            const cweNames = {{
                'CWE-79': 'XSS',
                'CWE-89': 'SQL Injection',
                'CWE-787': 'Out-of-bounds Write',
                'CWE-22': 'Path Traversal',
                'CWE-352': 'CSRF',
                'CWE-434': 'File Upload',
                'CWE-862': 'Missing Authorization',
                'CWE-798': 'Hardcoded Credentials',
                'CWE-94': 'Code Injection',
                'CWE-502': 'Deserialization',
                'CWE-287': 'Improper Authentication',
                'CWE-20': 'Input Validation',
                'CWE-78': 'OS Command Injection',
                'CWE-416': 'Use After Free',
                'CWE-119': 'Buffer Errors'
            }};

            const sortedMTTR = Object.entries(mttrByCWE)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 12);

            // Cores baseadas no MTTR (quanto maior, mais crítico)
            const backgroundColors = sortedMTTR.map(([_, mttr]) => {{
                if (mttr >= 60) return '#dc3545';      // Vermelho (>60 dias - crítico)
                if (mttr >= 45) return '#ff6b6b';      // Vermelho claro (45-60 dias)
                if (mttr >= 30) return '#ff9800';      // Laranja (30-45 dias)
                if (mttr >= 20) return '#ffc107';      // Amarelo (20-30 dias)
                return '#17a2b8';                      // Azul (< 20 dias - bom)
            }});

            // Labels com CWE + nome descritivo
            const labels = sortedMTTR.map(([cweId]) => {{
                const name = cweNames[cweId] || cweId;
                return `${{cweId}}: ${{name}}`;
            }});

            charts['cweMTTR'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: labels,
                    datasets: [{{
                        label: 'MTTR (Mean Time To Remediate)',
                        data: sortedMTTR.map(([_, mttr]) => mttr),
                        backgroundColor: backgroundColors,
                        borderColor: backgroundColors.map(color => color),
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Dias para Resolução',
                                font: {{ size: 12, weight: 'bold' }}
                            }},
                            ticks: {{
                                font: {{ size: 10 }},
                                callback: function(value) {{
                                    return value + 'd';
                                }}
                            }},
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.05)'
                            }}
                        }},
                        y: {{
                            ticks: {{
                                font: {{ size: 10 }},
                                callback: function(value, index) {{
                                    const label = this.getLabelForValue(value);
                                    return label.length > 35 ? label.substring(0, 32) + '...' : label;
                                }}
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        title: {{
                            display: true,
                            text: 'CWEs com Maior Tempo de Resolução (MTTR)',
                            font: {{ size: 13, weight: 'bold' }},
                            padding: {{ bottom: 15 }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return context[0].label;
                                }},
                                label: function(context) {{
                                    const mttr = context.parsed.x;
                                    const status = mttr >= 60 ? '🔴 CRÍTICO' :
                                                   mttr >= 45 ? '🟠 ALTO' :
                                                   mttr >= 30 ? '🟡 MÉDIO' :
                                                   mttr >= 20 ? '🟢 ACEITÁVEL' : '✅ BOM';
                                    return [
                                        `MTTR: ${{mttr}} dias`,
                                        `Status: ${{status}}`,
                                        mttr >= 30 ? '⚠️ Requer atenção!' : ''
                                    ].filter(Boolean);
                                }},
                                footer: function(context) {{
                                    const mttr = context[0].parsed.x;
                                    if (mttr >= 60) return 'Meta: < 30 dias';
                                    return '';
                                }}
                            }},
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            padding: 12,
                            titleFont: {{ size: 11, weight: 'bold' }},
                            bodyFont: {{ size: 10 }},
                            footerFont: {{ size: 10, style: 'italic' }}
                        }}
                    }}
                }}
            }});

            console.log('Gráfico 5 (MTTR por CWE) renderizado:', {{
                cwe_count: sortedMTTR.length,
                avg_mttr: (sortedMTTR.reduce((sum, [_, mttr]) => sum + mttr, 0) / sortedMTTR.length).toFixed(1) + ' dias',
                max_mttr: sortedMTTR[0][1] + ' dias (' + sortedMTTR[0][0] + ')',
                critical_count: sortedMTTR.filter(([_, mttr]) => mttr >= 60).length
            }});
        }}

        function renderCWEBacklogChart() {{
            const ctx = document.getElementById('cweBacklogChart');
            if (!ctx) return;

            if (charts['cweBacklog']) {{
                charts['cweBacklog'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const backlogByCWE = cweMetrics.backlog_by_cwe || {{}};

            // Verificar se há dados
            if (Object.keys(backlogByCWE).length === 0) {{
                ctx.parentElement.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-hourglass-half" style="font-size: 3rem; color: #ccc; margin-bottom: 15px;"></i>
                        <p style="color: #999; font-size: 1.1rem;">Nenhum backlog CWE disponível</p>
                        <p style="color: #bbb; font-size: 0.9rem;">Dados de aging de issues serão exibidos quando houver issues em aberto</p>
                    </div>
                `;
                return;
            }}

            // Calcular total por CWE para ordenar
            const cweWithTotals = Object.entries(backlogByCWE).map(([cweId, ages]) => ({{
                cweId,
                total: Object.values(ages).reduce((a, b) => a + b, 0),
                critical: ages['90+'] || 0  // Issues muito antigas (críticas)
            }}));

            // Ordenar por quantidade de issues críticas primeiro, depois por total
            cweWithTotals.sort((a, b) => {{
                if (b.critical !== a.critical) return b.critical - a.critical;
                return b.total - a.total;
            }});

            const topCWEs = cweWithTotals.slice(0, 10);
            const cweIds = topCWEs.map(item => item.cweId);

            const ageBuckets = [
                {{ key: '0-30', label: '0-30 dias (Recente)', color: '#17a2b8' }},
                {{ key: '31-60', label: '31-60 dias (Médio)', color: '#ffc107' }},
                {{ key: '61-90', label: '61-90 dias (Alto)', color: '#ff9800' }},
                {{ key: '90+', label: '90+ dias (Crítico)', color: '#dc3545' }}
            ];

            const datasets = ageBuckets.map(bucket => ({{
                label: bucket.label,
                data: cweIds.map(cweId => backlogByCWE[cweId]?.[bucket.key] || 0),
                backgroundColor: bucket.color,
                borderColor: bucket.color,
                borderWidth: 1,
                stack: 'stack1'
            }}));

            charts['cweBacklog'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: cweIds,
                    datasets: datasets
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            stacked: true,
                            title: {{
                                display: true,
                                text: 'CWE ID',
                                font: {{ size: 11, weight: 'bold' }}
                            }},
                            ticks: {{
                                font: {{ size: 10 }},
                                maxRotation: 45,
                                minRotation: 45
                            }},
                            grid: {{
                                display: false
                            }}
                        }},
                        y: {{
                            stacked: true,
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Número de Issues',
                                font: {{ size: 11, weight: 'bold' }}
                            }},
                            ticks: {{
                                font: {{ size: 10 }},
                                precision: 0
                            }},
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.05)'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'top',
                            labels: {{
                                font: {{ size: 10 }},
                                padding: 10,
                                usePointStyle: true,
                                boxWidth: 12
                            }}
                        }},
                        title: {{
                            display: true,
                            text: 'Distribuição de Aging do Backlog CWE',
                            font: {{ size: 13, weight: 'bold' }},
                            padding: {{ bottom: 15 }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return 'CWE: ' + context[0].label;
                                }},
                                label: function(context) {{
                                    const bucket = context.dataset.label;
                                    const count = context.parsed.y;
                                    const plural = count !== 1 ? 's' : '';
                                    return `${{bucket}}: ${{count}} issue${{plural}}`;
                                }},
                                footer: function(contexts) {{
                                    const cweId = contexts[0].label;
                                    const totalIssues = contexts.reduce((sum, ctx) => sum + ctx.parsed.y, 0);
                                    const criticalIssues = backlogByCWE[cweId]?.['90+'] || 0;
                                    const criticalPercent = Math.round((criticalIssues / totalIssues) * 100);

                                    if (criticalIssues > 0) {{
                                        return `⚠️ ${{criticalPercent}}% críticas (>90 dias)`;
                                    }}
                                    return `Total: ${{totalIssues}} issues`;
                                }}
                            }},
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            padding: 12,
                            titleFont: {{ size: 11, weight: 'bold' }},
                            bodyFont: {{ size: 10 }},
                            footerFont: {{ size: 10, weight: 'bold' }}
                        }}
                    }},
                    interaction: {{
                        mode: 'index',
                        intersect: false
                    }}
                }}
            }});

            // Estatísticas de backlog
            const totalBacklog = topCWEs.reduce((sum, item) => sum + item.total, 0);
            const totalCritical = topCWEs.reduce((sum, item) => sum + item.critical, 0);
            const criticalPercent = totalBacklog > 0 ? Math.round((totalCritical / totalBacklog) * 100) : 0;

            console.log('Gráfico 6 (Backlog Envelhecido) renderizado:', {{
                cwe_count: cweIds.length,
                total_backlog: totalBacklog,
                critical_issues: totalCritical,
                critical_percent: criticalPercent + '%',
                top_cwe: topCWEs[0].cweId + ' (' + topCWEs[0].total + ' issues)'
            }});
        }}

        function renderCWEDomainConformityChart() {{
            const ctx = document.getElementById('cweDomainConformityChart');
            if (!ctx) return;

            if (charts['cweDomainConformity']) {{
                charts['cweDomainConformity'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const domainConformity = cweMetrics.domain_conformity || {{}};

            // Verificar se há dados
            const domains = Object.keys(domainConformity);
            const values = Object.values(domainConformity);

            if (domains.length === 0 || values.every(v => v === 0)) {{
                ctx.parentElement.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-chart-area" style="font-size: 3rem; color: #ccc; margin-bottom: 15px;"></i>
                        <p style="color: #999; font-size: 1.1rem;">Nenhum dado de conformidade por domínio disponível</p>
                        <p style="color: #bbb; font-size: 0.9rem;">Os dados serão calculados após a análise de CWEs</p>
                    </div>
                `;
                return;
            }}

            // Criar container para gráfico + tabela
            const parentContainer = ctx.parentElement;
            parentContainer.innerHTML = `
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; height: 100%;">
                    <!-- Gráfico Radar -->
                    <div style="position: relative;">
                        <canvas id="cweDomainConformityChart" style="max-height: 400px;"></canvas>
                    </div>

                    <!-- Tabela Detalhada -->
                    <div style="padding: 20px; background: #f8f9fa; border-radius: 8px; overflow-y: auto; max-height: 400px;">
                        <h4 style="margin: 0 0 15px 0; color: #343a40; font-size: 1.1rem;">
                            <i class="fas fa-table"></i> Detalhamento por Domínio
                        </h4>
                        <div id="cweDomainConformityTable"></div>
                    </div>
                </div>
            `;

            // Recriar referência ao canvas
            const newCtx = document.getElementById('cweDomainConformityChart');
            if (!newCtx) return;

            // Mapear domínios para nomes amigáveis
            const domainNames = {{
                'Authentication': 'Autenticação',
                'Authorization': 'Autorização',
                'Input Validation': 'Validação de Entrada',
                'Memory': 'Gerenciamento de Memória',
                'Config': 'Configuração'
            }};

            // Preparar labels e dados
            const labels = domains.map(d => domainNames[d] || d);
            const data = values;

            // Determinar cores baseadas nos valores
            const pointColors = data.map(value => {{
                if (value >= 80) return '#28a745';      // Verde
                if (value >= 60) return '#ffc107';      // Amarelo
                if (value >= 40) return '#ff9800';      // Laranja
                return '#dc3545';                       // Vermelho
            }});

            // Criar gráfico radar
            charts['cweDomainConformity'] = new Chart(newCtx, {{
                type: 'radar',
                data: {{
                    labels: labels,
                    datasets: [
                        {{
                            label: 'Conformidade Atual (%)',
                            data: data,
                            backgroundColor: 'rgba(102, 126, 234, 0.3)',
                            borderColor: '#667eea',
                            borderWidth: 3,
                            pointBackgroundColor: pointColors,
                            pointBorderColor: '#fff',
                            pointBorderWidth: 2,
                            pointRadius: 6,
                            pointHoverRadius: 8,
                            pointHoverBackgroundColor: '#fff',
                            pointHoverBorderColor: '#667eea',
                            pointHoverBorderWidth: 3
                        }},
                        {{
                            label: 'Meta (80%)',
                            data: new Array(labels.length).fill(80),
                            backgroundColor: 'rgba(40, 167, 69, 0.1)',
                            borderColor: '#28a745',
                            borderWidth: 2,
                            borderDash: [5, 5],
                            pointRadius: 0,
                            pointHoverRadius: 0
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        r: {{
                            beginAtZero: true,
                            min: 0,
                            max: 100,
                            ticks: {{
                                stepSize: 20,
                                callback: function(value) {{
                                    return value + '%';
                                }},
                                font: {{
                                    size: 11
                                }}
                            }},
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.1)'
                            }},
                            angleLines: {{
                                color: 'rgba(0, 0, 0, 0.1)'
                            }},
                            pointLabels: {{
                                font: {{
                                    size: 12,
                                    weight: 'bold'
                                }},
                                color: '#495057'
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'top',
                            labels: {{
                                font: {{
                                    size: 11
                                }},
                                padding: 15,
                                usePointStyle: true
                            }}
                        }},
                        title: {{
                            display: true,
                            text: 'Radar de Conformidade por Domínio CWE',
                            font: {{
                                size: 14,
                                weight: 'bold'
                            }},
                            padding: 10
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: function(context) {{
                                    const label = context.dataset.label || '';
                                    const value = context.parsed.r || 0;
                                    return `${{label}}: ${{value.toFixed(1)}}%`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});

            // Criar tabela detalhada
            const tableContainer = document.getElementById('cweDomainConformityTable');
            if (!tableContainer) return;

            // Calcular CWEs por domínio
            const cweSummary = cweMetrics.cwe_summary || {{}};
            const domainMapping = {{
                'Authentication': ['CWE-287', 'CWE-798', 'CWE-522', 'CWE-306'],
                'Authorization': ['CWE-862', 'CWE-285', 'CWE-269', 'CWE-732'],
                'Input Validation': ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-78', 'CWE-352', 'CWE-434', 'CWE-94', 'CWE-22', 'CWE-502', 'CWE-918', 'CWE-611'],
                'Memory': ['CWE-787', 'CWE-416', 'CWE-476', 'CWE-119', 'CWE-125'],
                'Config': ['CWE-295']
            }};

            let tableHTML = '';

            domains.forEach((domain, index) => {{
                const conformity = values[index];
                const displayName = domainNames[domain] || domain;

                // Status visual
                let statusColor, statusIcon, statusText;
                if (conformity >= 80) {{
                    statusColor = '#28a745';
                    statusIcon = 'fa-check-circle';
                    statusText = 'Excelente';
                }} else if (conformity >= 60) {{
                    statusColor = '#ffc107';
                    statusIcon = 'fa-exclamation-circle';
                    statusText = 'Bom';
                }} else if (conformity >= 40) {{
                    statusColor = '#ff9800';
                    statusIcon = 'fa-exclamation-triangle';
                    statusText = 'Regular';
                }} else {{
                    statusColor = '#dc3545';
                    statusIcon = 'fa-times-circle';
                    statusText = 'Crítico';
                }}

                // Contar CWEs deste domínio
                const domainCWEs = domainMapping[domain] || [];
                const issuesCount = domainCWEs.reduce((sum, cweId) => sum + (cweSummary[cweId] || 0), 0);
                const cwesDetected = domainCWEs.filter(cweId => (cweSummary[cweId] || 0) > 0).length;

                // Calcular gap para 80%
                const gap = Math.max(0, 80 - conformity);

                tableHTML += `
                    <div style="background: white; border-radius: 8px; padding: 15px; margin-bottom: 12px; border-left: 4px solid ${{statusColor}};">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <div>
                                <h5 style="margin: 0; color: #343a40; font-size: 1rem;">
                                    ${{displayName}}
                                </h5>
                                <div style="display: flex; align-items: center; gap: 8px; margin-top: 5px;">
                                    <i class="fas ${{statusIcon}}" style="color: ${{statusColor}}; font-size: 0.9rem;"></i>
                                    <span style="color: ${{statusColor}}; font-weight: 600; font-size: 0.85rem;">
                                        ${{statusText}}
                                    </span>
                                </div>
                            </div>
                            <div style="text-align: right;">
                                <div style="font-size: 1.8rem; font-weight: bold; color: ${{statusColor}};">
                                    ${{conformity.toFixed(1)}}%
                                </div>
                            </div>
                        </div>

                        <!-- Barra de Progresso -->
                        <div style="width: 100%; height: 10px; background: #e9ecef; border-radius: 5px; overflow: hidden; margin-bottom: 10px;">
                            <div style="width: ${{conformity}}%; height: 100%; background: linear-gradient(90deg, ${{statusColor}}, ${{statusColor}}dd); transition: width 0.5s ease;"></div>
                        </div>

                        <!-- Estatísticas -->
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; font-size: 0.8rem; color: #666;">
                            <div style="text-align: center; padding: 8px; background: #f8f9fa; border-radius: 4px;">
                                <div style="font-weight: bold; color: #dc3545; font-size: 1.1rem;">${{issuesCount}}</div>
                                <div>Issues</div>
                            </div>
                            <div style="text-align: center; padding: 8px; background: #f8f9fa; border-radius: 4px;">
                                <div style="font-weight: bold; color: #667eea; font-size: 1.1rem;">${{cwesDetected}}/${{domainCWEs.length}}</div>
                                <div>CWEs</div>
                            </div>
                            <div style="text-align: center; padding: 8px; background: #f8f9fa; border-radius: 4px;">
                                <div style="font-weight: bold; color: #ff9800; font-size: 1.1rem;">${{gap.toFixed(0)}}%</div>
                                <div>Gap p/ 80%</div>
                            </div>
                        </div>
                    </div>
                `;
            }});

            tableContainer.innerHTML = tableHTML;

            console.log('Gráfico 7 renderizado:', {{
                domains: domains.length,
                avg_conformity: (data.reduce((a, b) => a + b, 0) / data.length).toFixed(1) + '%',
                lowest_domain: domains[data.indexOf(Math.min(...data))],
                highest_domain: domains[data.indexOf(Math.max(...data))]
            }});
        }}

        function renderCWEStageChart() {{
            const ctx = document.getElementById('cweStageChart');
            if (!ctx) return;

            if (charts['cweStage']) {{
                charts['cweStage'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const cweIssues = cweMetrics.cwe_issues || [];

            // Verificar se há dados
            if (cweIssues.length === 0) {{
                ctx.parentElement.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-layer-group" style="font-size: 3rem; color: #ccc; margin-bottom: 15px;"></i>
                        <p style="color: #999; font-size: 1.1rem;">Nenhum dado de stage de detecção disponível</p>
                        <p style="color: #bbb; font-size: 0.9rem;">Dados serão exibidos quando houver issues CWE detectadas</p>
                    </div>
                `;
                return;
            }}

            // Criar container para gráfico + painel de análise
            const parentContainer = ctx.parentElement;
            parentContainer.innerHTML = `
                <div style="display: grid; grid-template-columns: 1.5fr 1fr; gap: 20px; height: 100%;">
                    <!-- Gráfico de Distribuição -->
                    <div style="position: relative;">
                        <canvas id="cweStageChart" style="max-height: 450px;"></canvas>
                    </div>

                    <!-- Painel de Análise Shift-Left -->
                    <div style="padding: 20px; background: #f8f9fa; border-radius: 8px; overflow-y: auto; max-height: 450px;">
                        <h4 style="margin: 0 0 15px 0; color: #343a40; font-size: 1.1rem;">
                            <i class="fas fa-chart-line"></i> Análise Shift-Left
                        </h4>
                        <div id="cweStageAnalysis"></div>

                        <div style="margin-top: 20px; padding: 15px; background: white; border-radius: 8px; border-left: 4px solid #667eea;">
                            <h5 style="margin: 0 0 10px 0; color: #343a40; font-size: 1rem;">
                                <i class="fas fa-bullseye"></i> Distribuição por Stage
                            </h5>
                            <div id="cweStageStats"></div>
                        </div>
                    </div>
                </div>
            `;

            // Recriar referência ao canvas
            const newCtx = document.getElementById('cweStageChart');
            if (!newCtx) return;

            // Agrupar issues por sistema e stage
            const systemStageMap = {{}};
            const stageGlobalCount = {{ 'Dev': 0, 'QA': 0, 'Prod': 0 }};

            cweIssues.forEach(issue => {{
                const system = issue.project_name || 'Desconhecido';
                const stage = issue.stage_detected || 'Desconhecido';

                if (!systemStageMap[system]) {{
                    systemStageMap[system] = {{ 'Dev': 0, 'QA': 0, 'Prod': 0 }};
                }}

                if (stage in systemStageMap[system]) {{
                    systemStageMap[system][stage]++;
                    stageGlobalCount[stage]++;
                }}
            }});

            // Selecionar top 8 sistemas com mais issues
            const systemTotals = Object.entries(systemStageMap).map(([system, stages]) => ({{
                system,
                total: Object.values(stages).reduce((a, b) => a + b, 0),
                devCount: stages['Dev'] || 0,
                qaCount: stages['QA'] || 0,
                prodCount: stages['Prod'] || 0
            }}));
            systemTotals.sort((a, b) => b.total - a.total);
            const topSystems = systemTotals.slice(0, 8);

            // Preparar datasets por stage
            const stages = [
                {{ key: 'Dev', label: 'Development', color: '#28a745', icon: '💻' }},
                {{ key: 'QA', label: 'Quality Assurance', color: '#ffc107', icon: '🧪' }},
                {{ key: 'Prod', label: 'Production', color: '#dc3545', icon: '🚀' }}
            ];

            const datasets = stages.map(stage => ({{
                label: `${{stage.icon}} ${{stage.label}}`,
                data: topSystems.map(sys => sys[stage.key.toLowerCase() + 'Count']),
                backgroundColor: stage.color,
                borderColor: stage.color,
                borderWidth: 1,
                stack: 'stack1'
            }}));

            // Criar gráfico de barras horizontais empilhado
            charts['cweStage'] = new Chart(newCtx, {{
                type: 'bar',
                data: {{
                    labels: topSystems.map(s => s.system),
                    datasets: datasets
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',
                    scales: {{
                        x: {{
                            stacked: true,
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Número de CWEs Detectadas',
                                font: {{ size: 11, weight: 'bold' }}
                            }},
                            ticks: {{
                                font: {{ size: 10 }},
                                precision: 0
                            }},
                            grid: {{
                                color: 'rgba(0, 0, 0, 0.05)'
                            }}
                        }},
                        y: {{
                            stacked: true,
                            ticks: {{
                                font: {{ size: 10 }},
                                callback: function(value, index) {{
                                    const label = this.getLabelForValue(value);
                                    return label.length > 25 ? label.substring(0, 22) + '...' : label;
                                }}
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'top',
                            labels: {{
                                font: {{ size: 10 }},
                                padding: 10,
                                usePointStyle: true,
                                boxWidth: 12
                            }}
                        }},
                        title: {{
                            display: true,
                            text: 'Distribuição de Detecção de CWEs por Sistema e Stage',
                            font: {{ size: 13, weight: 'bold' }},
                            padding: {{ bottom: 15 }}
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return 'Sistema: ' + context[0].label;
                                }},
                                label: function(context) {{
                                    const stage = context.dataset.label;
                                    const count = context.parsed.x;
                                    const system = context.label;
                                    const systemData = topSystems.find(s => s.system === system);
                                    const percent = systemData ? Math.round((count / systemData.total) * 100) : 0;
                                    const plural = count !== 1 ? 's' : '';
                                    return [
                                        `${{stage}}: ${{count}} CWE${{plural}}`,
                                        `${{percent}}% do total do sistema`
                                    ];
                                }},
                                footer: function(contexts) {{
                                    const system = contexts[0].label;
                                    const systemData = topSystems.find(s => s.system === system);
                                    if (systemData) {{
                                        const shiftLeftScore = Math.round(
                                            ((systemData.devCount * 100 + systemData.qaCount * 50) /
                                            (systemData.total * 100)) * 100
                                        );
                                        return `Shift-Left Score: ${{shiftLeftScore}}%`;
                                    }}
                                    return '';
                                }}
                            }},
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            padding: 12,
                            titleFont: {{ size: 11, weight: 'bold' }},
                            bodyFont: {{ size: 10 }},
                            footerFont: {{ size: 10, style: 'italic' }}
                        }}
                    }},
                    interaction: {{
                        mode: 'index',
                        intersect: false
                    }}
                }}
            }});

            // Criar painel de análise
            const analysisContainer = document.getElementById('cweStageAnalysis');
            if (analysisContainer) {{
                // Calcular métricas de shift-left
                const totalIssues = cweIssues.length;
                const devPercent = Math.round((stageGlobalCount['Dev'] / totalIssues) * 100);
                const qaPercent = Math.round((stageGlobalCount['QA'] / totalIssues) * 100);
                const prodPercent = Math.round((stageGlobalCount['Prod'] / totalIssues) * 100);

                // Score shift-left (quanto mais cedo detectar, melhor)
                const shiftLeftScore = Math.round(
                    ((stageGlobalCount['Dev'] * 100 + stageGlobalCount['QA'] * 50) / (totalIssues * 100)) * 100
                );

                let scoreColor, scoreStatus, scoreIcon;
                if (shiftLeftScore >= 70) {{
                    scoreColor = '#28a745';
                    scoreStatus = 'EXCELENTE';
                    scoreIcon = 'fa-check-circle';
                }} else if (shiftLeftScore >= 50) {{
                    scoreColor = '#ffc107';
                    scoreStatus = 'BOM';
                    scoreIcon = 'fa-thumbs-up';
                }} else if (shiftLeftScore >= 30) {{
                    scoreColor = '#ff9800';
                    scoreStatus = 'REGULAR';
                    scoreIcon = 'fa-exclamation-triangle';
                }} else {{
                    scoreColor = '#dc3545';
                    scoreStatus = 'CRÍTICO';
                    scoreIcon = 'fa-times-circle';
                }}

                let analysisHTML = `
                    <!-- Shift-Left Score Card -->
                    <div style="background: white; border-radius: 8px; padding: 20px; margin-bottom: 15px; text-align: center; border: 3px solid ${{scoreColor}};">
                        <div style="font-size: 0.8rem; color: #6c757d; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">
                            Shift-Left Score
                        </div>
                        <div style="font-size: 3rem; font-weight: bold; color: ${{scoreColor}}; margin-bottom: 8px;">
                            ${{shiftLeftScore}}%
                        </div>
                        <div style="display: flex; align-items: center; justify-content: center; gap: 8px;">
                            <i class="fas ${{scoreIcon}}" style="color: ${{scoreColor}}; font-size: 1.2rem;"></i>
                            <span style="font-weight: 600; color: ${{scoreColor}}; font-size: 1rem; text-transform: uppercase; letter-spacing: 0.5px;">
                                ${{scoreStatus}}
                            </span>
                        </div>
                        <div style="margin-top: 12px; padding: 10px; background: #f8f9fa; border-radius: 6px; font-size: 0.75rem; color: #6c757d; line-height: 1.4;">
                            Quanto mais cedo detectar CWEs, menor o custo de correção
                        </div>
                    </div>

                    <!-- Sistemas com Melhor/Pior Performance -->
                    <div style="background: white; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
                        <div style="font-size: 0.85rem; font-weight: 600; color: #343a40; margin-bottom: 10px;">
                            <i class="fas fa-trophy" style="color: #ffc107;"></i> Melhor Detecção Antecipada
                        </div>
                `;

                // Encontrar sistema com melhor shift-left
                const bestSystem = topSystems.reduce((best, sys) => {{
                    const score = (sys.devCount * 100 + sys.qaCount * 50) / (sys.total * 100);
                    const bestScore = (best.devCount * 100 + best.qaCount * 50) / (best.total * 100);
                    return score > bestScore ? sys : best;
                }});

                const bestScore = Math.round(
                    ((bestSystem.devCount * 100 + bestSystem.qaCount * 50) / (bestSystem.total * 100)) * 100
                );

                analysisHTML += `
                        <div style="padding: 10px; background: #d4edda; border-left: 4px solid #28a745; border-radius: 4px; margin-bottom: 10px;">
                            <div style="font-weight: 600; color: #155724; font-size: 0.9rem; margin-bottom: 4px;">
                                ${{bestSystem.system.length > 30 ? bestSystem.system.substring(0, 27) + '...' : bestSystem.system}}
                            </div>
                            <div style="font-size: 0.75rem; color: #155724;">
                                Score: ${{bestScore}}% | Dev: ${{bestSystem.devCount}} | QA: ${{bestSystem.qaCount}} | Prod: ${{bestSystem.prodCount}}
                            </div>
                        </div>
                `;

                // Encontrar sistema com pior shift-left
                const worstSystem = topSystems.reduce((worst, sys) => {{
                    const score = (sys.devCount * 100 + sys.qaCount * 50) / (sys.total * 100);
                    const worstScore = (worst.devCount * 100 + worst.qaCount * 50) / (worst.total * 100);
                    return score < worstScore ? sys : worst;
                }});

                const worstScore = Math.round(
                    ((worstSystem.devCount * 100 + worstSystem.qaCount * 50) / (worstSystem.total * 100)) * 100
                );

                analysisHTML += `
                        <div style="font-size: 0.85rem; font-weight: 600; color: #343a40; margin: 15px 0 10px 0;">
                            <i class="fas fa-exclamation-triangle" style="color: #dc3545;"></i> Requer Mais Atenção
                        </div>
                        <div style="padding: 10px; background: #f8d7da; border-left: 4px solid #dc3545; border-radius: 4px;">
                            <div style="font-weight: 600; color: #721c24; font-size: 0.9rem; margin-bottom: 4px;">
                                ${{worstSystem.system.length > 30 ? worstSystem.system.substring(0, 27) + '...' : worstSystem.system}}
                            </div>
                            <div style="font-size: 0.75rem; color: #721c24;">
                                Score: ${{worstScore}}% | Dev: ${{worstSystem.devCount}} | QA: ${{worstSystem.qaCount}} | Prod: ${{worstSystem.prodCount}}
                            </div>
                        </div>
                    </div>
                `;

                analysisContainer.innerHTML = analysisHTML;
            }}

            // Criar painel de estatísticas
            const statsContainer = document.getElementById('cweStageStats');
            if (statsContainer) {{
                const statsHTML = `
                    <div style="display: grid; grid-template-columns: 1fr; gap: 12px;">
                        <!-- Dev -->
                        <div style="padding: 12px; background: #d4edda; border-radius: 6px; border-left: 4px solid #28a745;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                <span style="font-weight: 600; color: #155724; font-size: 0.9rem;">
                                    💻 Development
                                </span>
                                <span style="font-weight: bold; color: #155724; font-size: 1.1rem;">
                                    ${{devPercent}}%
                                </span>
                            </div>
                            <div style="width: 100%; height: 8px; background: #c3e6cb; border-radius: 4px; overflow: hidden;">
                                <div style="width: ${{devPercent}}%; height: 100%; background: #28a745; transition: width 0.3s ease;"></div>
                            </div>
                            <div style="font-size: 0.75rem; color: #155724; margin-top: 4px;">
                                ${{stageGlobalCount['Dev']}} CWEs detectadas
                            </div>
                        </div>

                        <!-- QA -->
                        <div style="padding: 12px; background: #fff3cd; border-radius: 6px; border-left: 4px solid #ffc107;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                <span style="font-weight: 600; color: #856404; font-size: 0.9rem;">
                                    🧪 Quality Assurance
                                </span>
                                <span style="font-weight: bold; color: #856404; font-size: 1.1rem;">
                                    ${{qaPercent}}%
                                </span>
                            </div>
                            <div style="width: 100%; height: 8px; background: #ffeaa7; border-radius: 4px; overflow: hidden;">
                                <div style="width: ${{qaPercent}}%; height: 100%; background: #ffc107; transition: width 0.3s ease;"></div>
                            </div>
                            <div style="font-size: 0.75rem; color: #856404; margin-top: 4px;">
                                ${{stageGlobalCount['QA']}} CWEs detectadas
                            </div>
                        </div>

                        <!-- Prod -->
                        <div style="padding: 12px; background: #f8d7da; border-radius: 6px; border-left: 4px solid #dc3545;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                <span style="font-weight: 600; color: #721c24; font-size: 0.9rem;">
                                    🚀 Production
                                </span>
                                <span style="font-weight: bold; color: #721c24; font-size: 1.1rem;">
                                    ${{prodPercent}}%
                                </span>
                            </div>
                            <div style="width: 100%; height: 8px; background: #f5c6cb; border-radius: 4px; overflow: hidden;">
                                <div style="width: ${{prodPercent}}%; height: 100%; background: #dc3545; transition: width 0.3s ease;"></div>
                            </div>
                            <div style="font-size: 0.75rem; color: #721c24; margin-top: 4px;">
                                ${{stageGlobalCount['Prod']}} CWEs detectadas
                            </div>
                        </div>
                    </div>

                    <div style="margin-top: 15px; padding: 12px; background: #d1ecf1; border-left: 4px solid #17a2b8; border-radius: 4px;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                            <i class="fas fa-info-circle" style="color: #0c5460;"></i>
                            <span style="font-weight: 600; color: #0c5460; font-size: 0.85rem;">Meta Shift-Left</span>
                        </div>
                        <div style="color: #0c5460; font-size: 0.75rem; line-height: 1.4;">
                            Objetivo: ≥70% de detecção em Dev/QA para reduzir custos de correção
                        </div>
                    </div>
                `;

                statsContainer.innerHTML = statsHTML;
            }}

            console.log('Gráfico 8 (Stage de Detecção por Sistema) renderizado:', {{
                total_systems: topSystems.length,
                shift_left_score: shiftLeftScore + '%',
                dev_detection: devPercent + '%',
                qa_detection: qaPercent + '%',
                prod_detection: prodPercent + '%',
                best_system: bestSystem.system + ' (' + bestScore + '%)',
                worst_system: worstSystem.system + ' (' + worstScore + '%)'
            }});
        }}

        function renderCWEDetectionSourceChart() {{
            const ctx = document.getElementById('cweDetectionSourceChart');
            if (!ctx) return;

            if (charts['cweDetectionSource']) {{
                charts['cweDetectionSource'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const cweBySource = cweMetrics.cwe_by_detection_source || {{}};

            // Agregar contagem por fonte
            const sourceCount = {{}};
            Object.keys(cweBySource).forEach(source => {{
                sourceCount[source] = Object.values(cweBySource[source]).reduce((a, b) => a + b, 0);
            }});

            charts['cweDetectionSource'] = new Chart(ctx, {{
                type: 'pie',
                data: {{
                    labels: Object.keys(sourceCount),
                    datasets: [{{
                        data: Object.values(sourceCount),
                        backgroundColor: ['#667eea', '#764ba2', '#f093fb', '#4facfe'],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: true, position: 'right' }}
                    }}
                }}
            }});
        }}

        function renderCWEIdentityChart() {{
            const ctx = document.getElementById('cweIdentityChart');
            if (!ctx) return;

            if (charts['cweIdentity']) {{
                charts['cweIdentity'].destroy();
            }}

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const cweIssues = cweMetrics.cwe_issues || [];

            // CWEs relacionados a Identidade e Autorização (IAM)
            const identityCWEs = {{
                'CWE-287': 'Autenticação Inadequada',
                'CWE-862': 'Falta de Autorização',
                'CWE-285': 'Autorização Incorreta',
                'CWE-798': 'Credenciais Hardcoded',
                'CWE-269': 'Gestão Incorreta de Privilégios',
                'CWE-522': 'Credenciais Desprotegidas',
                'CWE-306': 'Ausência de Autenticação',
                'CWE-732': 'Permissões Incorretas'
            }};

            // Filtrar apenas issues de CWEs de identidade
            const identityIssues = cweIssues.filter(issue =>
                Object.keys(identityCWEs).includes(issue.cwe_id)
            );

            // Verificar se há dados
            if (identityIssues.length === 0) {{
                ctx.parentElement.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-user-shield" style="font-size: 3rem; color: #ccc; margin-bottom: 15px;"></i>
                        <p style="color: #999; font-size: 1.1rem;">Nenhum CWE de Identidade/IAM detectado</p>
                        <p style="color: #bbb; font-size: 0.9rem;">Isso é um ótimo sinal para a segurança de autenticação e autorização!</p>
                    </div>
                `;
                return;
            }}

            // Criar container para visualização completa (gráfico + heatmap)
            const parentContainer = ctx.parentElement;
            parentContainer.innerHTML = `
                <div style="display: grid; grid-template-columns: 1fr 1.2fr; gap: 20px; height: 100%;">
                    <!-- Gráfico de Barras: CWEs por Sistema -->
                    <div style="position: relative;">
                        <canvas id="cweIdentityChart" style="max-height: 450px;"></canvas>
                    </div>

                    <!-- Matriz Heatmap: CWE x Sistema -->
                    <div style="padding: 20px; background: #f8f9fa; border-radius: 8px; overflow-y: auto; max-height: 450px;">
                        <h4 style="margin: 0 0 15px 0; color: #343a40; font-size: 1.1rem;">
                            <i class="fas fa-th"></i> Matriz de Impacto: CWE x Sistema
                        </h4>
                        <div id="cweIdentityMatrix"></div>

                        <div style="margin-top: 20px; padding: 15px; background: white; border-radius: 8px; border-left: 4px solid #3f51b5;">
                            <h5 style="margin: 0 0 10px 0; color: #343a40; font-size: 1rem;">
                                <i class="fas fa-info-circle"></i> Estatísticas de Identidade/IAM
                            </h5>
                            <div id="cweIdentityStats" style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.85rem;"></div>
                        </div>
                    </div>
                </div>
            `;

            // Recriar referência ao canvas
            const newCtx = document.getElementById('cweIdentityChart');
            if (!newCtx) return;

            // Agrupar por projeto e CWE
            const projectCWEMap = {{}};
            const cweProjectMap = {{}};

            identityIssues.forEach(issue => {{
                const project = issue.project_name || 'Desconhecido';
                const cweId = issue.cwe_id;

                if (!projectCWEMap[project]) projectCWEMap[project] = {{}};
                projectCWEMap[project][cweId] = (projectCWEMap[project][cweId] || 0) + 1;

                if (!cweProjectMap[cweId]) cweProjectMap[cweId] = {{}};
                cweProjectMap[cweId][project] = (cweProjectMap[cweId][project] || 0) + 1;
            }});

            // Selecionar top 8 sistemas com mais issues de identidade
            const projectTotals = Object.entries(projectCWEMap).map(([project, cwes]) => ({{
                project,
                total: Object.values(cwes).reduce((a, b) => a + b, 0)
            }}));
            projectTotals.sort((a, b) => b.total - a.total);
            const topProjects = projectTotals.slice(0, 8).map(p => p.project);

            // Preparar datasets por CWE para gráfico empilhado
            const datasets = Object.keys(identityCWEs).map((cweId, index) => {{
                const colors = [
                    '#dc3545', // Vermelho - CWE-287
                    '#ff6b6b', // Vermelho claro - CWE-862
                    '#ff9800', // Laranja - CWE-285
                    '#ffc107', // Amarelo - CWE-798
                    '#9c27b0', // Roxo - CWE-269
                    '#673ab7', // Roxo escuro - CWE-522
                    '#3f51b5', // Azul - CWE-306
                    '#2196f3'  // Azul claro - CWE-732
                ];

                return {{
                    label: `${{cweId}}: ${{identityCWEs[cweId]}}`,
                    data: topProjects.map(project => projectCWEMap[project]?.[cweId] || 0),
                    backgroundColor: colors[index],
                    borderColor: colors[index],
                    borderWidth: 1,
                    stack: 'stack1'
                }};
            }});

            // Criar gráfico de barras empilhado
            charts['cweIdentity'] = new Chart(newCtx, {{
                type: 'bar',
                data: {{
                    labels: topProjects,
                    datasets: datasets
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    indexAxis: 'y',  // Horizontal bars
                    scales: {{
                        x: {{
                            stacked: true,
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Número de Issues de Identidade/IAM',
                                font: {{ size: 11, weight: 'bold' }}
                            }},
                            ticks: {{ font: {{ size: 10 }} }}
                        }},
                        y: {{
                            stacked: true,
                            ticks: {{
                                font: {{ size: 10 }},
                                callback: function(value, index) {{
                                    const label = this.getLabelForValue(value);
                                    return label.length > 25 ? label.substring(0, 22) + '...' : label;
                                }}
                            }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            display: true,
                            position: 'bottom',
                            labels: {{
                                font: {{ size: 9 }},
                                padding: 8,
                                usePointStyle: true,
                                boxWidth: 10
                            }}
                        }},
                        title: {{
                            display: true,
                            text: 'Distribuição de CWEs de Identidade por Sistema',
                            font: {{ size: 13, weight: 'bold' }},
                            padding: 10
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: function(context) {{
                                    return context[0].label;
                                }},
                                label: function(context) {{
                                    const label = context.dataset.label || '';
                                    const value = context.parsed.x || 0;
                                    const plural = value !== 1 ? 's' : '';
                                    return `  ${{label}}: ${{value}} issue${{plural}}`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});

            // Criar matriz heatmap
            const matrixContainer = document.getElementById('cweIdentityMatrix');
            if (!matrixContainer) return;

            let matrixHTML = `
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 0.75rem;">
                        <thead>
                            <tr>
                                <th style="padding: 8px; background: #343a40; color: white; text-align: left; position: sticky; left: 0; z-index: 10; min-width: 120px;">Sistema</th>
            `;

            // Cabeçalhos CWE
            Object.keys(identityCWEs).forEach(cweId => {{
                matrixHTML += `
                    <th style="padding: 8px; background: #343a40; color: white; text-align: center; font-size: 0.7rem; min-width: 60px;"
                        title="${{identityCWEs[cweId]}}">
                        ${{cweId.replace('CWE-', '')}}
                    </th>
                `;
            }});

            matrixHTML += `
                                <th style="padding: 8px; background: #495057; color: white; text-align: center; font-weight: bold;">Total</th>
                            </tr>
                        </thead>
                        <tbody>
            `;

            // Linhas por sistema
            topProjects.forEach((project, projIndex) => {{
                const bgColor = projIndex % 2 === 0 ? '#ffffff' : '#f8f9fa';
                matrixHTML += `<tr style="background: ${{bgColor}};">`;
                matrixHTML += `
                    <td style="padding: 8px; font-weight: 600; color: #495057; position: sticky; left: 0; background: ${{bgColor}}; z-index: 5; border-right: 2px solid #dee2e6;"
                        title="${{project}}">
                        ${{project.length > 20 ? project.substring(0, 17) + '...' : project}}
                    </td>
                `;

                let projectTotal = 0;
                Object.keys(identityCWEs).forEach(cweId => {{
                    const count = projectCWEMap[project]?.[cweId] || 0;
                    projectTotal += count;

                    let cellColor = '#ffffff';
                    let textColor = '#999';
                    let fontWeight = 'normal';

                    if (count > 0) {{
                        if (count >= 10) {{
                            cellColor = '#dc3545';
                            textColor = '#ffffff';
                            fontWeight = 'bold';
                        }} else if (count >= 5) {{
                            cellColor = '#ff6b6b';
                            textColor = '#ffffff';
                            fontWeight = 'bold';
                        }} else if (count >= 3) {{
                            cellColor = '#ff9800';
                            textColor = '#ffffff';
                            fontWeight = '600';
                        }} else {{
                            cellColor = '#ffc107';
                            textColor = '#333';
                            fontWeight = '600';
                        }}
                    }}

                    matrixHTML += `
                        <td style="padding: 8px; text-align: center; background: ${{cellColor}}; color: ${{textColor}}; font-weight: ${{fontWeight}}; border: 1px solid #dee2e6;">
                            ${{count > 0 ? count : '-'}}
                        </td>
                    `;
                }});

                matrixHTML += `
                    <td style="padding: 8px; text-align: center; font-weight: bold; color: #dc3545; background: #f8f9fa; border: 1px solid #dee2e6;">
                        ${{projectTotal}}
                    </td>
                </tr>
                `;
            }});

            // Linha de totais
            matrixHTML += `
                <tr style="background: #e9ecef; font-weight: bold;">
                    <td style="padding: 8px; color: #495057; position: sticky; left: 0; background: #e9ecef; z-index: 5; border-right: 2px solid #dee2e6;">TOTAL</td>
            `;

            let grandTotal = 0;
            Object.keys(identityCWEs).forEach(cweId => {{
                const cweTotal = Object.values(cweProjectMap[cweId] || {{}}).reduce((a, b) => a + b, 0);
                grandTotal += cweTotal;
                matrixHTML += `
                    <td style="padding: 8px; text-align: center; color: #495057; border: 1px solid #dee2e6;">
                        ${{cweTotal}}
                    </td>
                `;
            }});

            matrixHTML += `
                    <td style="padding: 8px; text-align: center; color: #dc3545; font-size: 1.1rem; border: 1px solid #dee2e6;">
                        ${{grandTotal}}
                    </td>
                </tr>
            `;

            matrixHTML += `
                        </tbody>
                    </table>
                </div>
                <div style="margin-top: 10px; padding: 10px; background: white; border-radius: 4px; font-size: 0.75rem;">
                    <strong>Legenda:</strong>
                    <span style="display: inline-block; width: 20px; height: 15px; background: #dc3545; margin: 0 5px; border-radius: 3px;"></span> ≥10
                    <span style="display: inline-block; width: 20px; height: 15px; background: #ff6b6b; margin: 0 5px; border-radius: 3px;"></span> 5-9
                    <span style="display: inline-block; width: 20px; height: 15px; background: #ff9800; margin: 0 5px; border-radius: 3px;"></span> 3-4
                    <span style="display: inline-block; width: 20px; height: 15px; background: #ffc107; margin: 0 5px; border-radius: 3px;"></span> 1-2
                </div>
            `;

            matrixContainer.innerHTML = matrixHTML;

            // Criar estatísticas
            const statsContainer = document.getElementById('cweIdentityStats');
            if (!statsContainer) return;

            // Calcular estatísticas
            const totalIdentityIssues = identityIssues.length;
            const affectedSystems = Object.keys(projectCWEMap).length;
            const uniqueCWEs = Object.keys(cweProjectMap).length;
            const avgPerSystem = (totalIdentityIssues / affectedSystems).toFixed(1);

            // CWE mais crítico
            const cweRanking = Object.entries(cweProjectMap).map(([cweId, projects]) => ({{
                cweId,
                total: Object.values(projects).reduce((a, b) => a + b, 0),
                systems: Object.keys(projects).length
            }}));
            cweRanking.sort((a, b) => b.total - a.total);
            const topCWE = cweRanking[0];

            // Sistema mais afetado
            const systemRanking = Object.entries(projectCWEMap).map(([project, cwes]) => ({{
                project,
                total: Object.values(cwes).reduce((a, b) => a + b, 0),
                cweCount: Object.keys(cwes).length
            }}));
            systemRanking.sort((a, b) => b.total - a.total);
            const topSystem = systemRanking[0];

            statsContainer.innerHTML = `
                <div style="text-align: center; padding: 10px; background: #fff3cd; border-radius: 4px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #856404;">${{totalIdentityIssues}}</div>
                    <div style="color: #856404; font-size: 0.8rem;">Total de Issues IAM</div>
                </div>
                <div style="text-align: center; padding: 10px; background: #d1ecf1; border-radius: 4px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #0c5460;">${{affectedSystems}}</div>
                    <div style="color: #0c5460; font-size: 0.8rem;">Sistemas Afetados</div>
                </div>
                <div style="text-align: center; padding: 10px; background: #f8d7da; border-radius: 4px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #721c24;">${{uniqueCWEs}}</div>
                    <div style="color: #721c24; font-size: 0.8rem;">CWEs IAM Únicos</div>
                </div>
                <div style="text-align: center; padding: 10px; background: #d4edda; border-radius: 4px;">
                    <div style="font-size: 1.5rem; font-weight: bold; color: #155724;">${{avgPerSystem}}</div>
                    <div style="color: #155724; font-size: 0.8rem;">Média por Sistema</div>
                </div>
                <div style="padding: 10px; background: #f8d7da; border-radius: 4px; grid-column: span 2;">
                    <div style="font-weight: bold; color: #721c24; margin-bottom: 5px;">🔴 CWE Mais Crítico:</div>
                    <div style="color: #721c24; font-size: 0.8rem;">
                        <strong>${{topCWE.cweId}}</strong>: ${{identityCWEs[topCWE.cweId]}}<br>
                        ${{topCWE.total}} issues em ${{topCWE.systems}} sistema(s)
                    </div>
                </div>
                <div style="padding: 10px; background: #fff3cd; border-radius: 4px; grid-column: span 2;">
                    <div style="font-weight: bold; color: #856404; margin-bottom: 5px;">⚠️ Sistema Mais Afetado:</div>
                    <div style="color: #856404; font-size: 0.8rem;">
                        <strong>${{topSystem.project}}</strong><br>
                        ${{topSystem.total}} issues em ${{topSystem.cweCount}} CWE(s) diferente(s)
                    </div>
                </div>
            `;

            console.log('Gráfico 10 (CWEs Identidade x Sistemas) renderizado:', {{
                total_identity_issues: totalIdentityIssues,
                affected_systems: affectedSystems,
                unique_cwes: uniqueCWEs,
                top_cwe: topCWE.cweId,
                top_system: topSystem.project
            }});
        }}

        function renderCWEOriginChart() {{
            const ctx = document.getElementById('cweOriginChart');
            if (!ctx) return;

            if (charts['cweOrigin']) {{
                charts['cweOrigin'].destroy();
            }}

            // Dados simulados (em produção, viria de análise de origem)
            const totalIssues = dashboardData.cwe_metrics?.cwe_issues?.length || 0;
            const ownCode = Math.floor(totalIssues * 0.6);
            const thirdParty = totalIssues - ownCode;

            charts['cweOrigin'] = new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Código Próprio', 'Terceiros/Libs'],
                    datasets: [{{
                        data: [ownCode, thirdParty],
                        backgroundColor: ['#667eea', '#ff6b6b'],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: true, position: 'bottom' }}
                    }}
                }}
            }});
        }}

        function renderCWETeamTrainingChart() {{
            const ctx = document.getElementById('cweTeamTrainingChart');
            if (!ctx) return;

            if (charts['cweTeamTraining']) {{
                charts['cweTeamTraining'].destroy();
            }}

            // Dados simulados de times e treinamento
            const teams = ['Squad A', 'Squad B', 'Squad C', 'Squad D', 'Squad E'];
            const issuesData = teams.map(() => Math.floor(Math.random() * 50) + 10);
            const trainedData = teams.map((_, i) => issuesData[i] > 30 ? 0 : 1);

            charts['cweTeamTraining'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: teams,
                    datasets: [
                        {{
                            label: 'Issues CWE Top 25',
                            data: issuesData,
                            backgroundColor: '#dc3545',
                            borderColor: '#c82333',
                            borderWidth: 1,
                            yAxisID: 'y'
                        }},
                        {{
                            label: 'Treinamento Concluído',
                            data: trainedData,
                            backgroundColor: '#28a745',
                            borderColor: '#218838',
                            borderWidth: 1,
                            yAxisID: 'y1',
                            type: 'line'
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{ beginAtZero: true, position: 'left', title: {{ display: true, text: 'Issues' }} }},
                        y1: {{ beginAtZero: true, max: 1, position: 'right', grid: {{ drawOnChartArea: false }}, ticks: {{ stepSize: 1 }}, title: {{ display: true, text: 'Treinado (0/1)' }} }}
                    }},
                    plugins: {{
                        legend: {{ display: true, position: 'top' }}
                    }}
                }}
            }});
        }}

        function renderCWETables() {{
            renderCWERiskConcentration();
            renderCWESLATable();
        }}

        function renderCWERiskConcentration() {{
            const container = document.getElementById('cweRiskConcentration');
            if (!container) return;

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const allCWEIssues = cweMetrics.cwe_issues || [];

            // Filtrar apenas CWEs Top 25
            const top25Issues = allCWEIssues.filter(i => i.is_top_25);
            const totalIssues = top25Issues.length;

            // Contar issues em sistemas críticos
            const criticalIssues = top25Issues.filter(i => i.business_criticality === 'Alta').length;

            // Calcular concentração
            const concentration = totalIssues > 0 ? Math.round((criticalIssues / totalIssues) * 100) : 0;

            // Se não houver dados
            if (totalIssues === 0) {{
                container.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-info-circle" style="font-size: 3rem; color: #ccc; margin-bottom: 15px;"></i>
                        <p style="color: #999; font-size: 1.1rem;">Nenhuma issue CWE Top 25 identificada</p>
                        <p style="color: #bbb; font-size: 0.9rem;">Execute uma análise completa do SonarQube para obter dados</p>
                    </div>
                `;
                return;
            }}

            // Determinar cor baseada na concentração
            let concentrationColor = '#28a745';  // Verde
            let concentrationLevel = 'BAIXO';
            let concentrationIcon = 'fa-check-circle';
            let concentrationMessage = 'Risco bem distribuído';

            if (concentration >= 70) {{
                concentrationColor = '#dc3545';  // Vermelho
                concentrationLevel = 'CRÍTICO';
                concentrationIcon = 'fa-exclamation-triangle';
                concentrationMessage = 'Alto risco de impacto concentrado';
            }} else if (concentration >= 50) {{
                concentrationColor = '#ff9800';  // Laranja
                concentrationLevel = 'ALTO';
                concentrationIcon = 'fa-exclamation-circle';
                concentrationMessage = 'Risco moderadamente concentrado';
            }} else if (concentration >= 30) {{
                concentrationColor = '#ffc107';  // Amarelo
                concentrationLevel = 'MÉDIO';
                concentrationIcon = 'fa-info-circle';
                concentrationMessage = 'Concentração moderada de risco';
            }}

            // Contar projetos críticos únicos afetados
            const criticalProjects = new Set(
                top25Issues
                    .filter(i => i.business_criticality === 'Alta')
                    .map(i => i.project)
            );

            // Contar CWEs únicos em sistemas críticos
            const criticalCWEs = new Set(
                top25Issues
                    .filter(i => i.business_criticality === 'Alta')
                    .map(i => i.cwe_id)
            );

            // Top 5 projetos críticos com mais issues
            const projectIssuesCount = {{}};
            top25Issues
                .filter(i => i.business_criticality === 'Alta')
                .forEach(issue => {{
                    projectIssuesCount[issue.project] = (projectIssuesCount[issue.project] || 0) + 1;
                }});

            const topCriticalProjects = Object.entries(projectIssuesCount)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);

            // Top 5 CWEs em sistemas críticos
            const cweIssuesCount = {{}};
            top25Issues
                .filter(i => i.business_criticality === 'Alta')
                .forEach(issue => {{
                    cweIssuesCount[issue.cwe_id] = (cweIssuesCount[issue.cwe_id] || 0) + 1;
                }});

            const topCriticalCWEs = Object.entries(cweIssuesCount)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);

            // Gerar HTML
            let html = `
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                    <!-- Painel Principal de Concentração -->
                    <div style="text-align: center; padding: 30px; background: linear-gradient(135deg, ${{concentrationColor}}15 0%, ${{concentrationColor}}05 100%); border-radius: 10px; border: 2px solid ${{concentrationColor}}40;">
                        <i class="fas ${{concentrationIcon}}" style="font-size: 2.5rem; color: ${{concentrationColor}}; margin-bottom: 15px;"></i>
                        <h1 style="font-size: 4rem; color: ${{concentrationColor}}; margin: 0; font-weight: bold; text-shadow: 2px 2px 4px rgba(0,0,0,0.1);">
                            ${{concentration}}%
                        </h1>
                        <p style="font-size: 1.3rem; color: #666; margin: 15px 0 5px 0; font-weight: 600;">
                            Concentração de Risco
                        </p>
                        <div style="background: ${{concentrationColor}}; color: white; padding: 8px 20px; border-radius: 20px; display: inline-block; font-weight: bold; margin: 10px 0;">
                            NÍVEL: ${{concentrationLevel}}
                        </div>
                        <p style="color: #888; margin: 15px 0; font-size: 1rem;">
                            ${{concentrationMessage}}
                        </p>
                        <div style="margin-top: 20px; padding-top: 20px; border-top: 2px solid #eee;">
                            <div style="font-size: 0.9rem; color: #666; margin-bottom: 8px;">
                                <strong style="font-size: 1.8rem; color: ${{concentrationColor}};">${{criticalIssues}}</strong>
                                <span>de</span>
                                <strong style="font-size: 1.8rem; color: #667eea;">${{totalIssues}}</strong>
                            </div>
                            <p style="color: #999; font-size: 0.95rem; margin: 5px 0;">
                                issues CWE Top 25 em sistemas críticos
                            </p>
                        </div>
                    </div>

                    <!-- Painel de Estatísticas Detalhadas -->
                    <div style="padding: 20px; background: #f8f9fa; border-radius: 10px; border: 1px solid #dee2e6;">
                        <h3 style="margin: 0 0 20px 0; color: #343a40; font-size: 1.2rem;">
                            <i class="fas fa-chart-bar"></i> Estatísticas de Concentração
                        </h3>

                        <!-- Métricas -->
                        <div style="margin-bottom: 20px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: white; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid #667eea;">
                                <span style="color: #666; font-size: 0.95rem;">
                                    <i class="fas fa-server" style="color: #667eea; margin-right: 8px;"></i>
                                    Sistemas Críticos Afetados
                                </span>
                                <strong style="font-size: 1.3rem; color: #667eea;">${{criticalProjects.size}}</strong>
                            </div>

                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: white; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid #dc3545;">
                                <span style="color: #666; font-size: 0.95rem;">
                                    <i class="fas fa-bug" style="color: #dc3545; margin-right: 8px;"></i>
                                    CWEs Únicos Detectados
                                </span>
                                <strong style="font-size: 1.3rem; color: #dc3545;">${{criticalCWEs.size}}</strong>
                            </div>

                            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: white; border-radius: 8px; border-left: 4px solid #28a745;">
                                <span style="color: #666; font-size: 0.95rem;">
                                    <i class="fas fa-shield-alt" style="color: #28a745; margin-right: 8px;"></i>
                                    Issues em Sistemas Não-Críticos
                                </span>
                                <strong style="font-size: 1.3rem; color: #28a745;">${{totalIssues - criticalIssues}}</strong>
                            </div>
                        </div>

                        <!-- Barra de Progresso Visual -->
                        <div style="margin-top: 20px;">
                            <p style="font-size: 0.9rem; color: #666; margin-bottom: 8px; font-weight: 600;">
                                Distribuição de Risco
                            </p>
                            <div style="width: 100%; height: 30px; background: #e9ecef; border-radius: 15px; overflow: hidden; position: relative; box-shadow: inset 0 2px 4px rgba(0,0,0,0.1);">
                                <div style="width: ${{concentration}}%; height: 100%; background: linear-gradient(90deg, ${{concentrationColor}}, ${{concentrationColor}}dd); display: flex; align-items: center; justify-content: center; transition: width 0.5s ease;">
                                    <span style="color: white; font-weight: bold; font-size: 0.85rem; text-shadow: 1px 1px 2px rgba(0,0,0,0.3);">
                                        ${{concentration}}% Crítico
                                    </span>
                                </div>
                            </div>
                            <div style="display: flex; justify-content: space-between; margin-top: 5px; font-size: 0.75rem; color: #999;">
                                <span>0%</span>
                                <span>50%</span>
                                <span>100%</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Top 5 Projetos e CWEs Críticos -->
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;">
                    <!-- Top Projetos Críticos -->
                    <div style="padding: 20px; background: #fff; border-radius: 10px; border: 1px solid #dee2e6;">
                        <h4 style="margin: 0 0 15px 0; color: #343a40; font-size: 1.1rem;">
                            <i class="fas fa-server" style="color: #667eea;"></i>
                            Top 5 Sistemas Críticos Afetados
                        </h4>
            `;

            if (topCriticalProjects.length > 0) {{
                topCriticalProjects.forEach(([project, count], index) => {{
                    const barWidth = (count / topCriticalProjects[0][1]) * 100;
                    html += `
                        <div style="margin-bottom: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span style="font-size: 0.9rem; color: #495057; font-weight: 500;">
                                    ${{index + 1}}. ${{project.substring(0, 30)}}${{project.length > 30 ? '...' : ''}}
                                </span>
                                <strong style="color: #dc3545; font-size: 1rem;">${{count}}</strong>
                            </div>
                            <div style="width: 100%; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden;">
                                <div style="width: ${{barWidth}}%; height: 100%; background: linear-gradient(90deg, #dc3545, #ff6b6b); transition: width 0.3s ease;"></div>
                            </div>
                        </div>
                    `;
                }});
            }} else {{
                html += '<p style="color: #999; text-align: center; padding: 20px;">Nenhum sistema crítico identificado</p>';
            }}

            html += `
                    </div>

                    <!-- Top CWEs em Sistemas Críticos -->
                    <div style="padding: 20px; background: #fff; border-radius: 10px; border: 1px solid #dee2e6;">
                        <h4 style="margin: 0 0 15px 0; color: #343a40; font-size: 1.1rem;">
                            <i class="fas fa-bug" style="color: #dc3545;"></i>
                            Top 5 CWEs em Sistemas Críticos
                        </h4>
            `;

            if (topCriticalCWEs.length > 0) {{
                const cweNames = {{
                    'CWE-79': 'XSS',
                    'CWE-89': 'SQL Injection',
                    'CWE-862': 'Missing Authorization',
                    'CWE-287': 'Improper Authentication',
                    'CWE-798': 'Hard-coded Credentials'
                }};

                topCriticalCWEs.forEach(([cweId, count], index) => {{
                    const barWidth = (count / topCriticalCWEs[0][1]) * 100;
                    const cweName = cweNames[cweId] || cweId;
                    html += `
                        <div style="margin-bottom: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span style="font-size: 0.9rem; color: #495057; font-weight: 500;">
                                    ${{index + 1}}. ${{cweId}} - ${{cweName}}
                                </span>
                                <strong style="color: #667eea; font-size: 1rem;">${{count}}</strong>
                            </div>
                            <div style="width: 100%; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden;">
                                <div style="width: ${{barWidth}}%; height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); transition: width 0.3s ease;"></div>
                            </div>
                        </div>
                    `;
                }});
            }} else {{
                html += '<p style="color: #999; text-align: center; padding: 20px;">Nenhum CWE identificado</p>';
            }}

            html += `
                    </div>
                </div>
            `;

            container.innerHTML = html;

            console.log('KPI Concentração de Risco CWE renderizado:', {{
                concentration: concentration + '%',
                total_issues: totalIssues,
                critical_issues: criticalIssues,
                critical_projects: criticalProjects.size,
                critical_cwes: criticalCWEs.size
            }});
        }}

        function renderCWESLATable() {{
            const container = document.getElementById('cweSLATable');
            if (!container) return;

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const backlogByCWE = cweMetrics.backlog_by_cwe || {{}};

            // CWEs com mais issues vencendo SLA (>90 dias)
            const slaViolations = Object.entries(backlogByCWE).map(([cweId, ages]) => ({{
                cweId,
                overdueCount: ages['90+'] || 0,
                aging60to90: ages['61-90'] || 0,
                aging30to60: ages['31-60'] || 0,
                fresh: ages['0-30'] || 0,
                totalCount: Object.values(ages).reduce((a, b) => a + b, 0)
            }})).filter(item => item.overdueCount > 0 || item.aging60to90 > 0)
               .sort((a, b) => {{
                   // Priorizar por issues >90 dias, depois 61-90 dias
                   if (b.overdueCount !== a.overdueCount) return b.overdueCount - a.overdueCount;
                   return b.aging60to90 - a.aging60to90;
               }})
               .slice(0, 10);

            // CWE names para descrição
            const cweNames = {{
                'CWE-79': 'Cross-site Scripting',
                'CWE-89': 'SQL Injection',
                'CWE-287': 'Authentication',
                'CWE-862': 'Authorization',
                'CWE-798': 'Hardcoded Credentials',
                'CWE-22': 'Path Traversal',
                'CWE-352': 'CSRF',
                'CWE-787': 'Buffer Overflow',
                'CWE-434': 'File Upload',
                'CWE-502': 'Deserialization'
            }};

            if (slaViolations.length === 0) {{
                container.innerHTML = `
                    <div style="text-align: center; padding: 40px;">
                        <i class="fas fa-check-circle" style="font-size: 3rem; color: #28a745; margin-bottom: 15px;"></i>
                        <p style="color: #28a745; font-size: 1.2rem; font-weight: bold;">Nenhuma Issue Vencendo SLA!</p>
                        <p style="color: #666; font-size: 0.95rem;">Todas as issues CWE estão dentro do prazo estabelecido (< 90 dias)</p>
                    </div>
                `;
                return;
            }}

            // Tabela estilizada com cards
            let html = `
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.9rem;">
                        <thead>
                            <tr style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                                <th style="padding: 12px; text-align: left; border-top-left-radius: 8px; font-weight: 600;">Rank</th>
                                <th style="padding: 12px; text-align: left; font-weight: 600;">CWE</th>
                                <th style="padding: 12px; text-align: center; font-weight: 600;">
                                    <i class="fas fa-exclamation-triangle"></i> >90 dias
                                </th>
                                <th style="padding: 12px; text-align: center; font-weight: 600;">
                                    <i class="fas fa-clock"></i> 61-90 dias
                                </th>
                                <th style="padding: 12px; text-align: center; font-weight: 600;">Total</th>
                                <th style="padding: 12px; text-align: center; border-top-right-radius: 8px; font-weight: 600;">% SLA Vencido</th>
                            </tr>
                        </thead>
                        <tbody>
            `;

            slaViolations.forEach((item, index) => {{
                const percent = Math.round((item.overdueCount / item.totalCount) * 100);
                const cweName = cweNames[item.cweId] || '';

                // Cor do badge baseado na severidade
                let badgeColor, statusIcon, statusText;
                if (percent >= 75) {{
                    badgeColor = '#dc3545';
                    statusIcon = 'fa-times-circle';
                    statusText = 'CRÍTICO';
                }} else if (percent >= 50) {{
                    badgeColor = '#ff6b6b';
                    statusIcon = 'fa-exclamation-circle';
                    statusText = 'ALTO';
                }} else if (percent >= 25) {{
                    badgeColor = '#ff9800';
                    statusIcon = 'fa-exclamation-triangle';
                    statusText = 'MÉDIO';
                }} else {{
                    badgeColor = '#ffc107';
                    statusIcon = 'fa-info-circle';
                    statusText = 'BAIXO';
                }}

                const rowBg = index % 2 === 0 ? '#ffffff' : '#f8f9fa';

                html += `
                    <tr style="background: ${{rowBg}}; border-bottom: 1px solid #dee2e6;">
                        <td style="padding: 12px; text-align: center;">
                            <div style="width: 32px; height: 32px; background: ${{badgeColor}}; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 0.9rem; margin: 0 auto;">
                                ${{index + 1}}
                            </div>
                        </td>
                        <td style="padding: 12px;">
                            <div style="font-weight: bold; color: #343a40; font-size: 1rem; margin-bottom: 2px;">
                                ${{item.cweId}}
                            </div>
                            <div style="color: #6c757d; font-size: 0.8rem;">
                                ${{cweName}}
                            </div>
                        </td>
                        <td style="padding: 12px; text-align: center;">
                            <div style="display: inline-block; padding: 6px 12px; background: #fff5f5; border: 2px solid #dc3545; border-radius: 6px; color: #dc3545; font-weight: bold; font-size: 1.1rem;">
                                ${{item.overdueCount}}
                            </div>
                        </td>
                        <td style="padding: 12px; text-align: center;">
                            <div style="display: inline-block; padding: 6px 12px; background: #fff8e6; border: 2px solid #ff9800; border-radius: 6px; color: #ff9800; font-weight: 600; font-size: 1rem;">
                                ${{item.aging60to90}}
                            </div>
                        </td>
                        <td style="padding: 12px; text-align: center; font-weight: 600; color: #495057; font-size: 1rem;">
                            ${{item.totalCount}}
                        </td>
                        <td style="padding: 12px;">
                            <div style="display: flex; flex-direction: column; align-items: center; gap: 6px;">
                                <div style="display: flex; align-items: center; gap: 6px;">
                                    <i class="fas ${{statusIcon}}" style="color: ${{badgeColor}}; font-size: 1.1rem;"></i>
                                    <span style="font-weight: bold; font-size: 1.2rem; color: ${{badgeColor}};">
                                        ${{percent}}%
                                    </span>
                                </div>
                                <div style="width: 100px; height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden;">
                                    <div style="width: ${{percent}}%; height: 100%; background: ${{badgeColor}}; transition: width 0.3s ease;"></div>
                                </div>
                                <span style="font-size: 0.7rem; font-weight: 600; color: ${{badgeColor}}; text-transform: uppercase; letter-spacing: 0.5px;">
                                    ${{statusText}}
                                </span>
                            </div>
                        </td>
                    </tr>
                `;
            }});

            html += `
                        </tbody>
                    </table>
                </div>

                <!-- Legenda e Estatísticas -->
                <div style="margin-top: 20px; padding: 15px; background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border-radius: 8px;">
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                        <div style="text-align: center; padding: 10px; background: white; border-radius: 6px; border-left: 4px solid #dc3545;">
                            <div style="font-size: 1.8rem; font-weight: bold; color: #dc3545;">
                                ${{slaViolations.reduce((sum, item) => sum + item.overdueCount, 0)}}
                            </div>
                            <div style="font-size: 0.8rem; color: #6c757d; margin-top: 4px;">
                                Issues > 90 dias
                            </div>
                        </div>
                        <div style="text-align: center; padding: 10px; background: white; border-radius: 6px; border-left: 4px solid #ff9800;">
                            <div style="font-size: 1.8rem; font-weight: bold; color: #ff9800;">
                                ${{slaViolations.reduce((sum, item) => sum + item.aging60to90, 0)}}
                            </div>
                            <div style="font-size: 0.8rem; color: #6c757d; margin-top: 4px;">
                                Issues 61-90 dias
                            </div>
                        </div>
                        <div style="text-align: center; padding: 10px; background: white; border-radius: 6px; border-left: 4px solid #667eea;">
                            <div style="font-size: 1.8rem; font-weight: bold; color: #667eea;">
                                ${{slaViolations.length}}
                            </div>
                            <div style="font-size: 0.8rem; color: #6c757d; margin-top: 4px;">
                                CWEs em Violação
                            </div>
                        </div>
                    </div>

                    <div style="margin-top: 15px; padding: 12px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <i class="fas fa-info-circle" style="color: #856404; font-size: 1.2rem;"></i>
                            <div style="color: #856404; font-size: 0.85rem; line-height: 1.5;">
                                <strong>SLA Padrão:</strong> Issues devem ser resolvidas em até 90 dias.
                                Issues acima deste período indicam problemas de priorização ou complexidade técnica.
                            </div>
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = html;

            console.log('Tabela SLA renderizada:', {{
                violations_count: slaViolations.length,
                total_overdue: slaViolations.reduce((sum, item) => sum + item.overdueCount, 0),
                total_aging: slaViolations.reduce((sum, item) => sum + item.aging60to90, 0),
                top_violator: slaViolations[0].cweId + ' (' + slaViolations[0].overdueCount + ' issues)'
            }});
        }}

        function renderCWEOKRs() {{
            const container = document.getElementById('cweOKRsContainer');
            if (!container) return;

            const cweMetrics = dashboardData.cwe_metrics || {{}};
            const coverage = cweMetrics.cwe_top_25_coverage || 0;
            const criticalIssues = cweMetrics.cwe_critical_systems_count || 0;
            const avgMTTR = Object.values(cweMetrics.mttr_by_cwe || {{}}).reduce((a, b) => a + b, 0) / Math.max(Object.keys(cweMetrics.mttr_by_cwe || {{}}).length, 1);

            const okrs = [
                {{
                    objective: 'Reduzir exposição a CWE Top 25 em sistemas críticos',
                    krs: [
                        {{ description: 'Reduzir de 9 para 4 o nº de CWEs Top 25 presentes', current: coverage, target: 4, unit: 'CWEs' }},
                        {{ description: 'Reduzir em 60% issues de CWE-79 e CWE-89 em produção', current: criticalIssues, target: Math.floor(criticalIssues * 0.4), unit: 'issues' }},
                        {{ description: 'Atingir ≥90% conformidade em Auth/AuthZ (ASVS)', current: 65, target: 90, unit: '%' }}
                    ]
                }},
                {{
                    objective: 'Antecipar detecção de CWE para fases iniciais',
                    krs: [
                        {{ description: 'Aumentar de 20% para 70% detecção em Dev/PR', current: 20, target: 70, unit: '%' }},
                        {{ description: '100% sistemas críticos com SAST+SCA+secrets', current: 75, target: 100, unit: '%' }}
                    ]
                }},
                {{
                    objective: 'Encurtar MTTR de CWEs críticos',
                    krs: [
                        {{ description: 'Reduzir MTTR médio de 40 para 20 dias', current: Math.round(avgMTTR), target: 20, unit: 'dias' }},
                        {{ description: 'Eliminar backlog >90 dias em sistemas críticos', current: 15, target: 0, unit: 'issues' }}
                    ]
                }}
            ];

            let html = '';
            okrs.forEach((okr, index) => {{
                html += `
                    <div class="card mb-3" style="border-left: 4px solid #667eea;">
                        <div style="padding: 20px;">
                            <h4 style="color: #667eea; margin-bottom: 15px;">
                                <i class="fas fa-bullseye"></i> Objetivo ${{index + 1}}: ${{okr.objective}}
                            </h4>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>KR</th>
                                        <th>Atual</th>
                                        <th>Meta</th>
                                        <th>Progresso</th>
                                    </tr>
                                </thead>
                                <tbody>
                `;

                okr.krs.forEach((kr, krIndex) => {{
                    const progress = Math.min(100, Math.round((kr.current / kr.target) * 100));
                    const progressColor = progress >= 80 ? '#28a745' : progress >= 50 ? '#ffc107' : '#dc3545';

                    html += `
                        <tr>
                            <td>KR${{krIndex + 1}}: ${{kr.description}}</td>
                            <td style="font-weight: bold;">${{kr.current}} ${{kr.unit}}</td>
                            <td>${{kr.target}} ${{kr.unit}}</td>
                            <td>
                                <div style="width: 100%; background: #e9ecef; border-radius: 4px; overflow: hidden;">
                                    <div style="width: ${{progress}}%; background: ${{progressColor}}; padding: 5px; color: white; text-align: center; font-weight: bold;">
                                        ${{progress}}%
                                    </div>
                                </div>
                            </td>
                        </tr>
                    `;
                }});

                html += `
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            }});

            container.innerHTML = html;
        }}

    </script>
</body>
</html>"""


def start_server(port=8000):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args): pass
    
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(f"🌐 Servidor: http://localhost:{port}")
        print("⚠️  Ctrl+C para parar\n")
        webbrowser.open(f'http://localhost:{port}/sonarqube_dashboard.html')
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n✓ Encerrado")


def main():
    print("=" * 70)
    print("  DASHBOARD EXECUTIVO SONARQUBE - INTELLIGENCE OWASP 2025")
    print("=" * 70)
    print()
    
    url = input("URL do SonarQube: ").strip()
    token = input("Token: ").strip()
    
    if not url or not token:
        print("\n✗ URL e Token são obrigatórios!")
        return
    
    print()
    print("⏳ ATENÇÃO: Sistema de Intelligence Avançado com Aggregate Report")
    print("   ✓ NOVO: Aba Aggregate Report para análise temporal de projetos")
    print("   ✓ NOVO: Sistema de versionamento automático de scans")
    print("   ✓ NOVO: Diretório de histórico com snapshots datados")
    print("   ✓ NOVO: Análise de evolução OWASP Top 10 2025")
    print("   ✓ NOVO: Identificação de pontos críticos e recomendações")
    print("   ✓ NOVO: Processamento APENAS de branches principais (main, master, develop, developer)")
    print("   ✓ NOVO: Modal interativo para TODAS as categorias OWASP")
    print("   ✓ NOVO: Destaque especial para Secrets e Misconfigurations")
    print("   ✓ NOVO: Métricas de coverage por projeto")
    print("   ✓ NOVO: Filtro automático de dependency-check-report.html")
    print("   ✓ Classificação OWASP Top 10 2025 automática")
    print("   ✓ Geração de insights de inteligência")
    print("   ✓ Links diretos ao SonarQube para correção")
    print("   ✓ Interface executiva otimizada")
    print("   Isso pode levar vários minutos dependendo da quantidade de dados.")
    print()
    
    collector = SonarQubeCollector(url, token)
    
    if not collector.test_connection_and_auth():
        print("\n✗ Falha na conexão/autenticação.")
        return
    
    try:
        data = collector.collect_dashboard_data()
        
        if len(data['projects']) == 0:
            print("⚠️  Nenhum projeto encontrado!")
            return
        
        with open('sonarqube_dashboard_data.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print("\n✓ Dados salvos: sonarqube_dashboard_data.json")
        
        html = collector.generate_dashboard_html(data)
        
        with open('sonarqube_dashboard.html', 'w', encoding='utf-8') as f:
            f.write(html)
        print("✓ Dashboard gerado: sonarqube_dashboard.html")
        
        print(f"\n📊 HISTÓRICO DE SCANS:")
        scans = collector.get_scan_history()
        print(f"  - {len(scans)} snapshot(s) armazenado(s) em {SCANS_DIRECTORY}/")
        if scans:
            oldest = scans[0]['timestamp']
            newest = scans[-1]['timestamp']
            print(f"  - Período: {oldest} até {newest}")
        
        print()
        start_server(8000)
        
    except Exception as e:
        print(f"\n✗ Erro: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()