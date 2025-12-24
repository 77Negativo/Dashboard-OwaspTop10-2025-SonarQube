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

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    print("⚠️  Gemini AI não disponível. Instale com: pip install google-generativeai")

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

# CWE Top 25 2025 - Most Dangerous Software Weaknesses
CWE_TOP_25_2025_MAPPING = {
    'CWE-787': {
        'name': 'Out-of-bounds Write',
        'description': 'Escrita fora dos limites do buffer',
        'severity': 'CRITICAL',
        'rank': 1,
        'keywords': ['buffer', 'overflow', 'memory', 'write', 'bounds'],
        'attack_vector': 'Buffer overflow attacks, memory corruption, arbitrary code execution',
        'mitigation': 'Use linguagens memory-safe, validação de bounds, ferramentas de análise estática',
        'example': 'strcpy() sem validação de tamanho, array indexing sem verificação',
        'color': '#8B0000',
        'icon': 'fa-exclamation-triangle'
    },
    'CWE-79': {
        'name': 'Cross-site Scripting (XSS)',
        'description': 'Injeção de scripts maliciosos em páginas web',
        'severity': 'CRITICAL',
        'rank': 2,
        'keywords': ['xss', 'script', 'javascript', 'injection', 'html'],
        'attack_vector': 'Injeção de JavaScript malicioso, roubo de cookies, sessão hijacking',
        'mitigation': 'Sanitização de input, Content Security Policy, escape de output, frameworks seguros',
        'example': 'echo $_GET["user"] sem sanitização, innerHTML com dados não confiáveis',
        'color': '#DC3545',
        'icon': 'fa-code'
    },
    'CWE-89': {
        'name': 'SQL Injection',
        'description': 'Injeção de comandos SQL maliciosos',
        'severity': 'CRITICAL',
        'rank': 3,
        'keywords': ['sql', 'injection', 'database', 'query'],
        'attack_vector': 'Exfiltração de dados, bypass de autenticação, modificação de dados',
        'mitigation': 'Prepared statements, parametrized queries, ORMs, validação de input',
        'example': 'SELECT * FROM users WHERE id = " + userId (concatenação direta)',
        'color': '#DC3545',
        'icon': 'fa-database'
    },
    'CWE-416': {
        'name': 'Use After Free',
        'description': 'Uso de memória após liberação',
        'severity': 'CRITICAL',
        'rank': 4,
        'keywords': ['memory', 'free', 'pointer', 'dangling'],
        'attack_vector': 'Memory corruption, execução de código arbitrário, DoS',
        'mitigation': 'Smart pointers, garbage collection, análise estática, RAII pattern',
        'example': 'free(ptr); usar ptr depois, delete obj; obj->method()',
        'color': '#8B0000',
        'icon': 'fa-memory'
    },
    'CWE-78': {
        'name': 'OS Command Injection',
        'description': 'Injeção de comandos do sistema operacional',
        'severity': 'CRITICAL',
        'rank': 5,
        'keywords': ['command', 'injection', 'exec', 'shell', 'system'],
        'attack_vector': 'Execução de comandos arbitrários no servidor, acesso ao sistema',
        'mitigation': 'Evitar chamadas de sistema, whitelist de comandos, sanitização estrita',
        'example': 'os.system("ping " + userInput), exec() com dados não confiáveis',
        'color': '#DC3545',
        'icon': 'fa-terminal'
    },
    'CWE-20': {
        'name': 'Improper Input Validation',
        'description': 'Validação inadequada de entrada',
        'severity': 'HIGH',
        'rank': 6,
        'keywords': ['validation', 'input', 'sanitization', 'filter'],
        'attack_vector': 'Base para múltiplos ataques: injection, XSS, path traversal',
        'mitigation': 'Whitelist validation, type checking, regex patterns, frameworks de validação',
        'example': 'Aceitar qualquer input sem validação de tipo, formato ou range',
        'color': '#FF6B6B',
        'icon': 'fa-filter'
    },
    'CWE-125': {
        'name': 'Out-of-bounds Read',
        'description': 'Leitura fora dos limites do buffer',
        'severity': 'HIGH',
        'rank': 7,
        'keywords': ['buffer', 'read', 'bounds', 'memory'],
        'attack_vector': 'Information disclosure, DoS, bypass de proteções',
        'mitigation': 'Bounds checking, linguagens memory-safe, ferramentas de análise',
        'example': 'array[i] sem verificar se i < array.length',
        'color': '#FF6B6B',
        'icon': 'fa-book-reader'
    },
    'CWE-22': {
        'name': 'Path Traversal',
        'description': 'Travessia de diretórios',
        'severity': 'HIGH',
        'rank': 8,
        'keywords': ['path', 'traversal', 'directory', 'file', '../'],
        'attack_vector': 'Acesso a arquivos fora do diretório permitido, leitura de /etc/passwd',
        'mitigation': 'Validação de paths, chroot, whitelist de diretórios, canonicalização',
        'example': 'open("uploads/" + filename) com filename="../../../etc/passwd"',
        'color': '#FF9800',
        'icon': 'fa-folder-open'
    },
    'CWE-352': {
        'name': 'Cross-Site Request Forgery (CSRF)',
        'description': 'Falsificação de requisição entre sites',
        'severity': 'HIGH',
        'rank': 9,
        'keywords': ['csrf', 'token', 'request', 'forgery'],
        'attack_vector': 'Ações não autorizadas em nome do usuário autenticado',
        'mitigation': 'CSRF tokens, SameSite cookies, verificação de Origin/Referer',
        'example': 'Form sem token CSRF, endpoints sensíveis sem proteção',
        'color': '#FF9800',
        'icon': 'fa-exchange-alt'
    },
    'CWE-434': {
        'name': 'Unrestricted Upload of File',
        'description': 'Upload de arquivo sem restrições',
        'severity': 'HIGH',
        'rank': 10,
        'keywords': ['upload', 'file', 'extension', 'mime'],
        'attack_vector': 'Upload de webshell, execução de código, malware',
        'mitigation': 'Whitelist de extensões, verificação de MIME type, sandboxing, antivirus',
        'example': 'Aceitar .php, .exe sem validação, confiar apenas em extensão',
        'color': '#FF9800',
        'icon': 'fa-upload'
    },
    'CWE-862': {
        'name': 'Missing Authorization',
        'description': 'Falta de autorização',
        'severity': 'HIGH',
        'rank': 11,
        'keywords': ['authorization', 'access', 'permission', 'role'],
        'attack_vector': 'Acesso não autorizado a funcionalidades e dados',
        'mitigation': 'Verificação de autorização em todas as rotas, RBAC, políticas de acesso',
        'example': 'Endpoint sem verificar se usuário tem permissão, IDOR',
        'color': '#FFC107',
        'icon': 'fa-user-lock'
    },
    'CWE-476': {
        'name': 'NULL Pointer Dereference',
        'description': 'Desreferenciamento de ponteiro nulo',
        'severity': 'MEDIUM',
        'rank': 12,
        'keywords': ['null', 'pointer', 'dereference', 'npe'],
        'attack_vector': 'DoS, crash da aplicação, em alguns casos execução de código',
        'mitigation': 'Null checks, Optional types, defensive programming',
        'example': 'obj.method() sem verificar se obj != null',
        'color': '#FFC107',
        'icon': 'fa-ban'
    },
    'CWE-287': {
        'name': 'Improper Authentication',
        'description': 'Autenticação inadequada',
        'severity': 'CRITICAL',
        'rank': 13,
        'keywords': ['authentication', 'login', 'credential', 'password'],
        'attack_vector': 'Bypass de autenticação, acesso não autorizado',
        'mitigation': 'MFA, OAuth2, senha forte, rate limiting, session management',
        'example': 'Comparação de senha sem hash, autenticação sem validação',
        'color': '#DC3545',
        'icon': 'fa-key'
    },
    'CWE-190': {
        'name': 'Integer Overflow',
        'description': 'Overflow de inteiros',
        'severity': 'MEDIUM',
        'rank': 14,
        'keywords': ['integer', 'overflow', 'arithmetic', 'calculation'],
        'attack_vector': 'Buffer overflow, cálculos incorretos, bypass de validações',
        'mitigation': 'Checked arithmetic, validação de ranges, BigInteger',
        'example': 'int sum = a + b sem verificar overflow',
        'color': '#FFC107',
        'icon': 'fa-calculator'
    },
    'CWE-502': {
        'name': 'Deserialization of Untrusted Data',
        'description': 'Desserialização de dados não confiáveis',
        'severity': 'CRITICAL',
        'rank': 15,
        'keywords': ['deserialization', 'serialize', 'pickle', 'yaml'],
        'attack_vector': 'Remote code execution, object injection',
        'mitigation': 'Evitar desserialização, whitelist de classes, assinatura de dados',
        'example': 'pickle.loads(user_data), ObjectInputStream sem validação',
        'color': '#DC3545',
        'icon': 'fa-box-open'
    },
    'CWE-77': {
        'name': 'Command Injection',
        'description': 'Injeção de comandos',
        'severity': 'CRITICAL',
        'rank': 16,
        'keywords': ['command', 'injection', 'exec', 'shell'],
        'attack_vector': 'Execução de comandos arbitrários',
        'mitigation': 'Evitar exec, whitelist, parametrização',
        'example': 'eval(user_input), system() com input não sanitizado',
        'color': '#DC3545',
        'icon': 'fa-terminal'
    },
    'CWE-119': {
        'name': 'Memory Buffer Errors',
        'description': 'Erros de buffer de memória',
        'severity': 'HIGH',
        'rank': 17,
        'keywords': ['buffer', 'memory', 'overflow', 'underflow'],
        'attack_vector': 'Memory corruption, code execution',
        'mitigation': 'Linguagens memory-safe, bounds checking',
        'example': 'Operações de memória sem validação de limites',
        'color': '#FF6B6B',
        'icon': 'fa-memory'
    },
    'CWE-798': {
        'name': 'Hard-coded Credentials',
        'description': 'Credenciais codificadas no código',
        'severity': 'CRITICAL',
        'rank': 18,
        'keywords': ['password', 'credential', 'hardcoded', 'secret'],
        'attack_vector': 'Acesso não autorizado usando credenciais conhecidas',
        'mitigation': 'Variables de ambiente, secret managers, vaults',
        'example': 'password = "admin123", API_KEY = "12345" no código',
        'color': '#8B0000',
        'icon': 'fa-lock'
    },
    'CWE-918': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'description': 'Falsificação de requisição do lado do servidor',
        'severity': 'HIGH',
        'rank': 19,
        'keywords': ['ssrf', 'request', 'url', 'fetch'],
        'attack_vector': 'Acesso a recursos internos, cloud metadata, port scanning',
        'mitigation': 'Whitelist de URLs, validação de destino, network segmentation',
        'example': 'fetch(user_url) sem validação, curl com URL do usuário',
        'color': '#FF9800',
        'icon': 'fa-server'
    },
    'CWE-306': {
        'name': 'Missing Authentication',
        'description': 'Falta de autenticação',
        'severity': 'CRITICAL',
        'rank': 20,
        'keywords': ['authentication', 'login', 'access'],
        'attack_vector': 'Acesso direto a funcionalidades sem autenticação',
        'mitigation': 'Implementar autenticação em todos endpoints sensíveis',
        'example': 'API endpoint /admin sem verificação de autenticação',
        'color': '#8B0000',
        'icon': 'fa-user-slash'
    },
    'CWE-362': {
        'name': 'Race Condition',
        'description': 'Condição de corrida',
        'severity': 'MEDIUM',
        'rank': 21,
        'keywords': ['race', 'condition', 'concurrent', 'thread'],
        'attack_vector': 'TOCTOU attacks, privilege escalation, data corruption',
        'mitigation': 'Locks, synchronization, atomic operations, transações',
        'example': 'Check-then-use patterns, operações não atômicas',
        'color': '#FFC107',
        'icon': 'fa-random'
    },
    'CWE-269': {
        'name': 'Improper Privilege Management',
        'description': 'Gerenciamento inadequado de privilégios',
        'severity': 'HIGH',
        'rank': 22,
        'keywords': ['privilege', 'permission', 'elevation', 'sudo'],
        'attack_vector': 'Privilege escalation, acesso administrativo não autorizado',
        'mitigation': 'Least privilege principle, RBAC, verificação de permissões',
        'example': 'Executar com root desnecessariamente, setuid bits',
        'color': '#FF9800',
        'icon': 'fa-crown'
    },
    'CWE-94': {
        'name': 'Code Injection',
        'description': 'Injeção de código',
        'severity': 'CRITICAL',
        'rank': 23,
        'keywords': ['code', 'injection', 'eval', 'execute'],
        'attack_vector': 'Execução de código arbitrário controlado pelo atacante',
        'mitigation': 'Evitar eval(), code generation seguro, sandboxing',
        'example': 'eval(user_input), Function(user_code)()',
        'color': '#8B0000',
        'icon': 'fa-code'
    },
    'CWE-863': {
        'name': 'Incorrect Authorization',
        'description': 'Autorização incorreta',
        'severity': 'HIGH',
        'rank': 24,
        'keywords': ['authorization', 'access', 'permission'],
        'attack_vector': 'Acesso a recursos de outros usuários, privilege escalation',
        'mitigation': 'Verificação de ownership, ABAC, testes de autorização',
        'example': 'Verificar apenas autenticação, não verificar se recurso pertence ao usuário',
        'color': '#FF9800',
        'icon': 'fa-user-times'
    },
    'CWE-276': {
        'name': 'Incorrect Default Permissions',
        'description': 'Permissões padrão incorretas',
        'severity': 'MEDIUM',
        'rank': 25,
        'keywords': ['permission', 'file', 'chmod', 'access'],
        'attack_vector': 'Acesso não autorizado a arquivos e recursos',
        'mitigation': 'Umask correto, permissões explícitas, least privilege',
        'example': 'chmod 777, arquivos world-writable por padrão',
        'color': '#FFC107',
        'icon': 'fa-unlock'
    }
}

# Mapeamento de regras SonarQube para CWEs
SONARQUBE_TO_CWE_MAPPING = {
    # Buffer/Memory Issues
    'java:S2068': ['CWE-798'],  # Hard-coded credentials
    'python:S2068': ['CWE-798'],
    'javascript:S2068': ['CWE-798'],
    'csharp:S2068': ['CWE-798'],
    'secrets:S6290': ['CWE-798'],

    # Injection
    'java:S2077': ['CWE-89'],  # SQL Injection
    'java:S3649': ['CWE-89', 'CWE-78'],
    'javascript:S3649': ['CWE-89'],
    'python:S3649': ['CWE-89'],
    'php:S3649': ['CWE-89'],

    # XSS
    'javascript:S5148': ['CWE-79'],
    'java:S5131': ['CWE-79'],
    'python:S5131': ['CWE-79'],

    # Command Injection
    'java:S2076': ['CWE-78'],
    'python:S4721': ['CWE-78'],
    'javascript:S4721': ['CWE-78'],

    # Path Traversal
    'java:S2083': ['CWE-22'],
    'python:S5131': ['CWE-22'],

    # CSRF
    'java:S4502': ['CWE-352'],
    'javascript:S4502': ['CWE-352'],

    # File Upload
    'java:S2598': ['CWE-434'],

    # Authentication
    'java:S5804': ['CWE-287', 'CWE-306'],
    'java:S5876': ['CWE-287'],

    # Authorization
    'java:S4601': ['CWE-862', 'CWE-863'],
    'xml:S5604': ['CWE-862'],

    # Deserialization
    'java:S5135': ['CWE-502'],
    'python:S5135': ['CWE-502'],

    # SSRF
    'java:S5144': ['CWE-918'],

    # NULL Pointer
    'java:S2259': ['CWE-476'],

    # Integer Overflow
    'java:S2184': ['CWE-190'],

    # Race Condition
    'java:S2445': ['CWE-362'],

    # Privilege Management
    'java:S3649': ['CWE-269'],
}

# OWASP ASVS 4.0 (Application Security Verification Standard)
OWASP_ASVS_MAPPING = {
    'V1.1': {
        'category': 'V1: Architecture, Design and Threat Modeling',
        'name': 'Secure Software Development Lifecycle',
        'description': 'Verificação de práticas seguras no SDLC',
        'level': 2,
        'keywords': ['architecture', 'design', 'threat', 'model', 'sdlc'],
        'attack_vector': 'Falhas arquiteturais permitem ataques em múltiplos vetores',
        'mitigation': 'Threat modeling, design reviews, arquitetura segura por padrão',
        'example': 'Falta de threat modeling, arquitetura sem defesa em profundidade',
        'color': '#667eea',
        'icon': 'fa-sitemap',
        'severity': 'HIGH'
    },
    'V1.2': {
        'category': 'V1: Architecture, Design and Threat Modeling',
        'name': 'Authentication Architecture',
        'description': 'Arquitetura de autenticação robusta',
        'level': 1,
        'keywords': ['authentication', 'architecture', 'identity'],
        'attack_vector': 'Arquitetura de autenticação fraca permite bypass',
        'mitigation': 'Centralizar autenticação, usar padrões estabelecidos (OAuth2, OIDC)',
        'example': 'Múltiplos sistemas de autenticação, custom auth sem revisão',
        'color': '#667eea',
        'icon': 'fa-key',
        'severity': 'CRITICAL'
    },
    'V2.1': {
        'category': 'V2: Authentication',
        'name': 'Password Security',
        'description': 'Segurança de senhas e credenciais',
        'level': 1,
        'keywords': ['password', 'credential', 'hash', 'bcrypt', 'argon2'],
        'attack_vector': 'Senhas fracas, hashing inadequado, credenciais expostas',
        'mitigation': 'Argon2/bcrypt, políticas de senha forte, MFA obrigatório',
        'example': 'MD5/SHA1 para senhas, sem salt, senhas no código',
        'color': '#DC3545',
        'icon': 'fa-lock',
        'severity': 'CRITICAL'
    },
    'V2.2': {
        'category': 'V2: Authentication',
        'name': 'General Authenticator Security',
        'description': 'Segurança geral de autenticadores',
        'level': 1,
        'keywords': ['authenticator', 'credential', 'brute', 'force'],
        'attack_vector': 'Brute force, credential stuffing, account enumeration',
        'mitigation': 'Rate limiting, account lockout, CAPTCHA, mensagens genéricas',
        'example': 'Sem rate limit, mensagens "usuário não existe"',
        'color': '#DC3545',
        'icon': 'fa-user-shield',
        'severity': 'HIGH'
    },
    'V2.7': {
        'category': 'V2: Authentication',
        'name': 'Out of Band Verifier',
        'description': 'Verificadores fora de banda (MFA)',
        'level': 2,
        'keywords': ['mfa', '2fa', 'otp', 'totp'],
        'attack_vector': 'Bypass de MFA, MFA tokens roubados ou interceptados',
        'mitigation': 'MFA resistente a phishing (WebAuthn/FIDO2), OTP com expiração curta',
        'example': 'MFA via SMS (sim swap), tokens sem expiração',
        'color': '#FF9800',
        'icon': 'fa-mobile-alt',
        'severity': 'HIGH'
    },
    'V3.1': {
        'category': 'V3: Session Management',
        'name': 'Fundamental Session Management',
        'description': 'Gerenciamento fundamental de sessões',
        'level': 1,
        'keywords': ['session', 'cookie', 'token', 'jwt'],
        'attack_vector': 'Session hijacking, fixation, não invalidação de sessões',
        'mitigation': 'Tokens aleatórios, HTTPOnly/Secure flags, timeout, logout adequado',
        'example': 'Session ID previsível, cookies sem HTTPOnly, sessão após logout',
        'color': '#3F51B5',
        'icon': 'fa-clock',
        'severity': 'CRITICAL'
    },
    'V3.2': {
        'category': 'V3: Session Management',
        'name': 'Session Binding',
        'description': 'Vinculação de sessões',
        'level': 2,
        'keywords': ['session', 'binding', 'device', 'ip'],
        'attack_vector': 'Session hijacking através de roubo de token',
        'mitigation': 'Device fingerprinting, IP binding (com cuidado), re-autenticação',
        'example': 'Token válido em qualquer dispositivo/IP sem validação',
        'color': '#3F51B5',
        'icon': 'fa-link',
        'severity': 'MEDIUM'
    },
    'V4.1': {
        'category': 'V4: Access Control',
        'name': 'General Access Control Design',
        'description': 'Design geral de controle de acesso',
        'level': 1,
        'keywords': ['access', 'authorization', 'permission', 'rbac', 'abac'],
        'attack_vector': 'IDOR, privilege escalation, bypass de autorização',
        'mitigation': 'Deny by default, verificação em todas as rotas, RBAC/ABAC',
        'example': 'Controle apenas no frontend, autorização inconsistente',
        'color': '#8B0000',
        'icon': 'fa-shield-alt',
        'severity': 'CRITICAL'
    },
    'V4.2': {
        'category': 'V4: Access Control',
        'name': 'Operation Level Access Control',
        'description': 'Controle de acesso em nível de operação',
        'level': 1,
        'keywords': ['operation', 'authorization', 'action'],
        'attack_vector': 'Usuário acessa operações não autorizadas (delete, modify)',
        'mitigation': 'Verificar permissões para cada operação, principle of least privilege',
        'example': 'Usuário comum pode deletar recursos críticos',
        'color': '#8B0000',
        'icon': 'fa-user-lock',
        'severity': 'CRITICAL'
    },
    'V5.1': {
        'category': 'V5: Validation, Sanitization and Encoding',
        'name': 'Input Validation',
        'description': 'Validação de entrada',
        'level': 1,
        'keywords': ['input', 'validation', 'sanitization', 'whitelist'],
        'attack_vector': 'Injection attacks (SQL, XSS, Command), data corruption',
        'mitigation': 'Whitelist validation, type checking, reject invalid input',
        'example': 'Aceitar qualquer input, validação apenas no frontend',
        'color': '#FF6B6B',
        'icon': 'fa-filter',
        'severity': 'CRITICAL'
    },
    'V5.2': {
        'category': 'V5: Validation, Sanitization and Encoding',
        'name': 'Sanitization and Sandboxing',
        'description': 'Sanitização e isolamento',
        'level': 2,
        'keywords': ['sanitization', 'sandbox', 'encoding'],
        'attack_vector': 'XSS, code injection através de dados não sanitizados',
        'mitigation': 'Context-aware output encoding, DOMPurify, CSP',
        'example': 'innerHTML com dados não sanitizados, eval() com user input',
        'color': '#FF6B6B',
        'icon': 'fa-broom',
        'severity': 'HIGH'
    },
    'V5.3': {
        'category': 'V5: Validation, Sanitization and Encoding',
        'name': 'Output Encoding and Injection Prevention',
        'description': 'Encoding de saída e prevenção de injeção',
        'level': 1,
        'keywords': ['encoding', 'injection', 'sql', 'xss', 'command'],
        'attack_vector': 'SQL injection, XSS, command injection, LDAP injection',
        'mitigation': 'Prepared statements, parametrized queries, context-aware encoding',
        'example': 'String concatenation em queries, eval(), exec() com user data',
        'color': '#DC3545',
        'icon': 'fa-syringe',
        'severity': 'CRITICAL'
    },
    'V6.1': {
        'category': 'V6: Stored Cryptography',
        'name': 'Data Classification',
        'description': 'Classificação de dados',
        'level': 2,
        'keywords': ['data', 'classification', 'sensitive', 'pii'],
        'attack_vector': 'Exposição de dados sensíveis não classificados/protegidos',
        'mitigation': 'Classificar dados, aplicar proteções apropriadas (encryption at rest)',
        'example': 'PII sem classificação, dados sensíveis em logs',
        'color': '#FF9800',
        'icon': 'fa-tags',
        'severity': 'HIGH'
    },
    'V6.2': {
        'category': 'V6: Stored Cryptography',
        'name': 'Algorithms',
        'description': 'Algoritmos criptográficos',
        'level': 1,
        'keywords': ['crypto', 'algorithm', 'aes', 'rsa', 'encryption'],
        'attack_vector': 'Uso de algoritmos fracos ou quebrados (DES, MD5, SHA1)',
        'mitigation': 'AES-256, RSA-2048+, SHA-256+, evitar algoritmos deprecated',
        'example': 'DES, 3DES, MD5 para hashing, chaves RSA < 2048 bits',
        'color': '#DC3545',
        'icon': 'fa-key',
        'severity': 'CRITICAL'
    },
    'V7.1': {
        'category': 'V7: Error Handling and Logging',
        'name': 'Log Content',
        'description': 'Conteúdo de logs',
        'level': 1,
        'keywords': ['log', 'logging', 'audit', 'monitoring'],
        'attack_vector': 'Falta de logs impede detecção de ataques e investigação',
        'mitigation': 'Logging de eventos de segurança, auditing, SIEM integration',
        'example': 'Sem logs de autenticação, sem audit trail',
        'color': '#607D8B',
        'icon': 'fa-clipboard-list',
        'severity': 'MEDIUM'
    },
    'V7.2': {
        'category': 'V7: Error Handling and Logging',
        'name': 'Log Processing',
        'description': 'Processamento de logs',
        'level': 2,
        'keywords': ['log', 'processing', 'injection', 'sanitization'],
        'attack_vector': 'Log injection, log tampering, exposição de dados sensíveis',
        'mitigation': 'Sanitizar dados antes de logar, não logar secrets/PII, log integrity',
        'example': 'Logs com senhas, API keys, dados não sanitizados',
        'color': '#607D8B',
        'icon': 'fa-tasks',
        'severity': 'HIGH'
    },
    'V8.1': {
        'category': 'V8: Data Protection',
        'name': 'General Data Protection',
        'description': 'Proteção geral de dados',
        'level': 1,
        'keywords': ['data', 'protection', 'privacy', 'gdpr'],
        'attack_vector': 'Exposição de dados sensíveis em trânsito ou em repouso',
        'mitigation': 'HTTPS/TLS everywhere, encryption at rest, data minimization',
        'example': 'HTTP para dados sensíveis, dados em plaintext no DB',
        'color': '#009688',
        'icon': 'fa-database',
        'severity': 'CRITICAL'
    },
    'V8.2': {
        'category': 'V8: Data Protection',
        'name': 'Client-side Data Protection',
        'description': 'Proteção de dados no cliente',
        'level': 2,
        'keywords': ['client', 'browser', 'storage', 'cache'],
        'attack_vector': 'Dados sensíveis em localStorage, cache, ou browser history',
        'mitigation': 'Não armazenar secrets no cliente, usar sessionStorage, autocomplete=off',
        'example': 'Tokens em localStorage, autocomplete em campos de senha',
        'color': '#009688',
        'icon': 'fa-browser',
        'severity': 'MEDIUM'
    },
    'V9.1': {
        'category': 'V9: Communication',
        'name': 'Client Communication Security',
        'description': 'Segurança de comunicação cliente',
        'level': 1,
        'keywords': ['tls', 'https', 'ssl', 'certificate'],
        'attack_vector': 'Man-in-the-middle, downgrade attacks, certificate issues',
        'mitigation': 'TLS 1.2+, HSTS, certificate pinning, strong cipher suites',
        'example': 'TLS 1.0/1.1, weak ciphers, certificados self-signed em prod',
        'color': '#17a2b8',
        'icon': 'fa-lock',
        'severity': 'CRITICAL'
    },
    'V9.2': {
        'category': 'V9: Communication',
        'name': 'Server Communication Security',
        'description': 'Segurança de comunicação servidor',
        'level': 2,
        'keywords': ['server', 'communication', 'api', 'service'],
        'attack_vector': 'SSRF, comunicação não criptografada entre serviços',
        'mitigation': 'mTLS, API authentication, network segmentation',
        'example': 'Comunicação HTTP entre microserviços, sem autenticação',
        'color': '#17a2b8',
        'icon': 'fa-server',
        'severity': 'HIGH'
    },
    'V10.1': {
        'category': 'V10: Malicious Code',
        'name': 'Code Integrity',
        'description': 'Integridade de código',
        'level': 2,
        'keywords': ['integrity', 'code', 'malicious', 'backdoor'],
        'attack_vector': 'Código malicioso, backdoors, supply chain attacks',
        'mitigation': 'Code reviews, SCA, dependency scanning, SRI for CDN',
        'example': 'Dependências não verificadas, CDN sem SRI',
        'color': '#9C27B0',
        'icon': 'fa-virus',
        'severity': 'HIGH'
    },
    'V11.1': {
        'category': 'V11: Business Logic',
        'name': 'Business Logic Security',
        'description': 'Segurança de lógica de negócio',
        'level': 2,
        'keywords': ['business', 'logic', 'workflow', 'abuse'],
        'attack_vector': 'Abuso de lógica de negócio, bypass de workflows',
        'mitigation': 'Validação de estado, rate limiting, business rules enforcement',
        'example': 'Compra com preço negativo, pular etapas de aprovação',
        'color': '#795548',
        'icon': 'fa-briefcase',
        'severity': 'HIGH'
    },
    'V12.1': {
        'category': 'V12: Files and Resources',
        'name': 'File Upload',
        'description': 'Upload de arquivos',
        'level': 1,
        'keywords': ['upload', 'file', 'extension', 'mime'],
        'attack_vector': 'Upload de webshell, executáveis maliciosos, XXE',
        'mitigation': 'Whitelist de extensões, verificação de MIME type, antivirus, sandboxing',
        'example': 'Aceitar qualquer extensão, confiar apenas em extensão do arquivo',
        'color': '#FF9800',
        'icon': 'fa-upload',
        'severity': 'CRITICAL'
    },
    'V12.2': {
        'category': 'V12: Files and Resources',
        'name': 'File Integrity',
        'description': 'Integridade de arquivos',
        'level': 2,
        'keywords': ['file', 'integrity', 'checksum', 'signature'],
        'attack_vector': 'Modificação de arquivos, tampering',
        'mitigation': 'Checksums, digital signatures, file monitoring',
        'example': 'Arquivos sem verificação de integridade',
        'color': '#FF9800',
        'icon': 'fa-file-signature',
        'severity': 'MEDIUM'
    },
    'V12.5': {
        'category': 'V12: Files and Resources',
        'name': 'File Download',
        'description': 'Download de arquivos',
        'level': 1,
        'keywords': ['download', 'file', 'path', 'traversal'],
        'attack_vector': 'Path traversal, acesso a arquivos não autorizados',
        'mitigation': 'Validação de paths, whitelist de diretórios, access control',
        'example': 'download.php?file=../../../etc/passwd',
        'color': '#FFC107',
        'icon': 'fa-download',
        'severity': 'HIGH'
    },
    'V13.1': {
        'category': 'V13: API and Web Service',
        'name': 'Generic Web Service Security',
        'description': 'Segurança genérica de web services',
        'level': 1,
        'keywords': ['api', 'webservice', 'rest', 'soap'],
        'attack_vector': 'API abuse, lack of authentication, excessive data exposure',
        'mitigation': 'API authentication, rate limiting, input validation, least privilege',
        'example': 'APIs sem autenticação, endpoints expostos desnecessariamente',
        'color': '#00BCD4',
        'icon': 'fa-plug',
        'severity': 'CRITICAL'
    },
    'V13.2': {
        'category': 'V13: API and Web Service',
        'name': 'RESTful Web Service',
        'description': 'Serviços web RESTful',
        'level': 2,
        'keywords': ['rest', 'api', 'http', 'method'],
        'attack_vector': 'HTTP method tampering, CORS misconfiguration',
        'mitigation': 'Validação de métodos HTTP, CORS apropriado, API versioning',
        'example': 'DELETE disponível sem autorização, CORS: *',
        'color': '#00BCD4',
        'icon': 'fa-code',
        'severity': 'HIGH'
    },
    'V14.1': {
        'category': 'V14: Configuration',
        'name': 'Build and Deploy',
        'description': 'Build e deploy',
        'level': 1,
        'keywords': ['config', 'build', 'deploy', 'environment'],
        'attack_vector': 'Configurações inseguras, debug mode em produção',
        'mitigation': 'Remover debug em prod, configurações específicas por ambiente',
        'example': 'Debug mode em produção, stack traces expostos',
        'color': '#607D8B',
        'icon': 'fa-cogs',
        'severity': 'HIGH'
    },
    'V14.2': {
        'category': 'V14: Configuration',
        'name': 'Dependency',
        'description': 'Dependências',
        'level': 1,
        'keywords': ['dependency', 'component', 'library', 'vulnerability'],
        'attack_vector': 'Vulnerabilidades conhecidas em dependências',
        'mitigation': 'Dependency scanning, keep dependencies updated, SCA tools',
        'example': 'Dependências desatualizadas com CVEs conhecidas',
        'color': '#607D8B',
        'icon': 'fa-cubes',
        'severity': 'CRITICAL'
    },
    'V14.4': {
        'category': 'V14: Configuration',
        'name': 'HTTP Security Headers',
        'description': 'Headers HTTP de segurança',
        'level': 1,
        'keywords': ['header', 'csp', 'hsts', 'x-frame'],
        'attack_vector': 'Clickjacking, XSS, MIME sniffing',
        'mitigation': 'CSP, HSTS, X-Frame-Options, X-Content-Type-Options',
        'example': 'Sem CSP, sem HSTS, aplicação embeddable em iframe',
        'color': '#3F51B5',
        'icon': 'fa-heading',
        'severity': 'HIGH'
    }
}

# Mapeamento de regras SonarQube para ASVS
SONARQUBE_TO_ASVS_MAPPING = {
    # Authentication
    'java:S2068': ['V2.1', 'V6.2'],  # Hard-coded credentials
    'python:S2068': ['V2.1', 'V6.2'],
    'javascript:S2068': ['V2.1'],
    'csharp:S2068': ['V2.1'],
    'secrets:S6290': ['V2.1', 'V8.1'],
    'java:S5804': ['V2.1', 'V2.2'],
    'java:S5876': ['V2.1'],

    # Session Management
    'java:S2092': ['V3.1'],
    'javascript:S2092': ['V3.1'],

    # Access Control
    'java:S4601': ['V4.1', 'V4.2'],
    'xml:S5604': ['V4.1'],
    'java:S5808': ['V4.1'],

    # Input Validation & Injection
    'java:S2077': ['V5.1', 'V5.3'],  # SQL Injection
    'java:S3649': ['V5.1', 'V5.3'],
    'javascript:S3649': ['V5.1', 'V5.3'],
    'python:S3649': ['V5.1', 'V5.3'],
    'php:S3649': ['V5.1', 'V5.3'],
    'javascript:S5148': ['V5.2', 'V5.3'],  # XSS
    'java:S5131': ['V5.2', 'V5.3'],
    'python:S5131': ['V5.2', 'V5.3'],
    'java:S2076': ['V5.3'],  # Command Injection
    'python:S4721': ['V5.3'],
    'javascript:S4721': ['V5.3'],
    'java:S2083': ['V12.5'],  # Path Traversal

    # Cryptography
    'java:S4790': ['V6.2'],
    'java:S5542': ['V6.2'],
    'java:S5547': ['V6.2'],
    'javascript:S4790': ['V6.2'],
    'python:S4426': ['V6.2'],
    'csharp:S4790': ['V6.2'],
    'java:S2278': ['V6.2'],
    'csharp:S2278': ['V6.2'],

    # Logging
    'java:S2139': ['V7.1', 'V7.2'],
    'java:S106': ['V7.1'],
    'javascript:S106': ['V7.1'],
    'python:S106': ['V7.1'],
    'csharp:S106': ['V7.1'],
    'java:S4792': ['V7.2'],
    'csharp:S4792': ['V7.2'],

    # Data Protection
    'java:S4434': ['V8.1'],
    'java:S4502': ['V8.1', 'V9.1'],  # HTTPS/TLS
    'java:S5527': ['V9.1'],
    'javascript:S4426': ['V9.1'],
    'python:S5445': ['V9.1'],
    'csharp:S4426': ['V9.1'],

    # Communication
    'java:S5122': ['V9.1'],
    'csharp:S5122': ['V9.1'],

    # File Upload
    'java:S2598': ['V12.1'],

    # API Security
    'java:S5144': ['V13.1'],  # SSRF

    # Configuration
    'docker:S6471': ['V14.1'],
    'docker:S6476': ['V14.2'],
    'docker:S6475': ['V14.2'],
    'java:S4823': ['V14.2'],
    'javascript:S4507': ['V14.2'],
    'python:S4507': ['V14.2'],
    'csharp:S4507': ['V14.2'],
    'php:S4823': ['V14.2'],

    # Deserialization
    'java:S5135': ['V5.1', 'V13.1'],
    'python:S5135': ['V5.1'],

    # CSRF
    'java:S4502': ['V4.1'],
    'javascript:S4502': ['V4.1'],
}

GOVERNANCE_MATURITY_LEVELS = {
    'INICIAL': {'min_score': 0, 'max_score': 20, 'description': 'Inicial - Processos ad-hoc'},
    'DEVELOPING': {'min_score': 21, 'max_score': 40, 'description': 'Em Desenvolvimento - Alguns processos definidos'},
    'DEFINED': {'min_score': 41, 'max_score': 60, 'description': 'Definido - Processos documentados'},
    'MANAGED': {'min_score': 61, 'max_score': 80, 'description': 'Gerenciado - Processos monitorados'},
    'OPTIMIZED': {'min_score': 81, 'max_score': 100, 'description': 'Otimizado - Melhoria contínua'}
}


class GeminiAnalyzer:
    """Integração com Gemini AI para análises inteligentes de segurança"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.model = None
        if GEMINI_AVAILABLE and api_key:
            try:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-pro')
                print("🤖 Gemini AI configurado com sucesso!")
            except Exception as e:
                print(f"⚠️  Erro ao configurar Gemini: {e}")
                self.model = None

    def analyze_security_data(self, data: Dict, analysis_type: str = "comprehensive") -> Dict:
        """
        Analisa dados de segurança usando Gemini AI

        analysis_type: comprehensive, owasp, cwe, asvs, priorities, recommendations
        """
        if not self.model:
            return self._get_fallback_analysis(data, analysis_type)

        try:
            prompt = self._build_prompt(data, analysis_type)
            response = self.model.generate_content(prompt)

            # Parse da resposta
            analysis = {
                'type': analysis_type,
                'ai_generated': True,
                'content': response.text,
                'timestamp': datetime.now().isoformat()
            }

            return analysis

        except Exception as e:
            print(f"⚠️  Erro na análise Gemini: {e}")
            return self._get_fallback_analysis(data, analysis_type)

    def _build_prompt(self, data: Dict, analysis_type: str) -> str:
        """Constrói prompt específico para cada tipo de análise"""

        # Preparar resumo dos dados
        total_projects = len(data.get('projects', []))
        total_issues = sum(p.get('owasp_metrics', {}).values() for p in data.get('projects', []) if isinstance(p.get('owasp_metrics', {}), dict))

        owasp_summary = []
        for cat, count in data.get('owasp_metrics_global', {}).items():
            if count > 0 and cat != 'OTHER':
                owasp_summary.append(f"  - {cat}: {count} issues")

        cwe_summary = []
        for cwe, count in list(data.get('cwe_metrics_global', {}).items())[:10]:
            if count > 0 and cwe != 'OTHER':
                cwe_summary.append(f"  - {cwe}: {count} issues")

        asvs_summary = []
        for asvs, count in list(data.get('asvs_metrics_global', {}).items())[:10]:
            if count > 0 and asvs != 'OTHER':
                asvs_summary.append(f"  - {asvs}: {count} issues")

        base_context = f"""
Você é um especialista em segurança de aplicações e análise de vulnerabilidades.

CONTEXTO DO PROJETO:
- Total de Projetos: {total_projects}
- Total de Issues de Segurança: {total_issues}
- Governança: Nível {data.get('governance_metrics', {}).get('level', 'N/A')} (Score: {data.get('governance_metrics', {}).get('score', 0):.1f}/100)

TOP CATEGORIAS OWASP TOP 10 2025:
{chr(10).join(owasp_summary[:5]) if owasp_summary else '  Nenhuma issue detectada'}

TOP CWEs DETECTADAS:
{chr(10).join(cwe_summary[:5]) if cwe_summary else '  Nenhuma CWE detectada'}

TOP REQUISITOS ASVS:
{chr(10).join(asvs_summary[:5]) if asvs_summary else '  Nenhum requisito ASVS detectado'}

PROJETOS COM SECRETS: {data.get('projects_with_secrets', 0)}
PROJETOS COM MISCONFIGURATIONS: {data.get('projects_with_misconfigs', 0)}
"""

        prompts = {
            'comprehensive': base_context + """
TAREFA: Faça uma análise CRÍTICA e ABRANGENTE da segurança deste portfólio de aplicações.

Forneça:
1. **ANÁLISE CRÍTICA**: Avaliação honesta e direta dos riscos mais graves
2. **PRIORIZAÇÃO ESTRATÉGICA**: Top 5 ações por ordem de impacto (maior ROI de segurança)
3. **CAMINHO DE ATAQUE**: Como um atacante exploraria as vulnerabilidades encontradas
4. **ROADMAP DE CORREÇÃO**: Plano de 30/60/90 dias com ações específicas
5. **MÉTRICAS DE SUCESSO**: KPIs para medir melhoria
6. **QUICK WINS**: 3 correções rápidas para ganho imediato

Seja DIRETO, PRÁTICO e ACIONÁVEL. Foque em RESULTADOS, não em teoria.
""",

            'owasp': base_context + """
TAREFA: Análise focada em OWASP Top 10 2025.

Forneça:
1. **ANÁLISE POR CATEGORIA**: Para cada categoria OWASP com issues:
   - Severidade real do problema
   - Como atacantes exploram
   - Impacto no negócio
   - Correção prioritária

2. **CORRELAÇÕES PERIGOSAS**: Categorias que juntas criam risco exponencial
3. **PRIORIZAÇÃO**: Ordem de correção baseada em risco x esforço

Seja específico sobre COMO atacar e COMO corrigir.
""",

            'cwe': base_context + """
TAREFA: Análise focada em CWE (Common Weakness Enumeration).

Forneça:
1. **ANÁLISE DAS TOP 5 CWEs**:
   - Por que esta CWE é perigosa
   - Exploits conhecidos
   - Cadeia de ataque típica
   - Prioridade de correção

2. **VULNERABILIDADES ENCADEADAS**: CWEs que juntas permitem ataques complexos
3. **TÉCNICAS DE MITIGAÇÃO**: Específicas e implementáveis

Foque em EXPLOITABILIDADE e IMPACTO real.
""",

            'asvs': base_context + """
TAREFA: Análise focada em OWASP ASVS (Application Security Verification Standard).

Forneça:
1. **GAPS DE COMPLIANCE**:
   - Requisitos Level 1 não atendidos (CRÍTICO)
   - Requisitos Level 2 não atendidos (IMPORTANTE)
   - Impacto na postura de segurança

2. **ROADMAP DE CONFORMIDADE**: Plano para atingir Level 2
3. **CERTIFICAÇÃO**: Passos para certificação ASVS

Seja prático sobre o que implementar primeiro.
""",

            'priorities': base_context + """
TAREFA: Crie um PLANO DE AÇÃO PRIORIZADO.

Forneça uma lista numerada de 10 ações, ordenadas por:
- Impacto na segurança (peso 40%)
- Facilidade de implementação (peso 30%)
- Urgência/exploitabilidade (peso 30%)

Para cada ação:
1. O QUE fazer (específico)
2. POR QUE (justificativa)
3. COMO fazer (resumo técnico)
4. ESFORÇO estimado (horas/dias)
5. IMPACTO esperado (redução de risco %)

Seja ULTRA ESPECÍFICO e PRÁTICO.
""",

            'recommendations': base_context + """
TAREFA: Recomendações PRÁTICAS e IMPLEMENTÁVEIS.

Forneça:
1. **CORREÇÕES IMEDIATAS** (próximos 7 dias):
   - 3 ações de alto impacto
   - Como implementar (passo a passo)

2. **MELHORIAS CURTO PRAZO** (próximo mês):
   - 5 ações estratégicas
   - Recursos necessários

3. **TRANSFORMAÇÃO LONGO PRAZO** (próximos 3-6 meses):
   - Mudanças arquiteturais
   - Processo e cultura

4. **FERRAMENTAS RECOMENDADAS**: Específicas para os problemas encontrados

Seja PRÁTICO, não teórico.
"""
        }

        return prompts.get(analysis_type, prompts['comprehensive'])

    def _get_fallback_analysis(self, data: Dict, analysis_type: str) -> Dict:
        """Análise de fallback quando Gemini não está disponível"""
        return {
            'type': analysis_type,
            'ai_generated': False,
            'content': '⚠️ Análise IA não disponível. Configure Gemini AI para análises inteligentes.',
            'timestamp': datetime.now().isoformat()
        }

    def generate_critical_path(self, data: Dict) -> str:
        """Gera caminho crítico de correção"""
        if not self.model:
            return "Configure Gemini AI para gerar caminho crítico automaticamente."

        prompt = self._build_prompt(data, 'priorities')
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Erro ao gerar caminho crítico: {e}"

    def generate_attack_scenarios(self, data: Dict) -> str:
        """Gera cenários de ataque baseados nas vulnerabilidades"""
        if not self.model:
            return "Configure Gemini AI para gerar cenários de ataque."

        prompt = f"""
Baseado nestas vulnerabilidades, descreva 3 CENÁRIOS DE ATAQUE realistas:

{self._build_prompt(data, 'comprehensive')}

Para cada cenário:
1. **NOME DO ATAQUE**
2. **VETOR**: Como o atacante inicia
3. **EXPLORAÇÃO**: Passo a passo do ataque
4. **IMPACTO**: O que o atacante consegue
5. **DETECÇÃO**: Como detectar este ataque
6. **PREVENÇÃO**: Como bloquear

Seja TÉCNICO e REALISTA.
"""

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Erro ao gerar cenários: {e}"


class SonarQubeCollector:
    def __init__(self, base_url: str, token: str, gemini_api_key: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token

        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        # Configurar Gemini AI se a API Key foi fornecida
        self.gemini = GeminiAnalyzer(gemini_api_key) if gemini_api_key else None

        # Criar diretório para armazenar scans históricos
        self.ensure_scans_directory()

        print(f"🔧 Autenticação configurada: Bearer token")
        print(f"🔧 SSL será SEMPRE desabilitado em todas requisições")
        print(f"🔧 Total de repositórios esperados: {TOTAL_REPOSITORIES_EXPECTED}")
        print(f"🔧 Branches monitoradas: {', '.join(MAIN_BRANCHES)}")
        print(f"🔧 Monitoramento de secrets: Todas as regras que contêm '{SECRETS_PATTERN}'")
        print(f"🔧 Monitoramento de misconfigurations: {', '.join(MISCONFIG_PATTERNS)}")

        if self.gemini and self.gemini.model:
            print(f"🤖 Gemini AI configurado: Análises inteligentes ativadas")
        else:
            print(f"⚠️  Gemini AI não configurado: Análises básicas apenas")
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

    def classify_rule_to_cwe(self, rule: str, message: str = "", component: str = "") -> List[str]:
        """Classifica uma regra SonarQube para CWE(s)"""
        cwes = []

        # Primeiro verifica mapeamento direto
        if rule in SONARQUBE_TO_CWE_MAPPING:
            cwes.extend(SONARQUBE_TO_CWE_MAPPING[rule])

        # Se não encontrou mapeamento direto, tenta classificar por keywords
        if not cwes:
            rule_lower = rule.lower()
            message_lower = message.lower()
            component_lower = component.lower()
            combined_text = f"{rule_lower} {message_lower} {component_lower}"

            for cwe_id, data in CWE_TOP_25_2025_MAPPING.items():
                keywords = data.get('keywords', [])
                if any(keyword in combined_text for keyword in keywords):
                    cwes.append(cwe_id)
                    break  # Pega apenas a primeira correspondência por keyword

        return cwes if cwes else ['OTHER']

    def classify_rule_to_asvs(self, rule: str, message: str = "", component: str = "") -> List[str]:
        """Classifica uma regra SonarQube para requisito(s) ASVS"""
        asvs_ids = []

        # Primeiro verifica mapeamento direto
        if rule in SONARQUBE_TO_ASVS_MAPPING:
            asvs_ids.extend(SONARQUBE_TO_ASVS_MAPPING[rule])

        # Se não encontrou mapeamento direto, tenta classificar por keywords
        if not asvs_ids:
            rule_lower = rule.lower()
            message_lower = message.lower()
            component_lower = component.lower()
            combined_text = f"{rule_lower} {message_lower} {component_lower}"

            for asvs_id, data in OWASP_ASVS_MAPPING.items():
                keywords = data.get('keywords', [])
                if any(keyword in combined_text for keyword in keywords):
                    asvs_ids.append(asvs_id)
                    break  # Pega apenas a primeira correspondência por keyword

        return asvs_ids if asvs_ids else ['OTHER']

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
        print("COLETANDO DADOS PARA DASHBOARD CWE TOP 25 2025")
        print("=" * 70)
        print()
        print("ℹ️  Coletando apenas branches principais: main, master, develop, developer")
        print("ℹ️  Implementando classificação OWASP Top 10 2025...")
        print("ℹ️  Implementando classificação CWE Top 25 2025...")
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
            'cwe_metrics_global': defaultdict(int),
            'cwe_metrics_by_project': {},
            'cwe_details': [],
            'asvs_metrics_global': defaultdict(int),
            'asvs_metrics_by_project': {},
            'asvs_details': [],
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
                'cwe_metrics': defaultdict(int),
                'asvs_metrics': defaultdict(int),
                'governance_maturity': {},
                'coverage_branches': [],
                'average_coverage': 0
            }

            project_has_secrets = False
            project_has_misconfigs = False
            project_owasp_metrics = defaultdict(int)
            project_cwe_metrics = defaultdict(int)
            project_asvs_metrics = defaultdict(int)
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

                        # Classificação CWE
                        cwe_ids = self.classify_rule_to_cwe(rule, message, component)
                        for cwe_id in cwe_ids:
                            project_cwe_metrics[cwe_id] += 1
                            dashboard_data['cwe_metrics_global'][cwe_id] += 1

                        # Classificação ASVS
                        asvs_ids = self.classify_rule_to_asvs(rule, message, component)
                        for asvs_id in asvs_ids:
                            project_asvs_metrics[asvs_id] += 1
                            dashboard_data['asvs_metrics_global'][asvs_id] += 1
                        
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
                            'owasp_category': owasp_category,
                            'cwe_ids': cwe_ids,
                            'asvs_ids': asvs_ids
                        })

                        # Adicionar detalhes CWE
                        for cwe_id in cwe_ids:
                            if cwe_id != 'OTHER' and cwe_id in CWE_TOP_25_2025_MAPPING:
                                cwe_info = CWE_TOP_25_2025_MAPPING[cwe_id]
                                dashboard_data['cwe_details'].append({
                                    'cwe_id': cwe_id,
                                    'cwe_name': cwe_info['name'],
                                    'cwe_rank': cwe_info['rank'],
                                    'severity': cwe_info['severity'],
                                    'projectName': project_name,
                                    'projectKey': project_key,
                                    'issue_severity': severity,
                                    'rule': rule,
                                    'message': message
                                })

                        # Adicionar detalhes ASVS
                        for asvs_id in asvs_ids:
                            if asvs_id != 'OTHER' and asvs_id in OWASP_ASVS_MAPPING:
                                asvs_info = OWASP_ASVS_MAPPING[asvs_id]
                                dashboard_data['asvs_details'].append({
                                    'asvs_id': asvs_id,
                                    'asvs_name': asvs_info['name'],
                                    'category': asvs_info['category'],
                                    'level': asvs_info['level'],
                                    'severity': asvs_info['severity'],
                                    'projectName': project_name,
                                    'projectKey': project_key,
                                    'issue_severity': severity,
                                    'rule': rule,
                                    'message': message
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
            project_data['cwe_metrics'] = dict(project_cwe_metrics)
            project_data['asvs_metrics'] = dict(project_asvs_metrics)
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

            dashboard_data['cwe_metrics_by_project'][project_key] = {
                'project_name': project_name,
                'metrics': dict(project_cwe_metrics)
            }

            dashboard_data['asvs_metrics_by_project'][project_key] = {
                'project_name': project_name,
                'metrics': dict(project_asvs_metrics)
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
        dashboard_data['cwe_metrics_global'] = dict(dashboard_data['cwe_metrics_global'])
        dashboard_data['asvs_metrics_global'] = dict(dashboard_data['asvs_metrics_global'])

        # Gerar análises com Gemini AI
        if self.gemini and self.gemini.model:
            print("\n🤖 Gerando análises inteligentes com Gemini AI...")

            try:
                dashboard_data['ai_analyses'] = {
                    'comprehensive': self.gemini.analyze_security_data(dashboard_data, 'comprehensive'),
                    'owasp': self.gemini.analyze_security_data(dashboard_data, 'owasp'),
                    'cwe': self.gemini.analyze_security_data(dashboard_data, 'cwe'),
                    'asvs': self.gemini.analyze_security_data(dashboard_data, 'asvs'),
                    'priorities': self.gemini.analyze_security_data(dashboard_data, 'priorities'),
                    'recommendations': self.gemini.analyze_security_data(dashboard_data, 'recommendations'),
                    'critical_path': self.gemini.generate_critical_path(dashboard_data),
                    'attack_scenarios': self.gemini.generate_attack_scenarios(dashboard_data)
                }

                print("✓ Análises IA concluídas!")
            except Exception as e:
                print(f"⚠️  Erro ao gerar análises IA: {e}")
                dashboard_data['ai_analyses'] = {
                    'enabled': False,
                    'error': str(e),
                    'message': 'Erro ao processar análises IA'
                }
        else:
            dashboard_data['ai_analyses'] = {
                'enabled': False,
                'message': 'Configure Gemini API Key para análises inteligentes'
            }

        return dashboard_data
    
    def generate_dashboard_html(self, data: Dict) -> str:
        collection_date = datetime.fromisoformat(data['collection_date']).strftime('%d/%m/%Y %H:%M:%S')
        sonar_url = data.get('sonar_url', '#')
        
        # Carrega histórico de scans - apenas arquivos scan_*.json
        scan_history = self.get_scan_history()
        data['scan_history'] = scan_history

        # Adicionar mapeamento CWE ao data
        data['cwe_top_25_2025_mapping'] = CWE_TOP_25_2025_MAPPING

        # Adicionar mapeamento ASVS ao data
        data['owasp_asvs_mapping'] = OWASP_ASVS_MAPPING

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

        .btn-toggle {{
            background: none;
            border: 2px solid var(--primary-color);
            color: var(--primary-color);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: var(--transition);
            font-size: 14px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}

        .btn-toggle:hover {{
            background: var(--primary-color);
            color: white;
            transform: translateY(-2px);
        }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
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
                <button class="tab-btn" onclick="switchTab('cwe')">
                    <i class="fas fa-bug"></i> CWE Top 25 2025
                </button>
                <button class="tab-btn" onclick="switchTab('asvs')">
                    <i class="fas fa-check-double"></i> OWASP ASVS
                </button>
                <button class="tab-btn" onclick="switchTab('ai')">
                    <i class="fas fa-robot"></i> AI Insights
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

        <div id="cwe-tab" class="tab-content">
            <!-- Dashboard Gerencial CWE -->
            <div class="card mb-4" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                <div class="card-header" style="border-bottom: 2px solid rgba(255,255,255,0.3);">
                    <h2 class="card-title" style="color: white; font-size: 1.8rem;">
                        <i class="fas fa-bug"></i> CWE Top 25 2025 - Dashboard Inteligente de Vulnerabilidades
                    </h2>
                    <p style="margin: 10px 0 0 0; opacity: 0.9; font-size: 1.05rem;">
                        Análise das 25 fraquezas de software mais perigosas com insights de mitigação e vetores de ataque
                    </p>
                </div>
            </div>

            <!-- Cards de Métricas CWE -->
            <div class="grid grid-4 mb-4">
                <div class="card danger">
                    <div class="metric-value text-danger" id="cweTotalCritical">0</div>
                    <div class="metric-label">CWEs Críticas</div>
                    <div class="metric-change" id="cweCriticalProjects">0 projetos afetados</div>
                </div>
                <div class="card warning">
                    <div class="metric-value text-warning" id="cweTotalHigh">0</div>
                    <div class="metric-label">CWEs High</div>
                    <div class="metric-change" id="cweHighProjects">0 projetos afetados</div>
                </div>
                <div class="card info">
                    <div class="metric-value text-info" id="cweTotalMedium">0</div>
                    <div class="metric-label">CWEs Medium</div>
                    <div class="metric-change" id="cweMediumProjects">0 projetos afetados</div>
                </div>
                <div class="card success">
                    <div class="metric-value text-success" id="cweCategories">0</div>
                    <div class="metric-label">CWEs Detectadas</div>
                    <div class="metric-change" id="cweCategoriesChange">das 25 mais perigosas</div>
                </div>
            </div>

            <!-- Top 5 CWEs Mais Críticas com Dicas de Mitigação -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-exclamation-triangle card-icon text-danger"></i>
                        Top 5 CWEs Mais Críticas - Análise de Risco e Mitigação
                    </h3>
                </div>
                <div id="cweTop5CriticalContainer"></div>
            </div>

            <!-- Gráficos CWE -->
            <div class="grid grid-2 mb-4">
                <!-- Top 20 CWE por Volume -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-bar card-icon"></i>
                            Top 20 CWEs por Volume
                        </h3>
                    </div>
                    <div class="chart-container" style="height: 500px;">
                        <canvas id="cweTop20VolumeChart"></canvas>
                    </div>
                </div>

                <!-- CWE por Projeto -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-project-diagram card-icon"></i>
                            Distribuição de CWEs por Projeto
                        </h3>
                    </div>
                    <div class="chart-container" style="height: 500px;">
                        <canvas id="cweByProjectChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Status por Categoria para Governança -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-tasks card-icon"></i>
                        Status de Governança por Categoria CWE
                    </h3>
                </div>
                <div id="cweGovernanceStatusContainer"></div>
            </div>

            <!-- Matriz de Heatmap CWE x Projeto -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-th card-icon"></i>
                        Heatmap: CWEs por Projeto
                    </h3>
                </div>
                <div class="chart-container" style="height: 600px;">
                    <canvas id="cweHeatmapChart"></canvas>
                </div>
            </div>
        </div>

        <div id="asvs-tab" class="tab-content">
            <!-- Dashboard Gerencial ASVS -->
            <div class="card mb-4" style="background: linear-gradient(135deg, #4CAF50 0%, #2E7D32 100%); color: white;">
                <div class="card-header" style="border-bottom: 2px solid rgba(255,255,255,0.3);">
                    <h2 class="card-title" style="color: white; font-size: 1.8rem;">
                        <i class="fas fa-check-double"></i> OWASP ASVS 4.0 - Application Security Verification Standard
                    </h2>
                    <p style="margin: 10px 0 0 0; opacity: 0.9; font-size: 1.05rem;">
                        Verificação de segurança de aplicações baseada nos requisitos do ASVS com análise por níveis de maturidade
                    </p>
                </div>
            </div>

            <!-- Cards de Métricas ASVS -->
            <div class="grid grid-4 mb-4">
                <div class="card danger">
                    <div class="metric-value text-danger" id="asvsLevel1Issues">0</div>
                    <div class="metric-label">Requisitos Level 1</div>
                    <div class="metric-change" id="asvsLevel1Projects">0 projetos afetados</div>
                </div>
                <div class="card warning">
                    <div class="metric-value text-warning" id="asvsLevel2Issues">0</div>
                    <div class="metric-label">Requisitos Level 2</div>
                    <div class="metric-change" id="asvsLevel2Projects">0 projetos afetados</div>
                </div>
                <div class="card info">
                    <div class="metric-value text-info" id="asvsCriticalIssues">0</div>
                    <div class="metric-label">Issues Críticas</div>
                    <div class="metric-change" id="asvsCriticalProjects">0 projetos afetados</div>
                </div>
                <div class="card success">
                    <div class="metric-value text-success" id="asvsCategories">0</div>
                    <div class="metric-label">Requisitos Detectados</div>
                    <div class="metric-change" id="asvsCategoriesChange">categorias ASVS</div>
                </div>
            </div>

            <!-- Top 5 ASVS Mais Críticas com Dicas de Mitigação -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-exclamation-triangle card-icon text-danger"></i>
                        Top 5 Requisitos ASVS Mais Críticos - Análise de Risco e Mitigação
                    </h3>
                </div>
                <div id="asvsTop5CriticalContainer"></div>
            </div>

            <!-- Gráficos ASVS -->
            <div class="grid grid-2 mb-4">
                <!-- Top 20 ASVS por Volume -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-bar card-icon"></i>
                            Top 20 Requisitos ASVS por Volume
                        </h3>
                    </div>
                    <div class="chart-container" style="height: 500px;">
                        <canvas id="asvsTop20VolumeChart"></canvas>
                    </div>
                </div>

                <!-- ASVS por Projeto -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-project-diagram card-icon"></i>
                            Distribuição de Requisitos ASVS por Projeto
                        </h3>
                    </div>
                    <div class="chart-container" style="height: 500px;">
                        <canvas id="asvsByProjectChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Status por Categoria para Governança -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-tasks card-icon"></i>
                        Status de Governança por Categoria ASVS
                    </h3>
                </div>
                <div id="asvsGovernanceStatusContainer"></div>
            </div>

            <!-- Matriz de Heatmap ASVS x Projeto -->
            <div class="card mb-4">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-th card-icon"></i>
                        Heatmap: Requisitos ASVS por Projeto
                    </h3>
                </div>
                <div class="chart-container" style="height: 600px;">
                    <canvas id="asvsHeatmapChart"></canvas>
                </div>
            </div>
        </div>

        <!-- AI Insights Tab -->
        <div id="ai-tab" class="tab-content">
            <div class="card mb-4" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                <div class="card-header" style="background: transparent; border: none;">
                    <h2><i class="fas fa-robot"></i> Análises Inteligentes com Gemini AI</h2>
                    <p style="margin: 0; opacity: 0.9;">Insights críticos e caminhos de melhoria gerados por Inteligência Artificial</p>
                </div>
            </div>

            <div id="aiAnalysisContainer"></div>
            <div id="aiCriticalPathContainer"></div>
            <div id="aiAttackScenariosContainer"></div>
            <div id="aiRecommendationsContainer"></div>
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
                case 'cwe':
                    renderCWEAnalysis();
                    break;
                case 'asvs':
                    renderASVSAnalysis();
                    break;
                case 'ai':
                    renderAIInsights();
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

        // ===== AI INSIGHTS =====
        function renderAIInsights() {{
            const aiData = dashboardData.ai_analyses || {{}};

            // Verificar se a IA está habilitada
            if (aiData.enabled === false) {{
                renderAIDisabledMessage(aiData);
                return;
            }}

            // Renderizar as análises
            renderComprehensiveAnalysis(aiData);
            renderCriticalPath(aiData);
            renderAttackScenarios(aiData);
            renderAIRecommendations(aiData);
        }}

        function renderAIDisabledMessage(aiData) {{
            const container = document.getElementById('aiAnalysisContainer');
            if (!container) return;

            const message = aiData.message || 'Configure Gemini API Key para análises inteligentes';
            const error = aiData.error ? `<p style="color: #ff6b6b; margin-top: 10px;"><strong>Erro:</strong> ${{aiData.error}}</p>` : '';

            container.innerHTML = `
                <div class="card mb-4" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white;">
                    <div class="card-body" style="text-align: center; padding: 40px;">
                        <i class="fas fa-robot" style="font-size: 64px; margin-bottom: 20px; opacity: 0.8;"></i>
                        <h3>AI Insights não disponível</h3>
                        <p style="font-size: 16px; margin-top: 10px; opacity: 0.9;">${{message}}</p>
                        ${{error}}
                        <p style="margin-top: 20px; font-size: 14px; opacity: 0.8;">
                            <i class="fas fa-info-circle"></i> Execute o dashboard novamente com a Gemini API Key para habilitar análises inteligentes.
                        </p>
                    </div>
                </div>
            `;
        }}

        function convertMarkdownToHTML(text) {{
            if (!text) return '';

            // Converter negrito **texto**
            text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');

            // Converter itálico *texto*
            text = text.replace(/\*(.+?)\*/g, '<em>$1</em>');

            // Converter títulos ###
            text = text.replace(/^### (.+)$/gm, '<h4 style="margin-top: 20px; margin-bottom: 10px;">$1</h4>');
            text = text.replace(/^## (.+)$/gm, '<h3 style="margin-top: 25px; margin-bottom: 15px;">$1</h3>');
            text = text.replace(/^# (.+)$/gm, '<h2 style="margin-top: 30px; margin-bottom: 20px;">$1</h2>');

            // Converter listas - item
            text = text.replace(/^- (.+)$/gm, '<li style="margin-left: 20px;">$1</li>');
            text = text.replace(/(<li.*<\/li>)/s, '<ul>$1</ul>');

            // Converter listas numeradas 1. item
            text = text.replace(/^\d+\. (.+)$/gm, '<li style="margin-left: 20px;">$1</li>');

            // Converter quebras de linha duplas em parágrafos
            text = text.split('\\n\\n').map(para => para.trim() ? `<p>${{para.replace(/\\n/g, '<br>')}}</p>` : '').join('');

            return text;
        }}

        function renderComprehensiveAnalysis(aiData) {{
            const container = document.getElementById('aiAnalysisContainer');
            if (!container) return;

            const comprehensive = aiData.comprehensive || 'Análise não disponível';
            const owasp = aiData.owasp || '';
            const cwe = aiData.cwe || '';
            const asvs = aiData.asvs || '';
            const priorities = aiData.priorities || '';

            const html = `
                <div class="card mb-4">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-brain card-icon"></i>
                            Análise Abrangente de Segurança
                        </h3>
                        <button class="btn-toggle" onclick="toggleSection('comprehensiveSection')">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <div id="comprehensiveSection" class="card-body">
                        <div style="padding: 20px; background: #f8f9fa; border-radius: 8px; margin-bottom: 20px;">
                            ${{convertMarkdownToHTML(comprehensive)}}
                        </div>

                        <div class="grid grid-2" style="margin-top: 20px;">
                            <div class="card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">
                                <div class="card-header" style="background: transparent; border: none;">
                                    <h4><i class="fas fa-shield-alt"></i> Análise OWASP Top 10</h4>
                                </div>
                                <div class="card-body">
                                    ${{convertMarkdownToHTML(owasp)}}
                                </div>
                            </div>

                            <div class="card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white;">
                                <div class="card-header" style="background: transparent; border: none;">
                                    <h4><i class="fas fa-bug"></i> Análise CWE Top 25</h4>
                                </div>
                                <div class="card-body">
                                    ${{convertMarkdownToHTML(cwe)}}
                                </div>
                            </div>
                        </div>

                        <div class="grid grid-2" style="margin-top: 20px;">
                            <div class="card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white;">
                                <div class="card-header" style="background: transparent; border: none;">
                                    <h4><i class="fas fa-check-double"></i> Análise ASVS</h4>
                                </div>
                                <div class="card-body">
                                    ${{convertMarkdownToHTML(asvs)}}
                                </div>
                            </div>

                            <div class="card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); color: white;">
                                <div class="card-header" style="background: transparent; border: none;">
                                    <h4><i class="fas fa-exclamation-triangle"></i> Prioridades</h4>
                                </div>
                                <div class="card-body">
                                    ${{convertMarkdownToHTML(priorities)}}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = html;
        }}

        function renderCriticalPath(aiData) {{
            const container = document.getElementById('aiCriticalPathContainer');
            if (!container) return;

            const criticalPath = aiData.critical_path || 'Caminho crítico não disponível';

            const html = `
                <div class="card mb-4">
                    <div class="card-header" style="background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%); color: white; border: none;">
                        <h3 class="card-title" style="color: white;">
                            <i class="fas fa-route card-icon"></i>
                            Caminho Crítico de Correção
                        </h3>
                        <button class="btn-toggle" onclick="toggleSection('criticalPathSection')" style="color: white; border-color: white;">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <div id="criticalPathSection" class="card-body">
                        <div style="padding: 20px; background: #fff5f5; border-left: 4px solid #ff6b6b; border-radius: 4px;">
                            ${{convertMarkdownToHTML(criticalPath)}}
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = html;
        }}

        function renderAttackScenarios(aiData) {{
            const container = document.getElementById('aiAttackScenariosContainer');
            if (!container) return;

            const scenarios = aiData.attack_scenarios || 'Cenários de ataque não disponíveis';

            const html = `
                <div class="card mb-4">
                    <div class="card-header" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; border: none;">
                        <h3 class="card-title" style="color: white;">
                            <i class="fas fa-user-secret card-icon"></i>
                            Cenários de Ataque
                        </h3>
                        <button class="btn-toggle" onclick="toggleSection('attackScenariosSection')" style="color: white; border-color: white;">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <div id="attackScenariosSection" class="card-body">
                        <div style="padding: 20px; background: #fff0f6; border-left: 4px solid #f5576c; border-radius: 4px;">
                            ${{convertMarkdownToHTML(scenarios)}}
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = html;
        }}

        function renderAIRecommendations(aiData) {{
            const container = document.getElementById('aiRecommendationsContainer');
            if (!container) return;

            const recommendations = aiData.recommendations || 'Recomendações não disponíveis';

            const html = `
                <div class="card mb-4">
                    <div class="card-header" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; border: none;">
                        <h3 class="card-title" style="color: white;">
                            <i class="fas fa-lightbulb card-icon"></i>
                            Recomendações Estratégicas
                        </h3>
                        <button class="btn-toggle" onclick="toggleSection('recommendationsSection')" style="color: white; border-color: white;">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </div>
                    <div id="recommendationsSection" class="card-body">
                        <div style="padding: 20px; background: #f0f9ff; border-left: 4px solid #00f2fe; border-radius: 4px;">
                            ${{convertMarkdownToHTML(recommendations)}}
                        </div>
                    </div>
                </div>
            `;

            container.innerHTML = html;
        }}

        function toggleSection(sectionId) {{
            const section = document.getElementById(sectionId);
            const button = event.currentTarget;
            const icon = button.querySelector('i');

            if (section.style.display === 'none') {{
                section.style.display = 'block';
                icon.className = 'fas fa-chevron-down';
            }} else {{
                section.style.display = 'none';
                icon.className = 'fas fa-chevron-right';
            }}
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

        // ==================== CWE TOP 25 2025 ANALYSIS ====================

        const cweData = {data_json}.cwe_metrics_global || {{}};
        const cweDetails = {data_json}.cwe_details || [];
        const cweByProject = {data_json}.cwe_metrics_by_project || {{}};

        const cweTop25Mapping = {{
            'CWE-787': {{ name: 'Out-of-bounds Write', severity: 'CRITICAL', rank: 1, color: '#8B0000' }},
            'CWE-79': {{ name: 'Cross-site Scripting (XSS)', severity: 'CRITICAL', rank: 2, color: '#DC3545' }},
            'CWE-89': {{ name: 'SQL Injection', severity: 'CRITICAL', rank: 3, color: '#DC3545' }},
            'CWE-416': {{ name: 'Use After Free', severity: 'CRITICAL', rank: 4, color: '#8B0000' }},
            'CWE-78': {{ name: 'OS Command Injection', severity: 'CRITICAL', rank: 5, color: '#DC3545' }},
            'CWE-20': {{ name: 'Improper Input Validation', severity: 'HIGH', rank: 6, color: '#FF6B6B' }},
            'CWE-125': {{ name: 'Out-of-bounds Read', severity: 'HIGH', rank: 7, color: '#FF6B6B' }},
            'CWE-22': {{ name: 'Path Traversal', severity: 'HIGH', rank: 8, color: '#FF9800' }},
            'CWE-352': {{ name: 'CSRF', severity: 'HIGH', rank: 9, color: '#FF9800' }},
            'CWE-434': {{ name: 'Unrestricted Upload', severity: 'HIGH', rank: 10, color: '#FF9800' }},
            'CWE-862': {{ name: 'Missing Authorization', severity: 'HIGH', rank: 11, color: '#FFC107' }},
            'CWE-476': {{ name: 'NULL Pointer', severity: 'MEDIUM', rank: 12, color: '#FFC107' }},
            'CWE-287': {{ name: 'Improper Authentication', severity: 'CRITICAL', rank: 13, color: '#DC3545' }},
            'CWE-190': {{ name: 'Integer Overflow', severity: 'MEDIUM', rank: 14, color: '#FFC107' }},
            'CWE-502': {{ name: 'Deserialization', severity: 'CRITICAL', rank: 15, color: '#DC3545' }},
            'CWE-77': {{ name: 'Command Injection', severity: 'CRITICAL', rank: 16, color: '#DC3545' }},
            'CWE-119': {{ name: 'Memory Buffer Errors', severity: 'HIGH', rank: 17, color: '#FF6B6B' }},
            'CWE-798': {{ name: 'Hard-coded Credentials', severity: 'CRITICAL', rank: 18, color: '#8B0000' }},
            'CWE-918': {{ name: 'SSRF', severity: 'HIGH', rank: 19, color: '#FF9800' }},
            'CWE-306': {{ name: 'Missing Authentication', severity: 'CRITICAL', rank: 20, color: '#8B0000' }},
            'CWE-362': {{ name: 'Race Condition', severity: 'MEDIUM', rank: 21, color: '#FFC107' }},
            'CWE-269': {{ name: 'Improper Privilege Mgmt', severity: 'HIGH', rank: 22, color: '#FF9800' }},
            'CWE-94': {{ name: 'Code Injection', severity: 'CRITICAL', rank: 23, color: '#8B0000' }},
            'CWE-863': {{ name: 'Incorrect Authorization', severity: 'HIGH', rank: 24, color: '#FF9800' }},
            'CWE-276': {{ name: 'Incorrect Permissions', severity: 'MEDIUM', rank: 25, color: '#FFC107' }}
        }};

        function renderCWEAnalysis() {{
            updateCWEMetrics();
            renderCWETop5Critical();
            renderCWETop20VolumeChart();
            renderCWEByProjectChart();
            renderCWEGovernanceStatus();
            renderCWEHeatmap();
        }}

        function updateCWEMetrics() {{
            const data = getFilteredData();
            const cweMetrics = data.cwe_metrics_global || {{}};

            let criticalCount = 0;
            let highCount = 0;
            let mediumCount = 0;
            let categoriesDetected = 0;

            const projectsAffected = new Set();
            const criticalProjects = new Set();
            const highProjects = new Set();
            const mediumProjects = new Set();

            Object.entries(cweMetrics).forEach(([cweId, count]) => {{
                if (cweId === 'OTHER' || count === 0) return;
                categoriesDetected++;

                const cweInfo = cweTop25Mapping[cweId];
                if (!cweInfo) return;

                // Contar por severidade
                if (cweInfo.severity === 'CRITICAL') criticalCount += count;
                else if (cweInfo.severity === 'HIGH') highCount += count;
                else if (cweInfo.severity === 'MEDIUM') mediumCount += count;

                // Contar projetos afetados
                const details = (data.cwe_details || []).filter(d => d.cwe_id === cweId);
                details.forEach(d => {{
                    projectsAffected.add(d.projectKey);
                    if (cweInfo.severity === 'CRITICAL') criticalProjects.add(d.projectKey);
                    else if (cweInfo.severity === 'HIGH') highProjects.add(d.projectKey);
                    else if (cweInfo.severity === 'MEDIUM') mediumProjects.add(d.projectKey);
                }});
            }});

            document.getElementById('cweTotalCritical').textContent = criticalCount;
            document.getElementById('cweCriticalProjects').textContent = `${{criticalProjects.size}} projetos afetados`;

            document.getElementById('cweTotalHigh').textContent = highCount;
            document.getElementById('cweHighProjects').textContent = `${{highProjects.size}} projetos afetados`;

            document.getElementById('cweTotalMedium').textContent = mediumCount;
            document.getElementById('cweMediumProjects').textContent = `${{mediumProjects.size}} projetos afetados`;

            document.getElementById('cweCategories').textContent = categoriesDetected;
            document.getElementById('cweCategoriesChange').textContent = `de 25 mais perigosas`;
        }}

        function renderCWETop5Critical() {{
            const container = document.getElementById('cweTop5CriticalContainer');
            const data = getFilteredData();
            const cweMetrics = data.cwe_metrics_global || {{}};

            // Filtrar e ordenar CWEs por volume
            const sortedCWEs = Object.entries(cweMetrics)
                .filter(([id, count]) => id !== 'OTHER' && count > 0 && cweTop25Mapping[id])
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);

            if (sortedCWEs.length === 0) {{
                container.innerHTML = '<div class="empty-state"><i class="fas fa-check-circle" style="color: #28a745;"></i><br>Nenhuma CWE crítica detectada!</div>';
                return;
            }}

            let html = '<div style="display: grid; gap: 20px;">';

            sortedCWEs.forEach(([cweId, count], index) => {{
                const cweFullData = {data_json}.cwe_top_25_2025_mapping?.[cweId] || {{}};
                const cweShortData = cweTop25Mapping[cweId] || {{}};
                const details = (data.cwe_details || []).filter(d => d.cwe_id === cweId);
                const projectsAffected = new Set(details.map(d => d.projectKey)).size;

                const severityClass = cweShortData.severity === 'CRITICAL' ? 'danger' :
                                    cweShortData.severity === 'HIGH' ? 'warning' : 'info';
                const rankIcon = ['🥇', '🥈', '🥉', '4️⃣', '5️⃣'][index];

                html += `
                    <div class="card ${{severityClass}}" style="border-left: 5px solid ${{cweShortData.color}};">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div style="flex: 1;">
                                <h3 style="color: ${{cweShortData.color}}; margin-bottom: 10px; display: flex; align-items: center; gap: 10px;">
                                    <span style="font-size: 2rem;">${{rankIcon}}</span>
                                    <div>
                                        <div>${{cweId}}: ${{cweShortData.name}}</div>
                                        <div style="font-size: 0.85rem; font-weight: normal; color: #666;">
                                            Rank #${{cweShortData.rank}} - ${{cweShortData.severity}}
                                        </div>
                                    </div>
                                </h3>
                                <div style="margin: 15px 0; padding: 15px; background: rgba(0,0,0,0.05); border-radius: 8px;">
                                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 10px;">
                                        <div>
                                            <div style="font-size: 2rem; font-weight: bold; color: ${{cweShortData.color}};">${{count}}</div>
                                            <div style="font-size: 0.85rem; color: #666;">Issues Detectados</div>
                                        </div>
                                        <div>
                                            <div style="font-size: 2rem; font-weight: bold; color: #FF9800;">${{projectsAffected}}</div>
                                            <div style="font-size: 0.85rem; color: #666;">Projetos Afetados</div>
                                        </div>
                                        <div>
                                            <div style="font-size: 2rem; font-weight: bold; color: #3F51B5;">Top ${{index + 1}}</div>
                                            <div style="font-size: 0.85rem; color: #666;">Posição no Ranking</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div style="margin-top: 15px; padding: 15px; background: linear-gradient(135deg, rgba(255,255,255,0.9) 0%, rgba(240,240,240,0.9) 100%); border-radius: 10px;">
                            <div style="margin-bottom: 15px;">
                                <h4 style="color: #DC3545; margin-bottom: 8px;">
                                    <i class="fas fa-crosshairs"></i> Vetor de Ataque
                                </h4>
                                <p style="color: #555; line-height: 1.6;">${{cweFullData.attack_vector || 'Vetor de ataque não especificado'}}</p>
                            </div>

                            <div style="margin-bottom: 15px;">
                                <h4 style="color: #28a745; margin-bottom: 8px;">
                                    <i class="fas fa-shield-alt"></i> Como Mitigar
                                </h4>
                                <p style="color: #555; line-height: 1.6;">${{cweFullData.mitigation || 'Estratégias de mitigação não especificadas'}}</p>
                            </div>

                            <div>
                                <h4 style="color: #FFC107; margin-bottom: 8px;">
                                    <i class="fas fa-code"></i> Exemplo de Vulnerabilidade
                                </h4>
                                <code style="display: block; padding: 10px; background: #f5f5f5; border-radius: 5px; color: #333; font-size: 0.9rem;">
                                    ${{cweFullData.example || 'Exemplo não disponível'}}
                                </code>
                            </div>
                        </div>
                    </div>
                `;
            }});

            html += '</div>';
            container.innerHTML = html;
        }}

        function renderCWETop20VolumeChart() {{
            const ctx = document.getElementById('cweTop20VolumeChart');
            if (!ctx) return;

            const data = getFilteredData();
            const cweMetrics = data.cwe_metrics_global || {{}};

            const sortedCWEs = Object.entries(cweMetrics)
                .filter(([id, count]) => id !== 'OTHER' && count > 0 && cweTop25Mapping[id])
                .sort((a, b) => b[1] - a[1])
                .slice(0, 20);

            if (charts['cweTop20Volume']) charts['cweTop20Volume'].destroy();

            charts['cweTop20Volume'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: sortedCWEs.map(([id]) => `${{id}}\\n${{cweTop25Mapping[id]?.name || id}}`),
                    datasets: [{{
                        label: 'Quantidade de Issues',
                        data: sortedCWEs.map(([, count]) => count),
                        backgroundColor: sortedCWEs.map(([id]) => cweTop25Mapping[id]?.color || '#9E9E9E'),
                        borderColor: sortedCWEs.map(([id]) => cweTop25Mapping[id]?.color || '#9E9E9E'),
                        borderWidth: 2
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{ display: false }},
                        tooltip: {{
                            callbacks: {{
                                label: (context) => `Issues: ${{context.parsed.x}}`
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{ beginAtZero: true }}
                    }}
                }}
            }});
        }}

        function renderCWEByProjectChart() {{
            const ctx = document.getElementById('cweByProjectChart');
            if (!ctx) return;

            const data = getFilteredData();
            const projectsCWE = {{}};

            (data.cwe_details || []).forEach(detail => {{
                if (!projectsCWE[detail.projectName]) {{
                    projectsCWE[detail.projectName] = 0;
                }}
                projectsCWE[detail.projectName]++;
            }});

            const sortedProjects = Object.entries(projectsCWE)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 15);

            if (charts['cweByProject']) charts['cweByProject'].destroy();

            charts['cweByProject'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: sortedProjects.map(([name]) => name.substring(0, 30)),
                    datasets: [{{
                        label: 'CWEs por Projeto',
                        data: sortedProjects.map(([, count]) => count),
                        backgroundColor: 'rgba(102, 126, 234, 0.6)',
                        borderColor: 'rgba(102, 126, 234, 1)',
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
                        x: {{ beginAtZero: true }}
                    }}
                }}
            }});
        }}

        function renderCWEGovernanceStatus() {{
            const container = document.getElementById('cweGovernanceStatusContainer');
            const data = getFilteredData();
            const cweMetrics = data.cwe_metrics_global || {{}};

            const categories = {{
                'Injection Attacks': ['CWE-89', 'CWE-78', 'CWE-77', 'CWE-94'],
                'Authentication & Authorization': ['CWE-287', 'CWE-306', 'CWE-862', 'CWE-863', 'CWE-269'],
                'Memory Safety': ['CWE-787', 'CWE-416', 'CWE-125', 'CWE-119', 'CWE-476'],
                'Input Validation': ['CWE-20', 'CWE-79', 'CWE-22', 'CWE-352'],
                'Secrets & Config': ['CWE-798', 'CWE-276'],
                'Design Flaws': ['CWE-190', 'CWE-502', 'CWE-434', 'CWE-918', 'CWE-362']
            }};

            let html = '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">';

            Object.entries(categories).forEach(([category, cwes]) => {{
                let totalIssues = 0;
                let criticalCount = 0;
                const projectsAffected = new Set();

                cwes.forEach(cweId => {{
                    const count = cweMetrics[cweId] || 0;
                    totalIssues += count;

                    const cweInfo = cweTop25Mapping[cweId];
                    if (cweInfo?.severity === 'CRITICAL') {{
                        criticalCount += count;
                    }}

                    const details = (data.cwe_details || []).filter(d => d.cwe_id === cweId);
                    details.forEach(d => projectsAffected.add(d.projectKey));
                }});

                const status = totalIssues === 0 ? 'success' :
                             criticalCount > 0 ? 'danger' :
                             totalIssues > 10 ? 'warning' : 'info';

                const statusIcon = totalIssues === 0 ? 'fa-check-circle' :
                                 criticalCount > 0 ? 'fa-exclamation-triangle' : 'fa-info-circle';

                html += `
                    <div class="card ${{status}}">
                        <h4 style="margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
                            <i class="fas ${{statusIcon}}"></i>
                            ${{category}}
                        </h4>
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-top: 10px;">
                            <div style="padding: 10px; background: rgba(0,0,0,0.05); border-radius: 5px;">
                                <div style="font-size: 1.5rem; font-weight: bold;">${{totalIssues}}</div>
                                <div style="font-size: 0.85rem; color: #666;">Total Issues</div>
                            </div>
                            <div style="padding: 10px; background: rgba(0,0,0,0.05); border-radius: 5px;">
                                <div style="font-size: 1.5rem; font-weight: bold;">${{projectsAffected.size}}</div>
                                <div style="font-size: 0.85rem; color: #666;">Projetos</div>
                            </div>
                            <div style="padding: 10px; background: rgba(220,53,69,0.1); border-radius: 5px;">
                                <div style="font-size: 1.5rem; font-weight: bold; color: #DC3545;">${{criticalCount}}</div>
                                <div style="font-size: 0.85rem; color: #666;">Críticas</div>
                            </div>
                            <div style="padding: 10px; background: rgba(40,167,69,0.1); border-radius: 5px;">
                                <div style="font-size: 1.5rem; font-weight: bold; color: #28a745;">${{cwes.length}}</div>
                                <div style="font-size: 0.85rem; color: #666;">CWEs</div>
                            </div>
                        </div>
                        <div style="margin-top: 10px; font-size: 0.85rem; color: #666;">
                            <strong>CWEs Monitoradas:</strong> ${{cwes.join(', ')}}
                        </div>
                    </div>
                `;
            }});

            html += '</div>';
            container.innerHTML = html;
        }}

        function renderCWEHeatmap() {{
            const ctx = document.getElementById('cweHeatmapChart');
            if (!ctx) return;

            const data = getFilteredData();
            const projects = (data.projects || []).slice(0, 20);

            // Top 10 CWEs
            const cweMetrics = data.cwe_metrics_global || {{}};
            const topCWEs = Object.entries(cweMetrics)
                .filter(([id, count]) => id !== 'OTHER' && count > 0 && cweTop25Mapping[id])
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([id]) => id);

            const heatmapData = [];
            projects.forEach((project, pIndex) => {{
                topCWEs.forEach((cweId, cIndex) => {{
                    const count = (project.cwe_metrics || {{}})[cweId] || 0;
                    if (count > 0) {{
                        heatmapData.push({{
                            x: pIndex,
                            y: cIndex,
                            v: count
                        }});
                    }}
                }});
            }});

            const maxValue = Math.max(...heatmapData.map(d => d.v), 1);

            if (charts['cweHeatmap']) charts['cweHeatmap'].destroy();

            charts['cweHeatmap'] = new Chart(ctx, {{
                type: 'scatter',
                data: {{
                    datasets: [{{
                        label: 'CWE Issues',
                        data: heatmapData,
                        backgroundColor: heatmapData.map(d => {{
                            const intensity = d.v / maxValue;
                            return `rgba(220, 53, 69, ${{intensity}})`;
                        }}),
                        pointRadius: 15,
                        pointHoverRadius: 20
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            type: 'linear',
                            position: 'bottom',
                            ticks: {{
                                callback: (value) => projects[value]?.name.substring(0, 15) || '',
                                autoSkip: false
                            }},
                            min: -0.5,
                            max: projects.length - 0.5
                        }},
                        y: {{
                            type: 'linear',
                            ticks: {{
                                callback: (value) => topCWEs[value] || '',
                                autoSkip: false
                            }},
                            min: -0.5,
                            max: topCWEs.length - 0.5
                        }}
                    }},
                    plugins: {{
                        tooltip: {{
                            callbacks: {{
                                label: (context) => {{
                                    const point = context.raw;
                                    return `${{topCWEs[point.y]}}: ${{point.v}} issues em ${{projects[point.x]?.name}}`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
        }}

        // ============================================================================
        // ASVS ANALYSIS FUNCTIONS
        // ============================================================================

        function renderASVSAnalysis() {{
            updateASVSMetrics();
            renderASVSTop5Critical();
            renderASVSTop20VolumeChart();
            renderASVSByProjectChart();
            renderASVSGovernanceStatus();
            renderASVSHeatmap();
        }}

        function updateASVSMetrics() {{
            const data = getFilteredData();
            const asvsMetrics = data.asvs_metrics_global || {{}};
            const asvsMapping = dashboardData.owasp_asvs_mapping || {{}};

            let level1Count = 0;
            let level2Count = 0;
            let criticalCount = 0;
            let categoriesDetected = 0;

            const level1Projects = new Set();
            const level2Projects = new Set();
            const criticalProjects = new Set();

            // Count issues by level and severity
            Object.entries(asvsMetrics).forEach(([asvsId, count]) => {{
                if (asvsId === 'OTHER' || count === 0) return;
                categoriesDetected++;

                const asvsInfo = asvsMapping[asvsId];
                if (!asvsInfo) return;

                const level = asvsInfo.level || 1;
                const severity = asvsInfo.severity || 'MEDIUM';

                if (level === 1) {{
                    level1Count += count;
                }} else if (level === 2) {{
                    level2Count += count;
                }}

                if (severity === 'CRITICAL') {{
                    criticalCount += count;
                }}

                // Count affected projects
                const projects = data.projects || [];
                projects.forEach(project => {{
                    const projectMetrics = project.asvs_metrics || {{}};
                    if (projectMetrics[asvsId] > 0) {{
                        if (level === 1) level1Projects.add(project.key);
                        if (level === 2) level2Projects.add(project.key);
                        if (severity === 'CRITICAL') criticalProjects.add(project.key);
                    }}
                }});
            }});

            // Update UI
            document.getElementById('asvsLevel1Issues').textContent = level1Count;
            document.getElementById('asvsLevel1Projects').textContent = `${{level1Projects.size}} projetos afetados`;

            document.getElementById('asvsLevel2Issues').textContent = level2Count;
            document.getElementById('asvsLevel2Projects').textContent = `${{level2Projects.size}} projetos afetados`;

            document.getElementById('asvsCriticalIssues').textContent = criticalCount;
            document.getElementById('asvsCriticalProjects').textContent = `${{criticalProjects.size}} projetos afetados`;

            document.getElementById('asvsCategories').textContent = categoriesDetected;
            document.getElementById('asvsCategoriesChange').textContent = `de 14 categorias ASVS`;
        }}

        function renderASVSTop5Critical() {{
            const data = getFilteredData();
            const asvsMetrics = data.asvs_metrics_global || {{}};
            const asvsMapping = dashboardData.owasp_asvs_mapping || {{}};

            const criticalASVS = Object.entries(asvsMetrics)
                .filter(([id, count]) => {{
                    if (id === 'OTHER' || count === 0) return false;
                    const info = asvsMapping[id];
                    return info && (info.severity === 'CRITICAL' || info.severity === 'HIGH');
                }})
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);

            const container = document.getElementById('asvsTop5CriticalContainer');
            if (!container) return;

            if (criticalASVS.length === 0) {{
                container.innerHTML = `
                    <div style="padding: 30px; text-align: center; color: #28a745;">
                        <i class="fas fa-check-circle" style="font-size: 3rem; margin-bottom: 15px;"></i>
                        <h3>Excelente! Nenhum requisito ASVS crítico detectado.</h3>
                        <p>Continue mantendo as boas práticas de segurança.</p>
                    </div>
                `;
                return;
            }}

            let html = '<div style="padding: 20px;">';
            criticalASVS.forEach(([asvsId, count], index) => {{
                const info = asvsMapping[asvsId];
                if (!info) return;

                const severityColor = {{
                    'CRITICAL': '#dc3545',
                    'HIGH': '#fd7e14',
                    'MEDIUM': '#ffc107'
                }}[info.severity] || '#6c757d';

                html += `
                    <div style="margin-bottom: 25px; padding: 20px; background: white; border-left: 5px solid ${{severityColor}}; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <div style="display: flex; align-items: center; margin-bottom: 15px;">
                            <div style="flex: 1;">
                                <h4 style="margin: 0; color: ${{severityColor}};">
                                    <i class="fas fa-${{info.icon || 'exclamation-triangle'}}"></i>
                                    #${{index + 1}} - ${{asvsId}}: ${{info.name}}
                                </h4>
                                <p style="margin: 5px 0 0 0; color: #6c757d; font-size: 0.9rem;">
                                    ${{info.category}} - Level ${{info.level}}
                                </p>
                            </div>
                            <div style="text-align: right;">
                                <div style="font-size: 2rem; font-weight: bold; color: ${{severityColor}};">${{count}}</div>
                                <div style="font-size: 0.85rem; color: #6c757d;">issues</div>
                            </div>
                        </div>
                        <div style="margin-bottom: 12px;">
                            <strong style="color: #495057;">Descrição:</strong>
                            <p style="margin: 5px 0; color: #6c757d;">${{info.description}}</p>
                        </div>
                        <div style="margin-bottom: 12px;">
                            <strong style="color: #dc3545;">Vetor de Ataque:</strong>
                            <p style="margin: 5px 0; color: #6c757d;">${{info.attack_vector}}</p>
                        </div>
                        <div style="margin-bottom: 12px;">
                            <strong style="color: #28a745;">Mitigação:</strong>
                            <p style="margin: 5px 0; color: #6c757d;">${{info.mitigation}}</p>
                        </div>
                        <div style="padding: 10px; background: #f8f9fa; border-radius: 5px;">
                            <strong style="color: #495057;">Exemplo:</strong>
                            <p style="margin: 5px 0; color: #6c757d; font-style: italic;">${{info.example}}</p>
                        </div>
                    </div>
                `;
            }});
            html += '</div>';
            container.innerHTML = html;
        }}

        function renderASVSTop20VolumeChart() {{
            const ctx = document.getElementById('asvsTop20VolumeChart');
            if (!ctx) return;

            const data = getFilteredData();
            const asvsMetrics = data.asvs_metrics_global || {{}};
            const asvsMapping = dashboardData.owasp_asvs_mapping || {{}};

            const top20 = Object.entries(asvsMetrics)
                .filter(([id, count]) => id !== 'OTHER' && count > 0 && asvsMapping[id])
                .sort((a, b) => b[1] - a[1])
                .slice(0, 20);

            if (charts['asvsTop20Volume']) charts['asvsTop20Volume'].destroy();

            const colors = top20.map(([id]) => {{
                const info = asvsMapping[id];
                return info?.color || '#667eea';
            }});

            charts['asvsTop20Volume'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: top20.map(([id]) => id),
                    datasets: [{{
                        label: 'Issues por Requisito ASVS',
                        data: top20.map(([_, count]) => count),
                        backgroundColor: colors,
                        borderColor: colors.map(c => c),
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            callbacks: {{
                                title: (context) => {{
                                    const asvsId = context[0].label;
                                    const info = asvsMapping[asvsId];
                                    return info ? `${{asvsId}}: ${{info.name}}` : asvsId;
                                }},
                                label: (context) => `Issues: ${{context.parsed.x}}`,
                                afterLabel: (context) => {{
                                    const asvsId = context.label;
                                    const info = asvsMapping[asvsId];
                                    if (!info) return '';
                                    return [
                                        `Categoria: ${{info.category}}`,
                                        `Severidade: ${{info.severity}}`,
                                        `Level: ${{info.level}}`
                                    ];
                                }}
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Número de Issues'
                            }}
                        }},
                        y: {{
                            title: {{
                                display: true,
                                text: 'Requisitos ASVS'
                            }}
                        }}
                    }}
                }}
            }});
        }}

        function renderASVSByProjectChart() {{
            const ctx = document.getElementById('asvsByProjectChart');
            if (!ctx) return;

            const data = getFilteredData();
            const projects = data.projects || [];

            const projectData = projects.map(project => {{
                const asvsMetrics = project.asvs_metrics || {{}};
                const total = Object.entries(asvsMetrics)
                    .filter(([id]) => id !== 'OTHER')
                    .reduce((sum, [_, count]) => sum + count, 0);
                return {{ name: project.name, total }};
            }})
            .filter(p => p.total > 0)
            .sort((a, b) => b.total - a.total)
            .slice(0, 15);

            if (charts['asvsByProject']) charts['asvsByProject'].destroy();

            charts['asvsByProject'] = new Chart(ctx, {{
                type: 'bar',
                data: {{
                    labels: projectData.map(p => p.name),
                    datasets: [{{
                        label: 'Total de Issues ASVS',
                        data: projectData.map(p => p.total),
                        backgroundColor: '#4CAF50',
                        borderColor: '#2E7D32',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            display: false
                        }},
                        tooltip: {{
                            callbacks: {{
                                label: (context) => `Issues ASVS: ${{context.parsed.x}}`
                            }}
                        }}
                    }},
                    scales: {{
                        x: {{
                            beginAtZero: true,
                            title: {{
                                display: true,
                                text: 'Número de Issues'
                            }}
                        }}
                    }}
                }}
            }});
        }}

        function renderASVSGovernanceStatus() {{
            const data = getFilteredData();
            const asvsMetrics = data.asvs_metrics_global || {{}};
            const asvsMapping = dashboardData.owasp_asvs_mapping || {{}};

            // Group by main category
            const categories = {{}};
            Object.entries(asvsMetrics).forEach(([asvsId, count]) => {{
                if (asvsId === 'OTHER' || count === 0) return;
                const info = asvsMapping[asvsId];
                if (!info) return;

                const category = info.category.split(':')[0]; // e.g., "V1" from "V1: Architecture..."
                if (!categories[category]) {{
                    categories[category] = {{ count: 0, name: info.category }};
                }}
                categories[category].count += count;
            }});

            const container = document.getElementById('asvsGovernanceStatusContainer');
            if (!container) return;

            let html = '<div style="padding: 20px;">';
            html += '<div class="grid grid-3" style="gap: 20px;">';

            Object.entries(categories)
                .sort((a, b) => b[1].count - a[1].count)
                .forEach(([catId, catInfo]) => {{
                    const status = catInfo.count === 0 ? 'success' :
                                   catInfo.count < 10 ? 'warning' : 'danger';
                    const statusColor = {{
                        'success': '#28a745',
                        'warning': '#ffc107',
                        'danger': '#dc3545'
                    }}[status];

                    html += `
                        <div style="padding: 20px; background: white; border-radius: 8px; border-left: 5px solid ${{statusColor}}; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                            <h4 style="margin: 0 0 10px 0; color: #495057;">${{catInfo.name}}</h4>
                            <div style="font-size: 2rem; font-weight: bold; color: ${{statusColor}}; margin-bottom: 10px;">
                                ${{catInfo.count}}
                            </div>
                            <div style="font-size: 0.9rem; color: #6c757d;">
                                issues detectadas
                            </div>
                        </div>
                    `;
                }});

            html += '</div></div>';
            container.innerHTML = html;
        }}

        function renderASVSHeatmap() {{
            const ctx = document.getElementById('asvsHeatmapChart');
            if (!ctx) return;

            const data = getFilteredData();
            const projects = (data.projects || []).slice(0, 20);
            const asvsMapping = dashboardData.owasp_asvs_mapping || {{}};

            // Top 10 ASVS
            const asvsMetrics = data.asvs_metrics_global || {{}};
            const topASVS = Object.entries(asvsMetrics)
                .filter(([id, count]) => id !== 'OTHER' && count > 0 && asvsMapping[id])
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .map(([id]) => id);

            const heatmapData = [];
            projects.forEach((project, pIndex) => {{
                topASVS.forEach((asvsId, cIndex) => {{
                    const count = (project.asvs_metrics || {{}})[asvsId] || 0;
                    if (count > 0) {{
                        heatmapData.push({{
                            x: pIndex,
                            y: cIndex,
                            v: count
                        }});
                    }}
                }});
            }});

            const maxValue = Math.max(...heatmapData.map(d => d.v), 1);

            if (charts['asvsHeatmap']) charts['asvsHeatmap'].destroy();

            charts['asvsHeatmap'] = new Chart(ctx, {{
                type: 'scatter',
                data: {{
                    datasets: [{{
                        label: 'ASVS Issues',
                        data: heatmapData,
                        backgroundColor: heatmapData.map(d => {{
                            const intensity = d.v / maxValue;
                            return `rgba(76, 175, 80, ${{intensity}})`;
                        }}),
                        pointRadius: 15,
                        pointHoverRadius: 20
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        x: {{
                            type: 'linear',
                            position: 'bottom',
                            ticks: {{
                                callback: (value) => projects[value]?.name.substring(0, 15) || '',
                                autoSkip: false
                            }},
                            min: -0.5,
                            max: projects.length - 0.5
                        }},
                        y: {{
                            type: 'linear',
                            ticks: {{
                                callback: (value) => topASVS[value] || '',
                                autoSkip: false
                            }},
                            min: -0.5,
                            max: topASVS.length - 0.5
                        }}
                    }},
                    plugins: {{
                        tooltip: {{
                            callbacks: {{
                                label: (context) => {{
                                    const point = context.raw;
                                    return `${{topASVS[point.y]}}: ${{point.v}} issues em ${{projects[point.x]?.name}}`;
                                }}
                            }}
                        }}
                    }}
                }}
            }});
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
    print("\n" + "=" * 70)
    print("  DASHBOARD SONARQUBE + GEMINI AI")
    print("  Análises Inteligentes de Segurança")
    print("=" * 70 + "\n")

    url = input("🔗 SonarQube URL: ").strip()
    token = input("🔑 SonarQube Token: ").strip()

    print("\n💡 Configure Gemini AI para análises inteligentes (opcional)")
    print("   Obtenha sua API Key em: https://makersuite.google.com/app/apikey")
    gemini_key = input("🤖 Gemini API Key (Enter para pular): ").strip()

    if not gemini_key:
        print("⚠️  Continuando sem Gemini AI (análises limitadas)")
        gemini_key = None

    if not url or not token:
        print("\n✗ SonarQube URL e Token são obrigatórios!")
        return

    print()
    print("⏳ ATENÇÃO: Sistema de Intelligence Avançado com Aggregate Report")
    print("   ✓ NOVO: Aba AI Insights com análises Gemini AI")
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

    collector = SonarQubeCollector(url, token, gemini_key)
    
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