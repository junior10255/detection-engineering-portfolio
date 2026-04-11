#!/usr/bin/env python3
"""
Detection Engineering Portfolio - Xtreme v13.0 (Staff Edition)
===================================================================
✔ ATOMIC WRITES: Uso de safe_write em todos os arquivos (README/JSON/Logs).
✔ IDEMPOTENCY: Proteção contra sobreescrita acidental no movimento de arquivos.
✔ WEIGHTED HEURISTICS: Classificação de táticas por sistema de pontuação/pesos.
✔ ROBUST NORMALIZATION: Sanitização rigorosa de strings e metadados.
✔ AUDIT PERSISTENCE: Gravação física de logs de processamento para debugging.
"""

import os
import shutil
import yaml
import json
from datetime import datetime
from pathlib import Path
import tempfile
import re

# =========================
# CONFIGURAÇÃO DE DOMÍNIO
# =========================
MITRE_TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
]

EXTRA_FOLDERS = ['research/pocs', 'img', 'tools', 'audit']

ID_TO_TACTIC = {
    't1595': 'reconnaissance', 't1566': 'initial_access',
    't1059': 'execution', 't1047': 'execution',
    't1053': 'persistence', 't1547': 'persistence',
    't1021': 'lateral_movement', 't1003': 'credential_access',
    't1027': 'defense_evasion', 't1070': 'defense_evasion',
    't1087': 'discovery', 't1082': 'discovery',
    't1485': 'impact', 't1071': 'command_and_control'
}

# Estado Global
CACHE = {}
PROCESSED = set()
GLOBAL_STATS = {}

SCRIPT_NAME = os.path.basename(__file__) if "__file__" in globals() else "organize.py"

# =========================
# GESTÃO DE ESTADO E LOGS
# =========================

def reset_stats():
    global GLOBAL_STATS, PROCESSED, CACHE
    PROCESSED.clear()
    CACHE.clear()
    GLOBAL_STATS = {
        "invalid_count": 0,
        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "logsources": {},
        "authors": {},
        "audit_log": []
    }

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[*] [{ts}] {msg}"
    print(formatted_msg)
    GLOBAL_STATS["audit_log"].append(formatted_msg)

def safe_write(path, content):
    """Garante escrita atômica para evitar corrupção de arquivos."""
    dir_name = os.path.dirname(path) or "."
    os.makedirs(dir_name, exist_ok=True)
    
    # Cria arquivo temporário no mesmo sistema de arquivos
    fd, temp_p = tempfile.mkstemp(dir=dir_name, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
            tmp.write(content)
        # Operação atômica de substituição
        os.replace(temp_p, path)
    except Exception as e:
        if os.path.exists(temp_p): os.remove(temp_p)
        print(f"!!! ERRO CRÍTICO escrita em {path}: {e}")

def persist_audit(base):
    audit_path = os.path.join(base, 'audit', 'process.log')
    log_content = "\n".join(GLOBAL_STATS["audit_log"])
    safe_write(audit_path, log_content)

# =========================
# INTELIGÊNCIA DE QUALIDADE
# =========================

def aplicar_heuristica_ponderada(data):
    """Classificação baseada em pesos para maior precisão de tática."""
    content_str = str(data).lower()
    
    pesos = {
        'credential_access': [('lsass', 3), ('mimikatz', 4), ('password', 1), ('credential', 1), ('ntlm', 2)],
        'lateral_movement': [('psexec', 4), ('smb', 2), ('remote desktop', 3), ('lateral', 2), ('rpc', 1)],
        'discovery': [('whoami', 3), ('net user', 3), ('ipconfig', 2), ('discovery', 1), ('query', 1)],
        'impact': [('ransom', 4), ('encrypt', 3), ('delete', 1), ('wipe', 2), ('shadowcopy', 4)],
        'defense_evasion': [('disable', 1), ('obfuscation', 3), ('tamper', 3), ('clear', 2)]
    }

    scores = {}
    for tatica, termos in pesos.items():
        score = sum(peso for termo, peso in termos if termo in content_str)
        scores[tatica] = score

    # Retorna a tática com maior score, se houver empate ou zero, default: execution
    max_tatica = max(scores, key=scores.get)
    if scores[max_tatica] > 0:
        return max_tatica
    
    return 'execution'

def extrair_metadados(path):
    if path in CACHE: return CACHE[path]

    # Defaults limpos
    meta = {
        'tatica': 'execution', 
        'level': 'low', 
        'valid': True, 
        'score': 0, 
        'author': 'Desconhecido', 
        'logsource': 'any/any'
    }

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            meta['valid'] = False
            return meta

        # Normalização Robusta
        meta['level'] = str(data.get('level', 'low')).strip().lower()
        if meta['level'] not in ['critical', 'high', 'medium', 'low']:
            meta['level'] = 'low'
            
        meta['author'] = str(data.get('author', 'Desconhecido')).strip()
        
        # Logsource Normalization
        ls = data.get('logsource', {})
        prod = str(ls.get('product', 'any')).strip().lower()
        svc = str(ls.get('service', 'any')).strip().lower()
        meta['logsource'] = f"{prod}/{svc}"

        # --- SCORING ENGINE ---
        score = 0
        bonus = {'description': 20, 'author': 10, 'falsepositives': 15, 'references': 10, 'tags': 25, 'id': 20}
        score = sum(pt for k, pt in bonus.items() if data.get(k))
        
        if not data.get('falsepositives'): score -= 15
        if not data.get('references'): score -= 10
        
        valid_schema = all(k in data for k in ['title', 'logsource', 'detection'])
        if not valid_schema:
            score -= 30
            meta['valid'] = False

        meta['score'] = max(0, min(score, 100))

        if path not in PROCESSED:
            if not meta['valid']: GLOBAL_STATS['invalid_count'] += 1
            GLOBAL_STATS['severity'][meta['level']] = GLOBAL_STATS['severity'].get(meta['level'], 0) + 1
            GLOBAL_STATS['authors'][meta['author']] = GLOBAL_STATS['authors'].get(meta['author'], 0) + 1
            GLOBAL_STATS['logsources'][meta['logsource']] = GLOBAL_STATS['logsources'].get(meta['logsource'], 0) + 1
            PROCESSED.add(path)

        # --- TACTIC MAPPING (Explicit First) ---
        tags = data.get('tags', [])
        found_tactic = False
        if isinstance(tags, list):
            for tag in [str(t).lower().strip() for t in tags]:
                if tag.startswith('attack.') and not tag.startswith('attack.t'):
                    t_name = tag.split('.')[1].replace('-', '_')
                    if t_name in MITRE_TACTICS:
                        meta['tatica'] = t_name
                        found_tactic = True
                        break
                elif tag.startswith('attack.t'):
                    match = re.search(r't\d{4}', tag)
                    if match:
                        tid = match.group()
                        if tid in ID_TO_TACTIC:
                            meta['tatica'] = ID_TO_TACTIC[tid]
                            found_tactic = True
                            break
        
        if not found_tactic:
            meta['tatica'] = aplicar_heuristica_ponderada(data)

    except Exception as e:
        meta['valid'] = False
        log(f"Falha ao ler YAML {os.path.basename(path)}: {e}")

    CACHE[path] = meta
    return meta

# =========================
# FLUXO DE ORGANIZAÇÃO
# =========================

def preparar_estrutura(base):
    for t in MITRE_TACTICS:
        os.makedirs(os.path.join(base, 'Sigma', t), exist_ok=True)
    for p in EXTRA_FOLDERS:
        os.makedirs(os.path.join(base, p), exist_ok=True)

def organizar(base):
    protected = ['README.md', 'metrics.json', SCRIPT_NAME, 'index.html', '.gitignore', 'LICENSE', 'process.log']
    for f in os.listdir(base):
        full_p = os.path.join(base, f)
        if not os.path.isfile(full_p) or f in protected: continue

        destino = None
        if f.endswith(('.yml', '.yaml')):
            meta = extrair_metadados(full_p)
            destino = os.path.join(base, 'Sigma', meta['tatica'], f)
        elif f.endswith('.md'):
            destino = os.path.join(base, 'research', 'pocs', f)
        elif f.endswith(('.png', '.jpg', '.jpeg', '.svg', '.gif')):
            destino = os.path.join(base, 'img', f)

        if destino:
            os.makedirs(os.path.dirname(destino), exist_ok=True)
            if not os.path.exists(destino):
                try:
                    shutil.move(full_p, destino)
                except Exception as e:
                    log(f"Erro ao mover {f}: {e}")
            else:
                log(f"Conflito ignorado: {f} já existe em {os.path.dirname(destino)}")

def gerar_docs(base):
    log("Consolidando métricas e gerando insights...")
    total, scores, tabela = 0, [], ""
    counts = {t: 0 for t in MITRE_TACTICS}
    sigma_root = os.path.join(base, 'Sigma')
    sev_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}

    for t in MITRE_TACTICS:
        path_t = os.path.join(sigma_root, t)
        if not os.path.exists(path_t): continue
        
        files = [f for f in os.listdir(path_t) if f.endswith(('.yml', '.yaml'))]
        files.sort(key=lambda x: (sev_map.get(extrair_metadados(os.path.join(path_t, x))['level'], 0), x), reverse=True)

        for f in files:
            total += 1
            counts[t] += 1
            info = extrair_metadados(os.path.join(path_t, f))
            scores.append(info['score'])
            emoji = '🔴' if info['level'] in ['high', 'critical'] else '🟡' if info['level'] == 'medium' else '🔵'
            tabela += f"| {emoji} | {t.replace('_',' ').title()} | `{f}` | {info['score']}% | [Ver](Sigma/{t}/{f}) |\n"

    avg_score = round(sum(scores) / len(scores), 2) if scores else 0
    coverage = round((sum(1 for v in counts.values() if v > 0) / len(MITRE_TACTICS)) * 100, 2)

    top_authors = sorted(GLOBAL_STATS['authors'].items(), key=lambda x: x[1], reverse=True)[:3]
    top_sources = sorted(GLOBAL_STATS['logsources'].items(), key=lambda x: x[1], reverse=True)[:3]

    # Métricas JSON com safe_write
    metrics = {
        "summary": {"total": total, "quality": avg_score, "coverage": coverage},
        "details": {"severity": GLOBAL_STATS['severity'], "tactics": counts},
        "insights": {"top_authors": top_authors, "top_logsources": top_sources},
        "updated_at": datetime.now().isoformat()
    }
    safe_write(
        os.path.join(base, "metrics.json"),
        json.dumps(metrics, indent=4, ensure_ascii=False, sort_keys=True)
    )

    # README com safe_write
    insights_md = "## 💡 Insights do Portfólio\n\n"
    insights_md += "### 🧑‍💻 Top Contribuidores\n" + "\n".join([f"- {a} ({c} regras)" for a, c in top_authors]) + "\n\n"
    insights_md += "### 🔌 Fontes de Log Predominantes\n" + "\n".join([f"- `{s}` ({c} regras)" for s, c in top_sources]) + "\n"

    readme_content = f"""# 🛡️ Detection Engineering Portfolio

![MITRE](https://img.shields.io/badge/MITRE%20Coverage-{coverage}%25-blueviolet)
![Maturity](https://img.shields.io/badge/Quality%20Score-{avg_score}%25-brightgreen)
![Volume](https://img.shields.io/badge/Sigma%20Rules-{total}-blue)

{insights_md}

## 📋 Inventário (Ranking por Severidade)
| Nível | Tática | Regra | Qualidade | Link |
|:---:|:---|:---|:---:|:---|
{tabela if tabela else '| - | - | Vazio | - | - |'}

---
_Gerado via {SCRIPT_NAME} v13.0 Staff Edition_
"""
    safe_write(os.path.join(base, "README.md"), readme_content)
    log(f"Portfolio Finalizado: {total} regras | {coverage}% Cobertura MITRE")
    persist_audit(base)

if __name__ == "__main__":
    current_dir = os.getcwd()
    print(f"🚀 Iniciando {SCRIPT_NAME} v13.0 Staff Edition")
    reset_stats()
    preparar_estrutura(current_dir)
    organizar(current_dir)
    gerar_docs(current_dir)