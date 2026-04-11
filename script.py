#!/usr/bin/env python3
"""
Detection Engineering Portfolio - Xtreme v10.3 (Enterprise Hardened)
===================================================================
✔ Corrige duplicação de métricas (cache-safe)
✔ Limpeza automática de arquivos de conflito (.orig, .bak, .rej)
✔ .gitkeep em toda estrutura
✔ Hardening para múltiplas execuções
✔ Proteção contra encoding issues (Windows/Linux)
"""

import os
import shutil
import yaml
import json
from datetime import datetime
from urllib.parse import quote
from pathlib import Path

# =========================
# CONFIG
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

# =========================
# GLOBAL STATE
# =========================
CACHE = {}
PROCESSED = set()

GLOBAL_STATS = {
    "invalid": 0,
    "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "logsources": {},
    "authors": {},
    "audit_log": []
}

# =========================
# UTIL
# =========================
def log_audit(msg):
    GLOBAL_STATS["audit_log"].append(f"[{datetime.now().isoformat()}] {msg}")

def clean_conflicts(base):
    """Remove arquivos de conflito de merge automaticamente"""
    for root, _, files in os.walk(base):
        for f in files:
            if f.endswith(('.orig', '.bak', '.rej')):
                try:
                    os.remove(os.path.join(root, f))
                    log_audit(f"REMOVIDO conflito: {f}")
                except:
                    pass

def ensure_gitkeep(base):
    """Garante .gitkeep em todas pastas vazias"""
    for root, dirs, files in os.walk(base):
        if '.git' in root:
            continue
        if not files and not dirs:
            Path(os.path.join(root, '.gitkeep')).touch(exist_ok=True)

def calcular_score(data):
    score = 0
    weights = {
        'description': 20,
        'author': 10,
        'falsepositives': 20,
        'references': 10,
        'date': 10,
        'tags': 30
    }
    for field, points in weights.items():
        if data.get(field):
            score += points
    return score

# =========================
# METADATA
# =========================
def extrair_metadados(path):
    if path in CACHE:
        return CACHE[path]

    meta = {
        'tatica': 'execution',
        'level': 'low',
        'valid': True,
        'score': 0,
        'author': 'Unknown',
        'logsource': 'Unknown'
    }

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            meta['valid'] = False
            CACHE[path] = meta
            return meta

        # evitar duplicação de métricas
        if path not in PROCESSED:
            meta['level'] = str(data.get('level', 'low')).lower()
            meta['author'] = data.get('author', 'Unknown')
            meta['score'] = calcular_score(data)

            # logsource
            ls = data.get('logsource', {})
            ls_str = f"{ls.get('product','any')}/{ls.get('service','any')}"
            meta['logsource'] = ls_str

            # stats
            GLOBAL_STATS['severity'][meta['level']] = GLOBAL_STATS['severity'].get(meta['level'], 0) + 1
            GLOBAL_STATS['logsources'][ls_str] = GLOBAL_STATS['logsources'].get(ls_str, 0) + 1
            GLOBAL_STATS['authors'][meta['author']] = GLOBAL_STATS['authors'].get(meta['author'], 0) + 1

            if not all(k in data for k in ['title', 'logsource', 'detection']):
                meta['valid'] = False
                GLOBAL_STATS['invalid'] += 1

            PROCESSED.add(path)

        # MITRE mapping
        tags = data.get('tags', [])
        if isinstance(tags, list):
            for tag in [str(t).lower() for t in tags]:
                if tag.startswith('attack.') and not tag.startswith('attack.t'):
                    nome = tag.split('.')[1].replace('-', '_')
                    if nome in MITRE_TACTICS:
                        meta['tatica'] = nome
                        break
                elif tag.startswith('attack.t'):
                    tid = tag.split('.')[1].split('.')[0]
                    if tid in ID_TO_TACTIC:
                        meta['tatica'] = ID_TO_TACTIC[tid]
                        break

    except Exception as e:
        meta['valid'] = False
        GLOBAL_STATS['invalid'] += 1
        log_audit(f"ERRO leitura {path}: {e}")

    CACHE[path] = meta
    return meta

# =========================
# ORGANIZAÇÃO
# =========================
def preparar_estrutura(base):
    for t in MITRE_TACTICS:
        os.makedirs(os.path.join(base, 'Sigma', t), exist_ok=True)

    for p in EXTRA_FOLDERS:
        os.makedirs(os.path.join(base, p), exist_ok=True)

def organizar(base):
    script = os.path.basename(__file__) if "__file__" in globals() else "script.py"

    for f in os.listdir(base):
        if f in ['README.md', 'metrics.json', script, 'index.html', '.gitignore']:
            continue

        full = os.path.join(base, f)
        if not os.path.isfile(full):
            continue

        destino = None

        if f.endswith(('.yml', '.yaml')):
            meta = extrair_metadados(full)
            destino = os.path.join(base, 'Sigma', meta['tatica'], f)

        elif f.endswith('.md'):
            destino = os.path.join(base, 'research/pocs', f)

        elif f.endswith(('.png', '.jpg', '.jpeg', '.svg')):
            destino = os.path.join(base, 'img', f)

        if destino and not os.path.exists(destino):
            shutil.move(full, destino)
            log_audit(f"MOVIDO: {f}")

# =========================
# DOCS
# =========================
def gerar_docs(base):
    total, scores, tabela = 0, [], ""
    counts = {t: 0 for t in MITRE_TACTICS}

    poc_dir = os.path.join(base, 'research/pocs')
    pocs = [os.path.splitext(f)[0] for f in os.listdir(poc_dir) if f.endswith('.md')] if os.path.exists(poc_dir) else []

    for t in MITRE_TACTICS:
        pasta = os.path.join(base, 'Sigma', t)
        if not os.path.exists(pasta):
            continue

        for f in sorted(os.listdir(pasta)):
            if f.endswith(('.yml', '.yaml')):
                total += 1
                counts[t] += 1

                info = extrair_metadados(os.path.join(pasta, f))
                scores.append(info['score'])

                cor = '🔴' if info['level'] in ['high', 'critical'] else '🟡' if info['level'] == 'medium' else '🔵'

                poc_link = "---"
                for p in pocs:
                    if p in f or os.path.splitext(f)[0] in p:
                        poc_link = f"[🔍 POC](research/pocs/{p}.md)"
                        break

                tabela += f"| {cor} | {t.title()} | `{f}` | {info['score']}% | {poc_link} | [Regra](Sigma/{t}/{f}) |\n"

    avg_score = round(sum(scores) / len(scores), 2) if scores else 0

    metrics = {
        "summary": {
            "total": total,
            "invalid": GLOBAL_STATS['invalid'],
            "avg_quality": avg_score
        },
        "severity": GLOBAL_STATS['severity'],
        "tactics": counts,
        "authors": GLOBAL_STATS['authors'],
        "sources": GLOBAL_STATS['logsources'],
        "updated_at": datetime.now().isoformat()
    }

    with open(os.path.join(base, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    data_label = quote(datetime.now().strftime("%d/%m/%Y %H:%M"))

    readme = f"""# 🛡️ Detection Engineering Portfolio

![Quality](https://img.shields.io/badge/Quality-{avg_score}%25-brightgreen)
![Rules](https://img.shields.io/badge/Rules-{total}-blue)
![Updated](https://img.shields.io/badge/Updated-{data_label}-orange)

## 📜 Regras por Tática
| Level | Tática | Nome | Score | POC | Link |
| :---: | :--- | :--- | :---: | :---: | :--- |
{tabela if tabela else '| - | - | vazio | - | - | - |'}

---
*Enterprise Organizer v10.3*
"""

    with open(os.path.join(base, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    os.makedirs(os.path.join(base, "audit"), exist_ok=True)
    with open(os.path.join(base, "audit/process.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(GLOBAL_STATS["audit_log"]))

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    base = os.getcwd()
    print("🚀 Xtreme Organizer v10.3 (Enterprise)")

    clean_conflicts(base)
    preparar_estrutura(base)
    organizar(base)
    ensure_gitkeep(base)
    gerar_docs(base)

    print("✅ Finalizado com sucesso (nível enterprise)")