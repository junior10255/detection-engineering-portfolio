#!/usr/bin/env python3
"""
Detection Engineering Portfolio - Xtreme v10.1 (Enterprise Hardened)
===================================================================
✔ Fix cálculo de qualidade média
✔ Proteção total contra crash (pastas / encoding)
✔ .gitkeep em toda estrutura
✔ Proteção contra sobrescrita
✔ Auditoria robusta
✔ Pronto para CI/CD
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

CACHE = {}
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
def get_script_name():
    try:
        return os.path.basename(__file__)
    except:
        return "script.py"


def log_audit(msg):
    GLOBAL_STATS["audit_log"].append(f"[{datetime.now().isoformat()}] {msg}")


# =========================
# SCORE
# =========================
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

        meta['level'] = str(data.get('level', 'low')).lower()
        meta['author'] = data.get('author', 'Unknown')
        meta['score'] = calcular_score(data)

        # Logsource
        ls = data.get('logsource', {})
        ls_str = f"{ls.get('product','any')}/{ls.get('service','any')}"
        meta['logsource'] = ls_str

        # Stats
        GLOBAL_STATS['severity'][meta['level']] = GLOBAL_STATS['severity'].get(meta['level'], 0) + 1
        GLOBAL_STATS['logsources'][ls_str] = GLOBAL_STATS['logsources'].get(ls_str, 0) + 1
        GLOBAL_STATS['authors'][meta['author']] = GLOBAL_STATS['authors'].get(meta['author'], 0) + 1

        # Validação
        if not all(k in data for k in ['title', 'logsource', 'detection']):
            meta['valid'] = False
            GLOBAL_STATS['invalid'] += 1

        # MITRE
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
        log_audit(f"Erro em {path}: {e}")
        meta['valid'] = False
        GLOBAL_STATS['invalid'] += 1

    CACHE[path] = meta
    return meta


# =========================
# ESTRUTURA
# =========================
def preparar_estrutura(base):
    for t in MITRE_TACTICS:
        os.makedirs(os.path.join(base, 'Sigma', t), exist_ok=True)

    for p in EXTRA_FOLDERS:
        os.makedirs(os.path.join(base, p), exist_ok=True)

    # .gitkeep global
    for root, dirs, files in os.walk(base):
        if '.git' in root:
            continue
        if not files and not dirs:
            Path(os.path.join(root, '.gitkeep')).touch(exist_ok=True)


# =========================
# ORGANIZAÇÃO
# =========================
def organizar(base):
    script = get_script_name()

    for f in os.listdir(base):
        if f in ['README.md', 'metrics.json', script, 'index.html']:
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

        if destino:
            if os.path.exists(destino):
                log_audit(f"IGNORADO (existe): {f}")
            else:
                shutil.move(full, destino)
                log_audit(f"MOVIDO: {f} -> {destino}")


# =========================
# DASHBOARD
# =========================
def gerar_docs(base):
    total = 0
    scores = []
    tabela = ""
    counts = {t: 0 for t in MITRE_TACTICS}

    poc_dir = os.path.join(base, 'research/pocs')
    pocs = []
    if os.path.exists(poc_dir):
        pocs = [os.path.splitext(f)[0] for f in os.listdir(poc_dir) if f.endswith('.md')]

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

                link = f"Sigma/{t}/{f}"

                poc_link = "---"
                for p in pocs:
                    if p in f or os.path.splitext(f)[0] in p:
                        poc_link = f"[🔍 POC](research/pocs/{p}.md)"
                        break

                tabela += f"| {cor} | {t.title()} | `{f}` | {info['score']}% | {poc_link} | [Regra]({link}) |\n"

    avg_score = round(sum(scores) / len(scores), 2) if scores else 0

    # JSON
    metrics = {
        "summary": {
            "total": total,
            "invalid": GLOBAL_STATS['invalid'],
            "avg_quality": avg_score
        },
        "severity": GLOBAL_STATS['severity'],
        "tactics": counts,
        "sources": GLOBAL_STATS['logsources'],
        "authors": GLOBAL_STATS['authors'],
        "updated_at": datetime.now().isoformat()
    }

    with open(os.path.join(base, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

    # README
    gaps = [t.title() for t, c in counts.items() if c == 0]
    data = quote(datetime.now().strftime("%d/%m/%Y %H:%M"))

    readme = f"""# 🛡️ Detection Engineering Portfolio v10

![Quality](https://img.shields.io/badge/Quality-{avg_score}%25-brightgreen)
![Rules](https://img.shields.io/badge/Rules-{total}-blue)
![Updated](https://img.shields.io/badge/Updated-{data}-orange)

## 🎯 Gap Analysis
{", ".join(gaps) if gaps else "Cobertura completa 🚀"}

## 📜 Rules
| Level | Tática | Nome | Score | POC | Link |
| :---: | :--- | :--- | :---: | :---: | :--- |
{tabela if tabela else '| - | - | vazio | - | - | - |'}

---
*Generated by Xtreme Organizer v10.1*
"""

    with open(os.path.join(base, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    with open(os.path.join(base, "audit/process.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(GLOBAL_STATS["audit_log"]))

    return total, avg_score


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    base = os.getcwd()

    print("🚀 Xtreme Organizer v10.1\n")

    preparar_estrutura(base)
    organizar(base)
    total, avg = gerar_docs(base)

    print("\n" + "="*50)
    print(f"✅ Finalizado")
    print(f"📊 Regras: {total}")
    print(f"⭐ Qualidade média: {avg}%")
    print(f"⚠️ Inválidas: {GLOBAL_STATS['invalid']}")
    print(f"⚡ Analisadas: {len(CACHE)}")
    print("="*50)