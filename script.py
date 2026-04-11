#!/usr/bin/env python3
"""
Detection Engineering Portfolio - Xtreme v14.1 (Architect Edition - Fix)
========================================================================
✔ Corrigido: Agora processa regras já existentes em Sigma/ (não as ignora).
✔ Mantém todas as métricas avançadas e ordenação SOC.
✔ Movimentação segura apenas para arquivos fora do local correto.
"""

import os
import shutil
import yaml
import json
from datetime import datetime
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

MAX_SCORE = 100

GLOBAL_STATS = {
    "invalid_count": 0,
    "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "logsources": {},
    "authors": {},
    "audit_log": []
}

SCRIPT_NAME = os.path.basename(__file__)

def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[*] [{ts}] {msg}"
    print(formatted_msg)
    GLOBAL_STATS["audit_log"].append(formatted_msg)

def safe_write(path, content):
    dir_name = os.path.dirname(path) or "."
    os.makedirs(dir_name, exist_ok=True)
    fd, temp_p = tempfile.mkstemp(dir=dir_name, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
            tmp.write(content)
        os.replace(temp_p, path)
    except Exception as e:
        if os.path.exists(temp_p):
            os.remove(temp_p)
        log(f"ERRO DE ESCRITA: {e}")

def append_audit_log(base, lines):
    log_path = os.path.join(base, 'audit', 'process.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")

def aplicar_heuristica(data):
    content_str = str(data).lower()
    pesos = {
        'credential_access': [('lsass', 3), ('mimikatz', 4), ('password', 1)],
        'lateral_movement': [('psexec', 4), ('smb', 2), ('rpc', 1)],
        'discovery': [('whoami', 3), ('net user', 3), ('ipconfig', 2)],
        'impact': [('ransom', 4), ('encrypt', 3), ('shadowcopy', 4)],
        'defense_evasion': [('disable', 1), ('obfuscation', 3), ('tamper', 3)]
    }
    scores = {tatica: sum(p for t, p in termos if t in content_str) for tatica, termos in pesos.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] >= 3 else 'uncategorized'

def processar_sigma(path):
    meta = {
        'tatica': 'uncategorized',
        'level': 'low',
        'valid': True,
        'score': 0,
        'author': 'Desconhecido',
        'logsource': 'any/any'
    }
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = yaml.safe_load(f)
        if not data or not isinstance(data, dict):
            GLOBAL_STATS['invalid_count'] += 1
            return None

        meta['level'] = str(data.get('level', 'low')).strip().lower()
        if meta['level'] not in GLOBAL_STATS['severity']:
            meta['level'] = 'low'

        meta['author'] = str(data.get('author', 'Desconhecido')).strip()
        ls = data.get('logsource', {})
        meta['logsource'] = f"{ls.get('product', 'any')}/{ls.get('service', 'any')}".lower()

        bonus = {'description': 20, 'author': 10, 'falsepositives': 15,
                 'references': 10, 'tags': 25, 'id': 20}
        raw_score = sum(pt for k, pt in bonus.items() if data.get(k))
        meta['score'] = min(MAX_SCORE, raw_score)
        meta['score_percent'] = round((meta['score'] / MAX_SCORE) * 100, 2)

        tags = data.get('tags', [])
        found = False
        if isinstance(tags, list):
            for tag in tags:
                tag = tag.lower()
                if 'attack.t' in tag:
                    tid = re.search(r't\d{4}', tag)
                    if tid and tid.group() in ID_TO_TACTIC:
                        meta['tatica'] = ID_TO_TACTIC[tid.group()]
                        found = True
                        break
                elif 'attack.' in tag:
                    t_name = tag.split('.')[-1].replace('-', '_')
                    if t_name in MITRE_TACTICS:
                        meta['tatica'] = t_name
                        found = True
                        break
        if not found:
            meta['tatica'] = aplicar_heuristica(data)

        GLOBAL_STATS['severity'][meta['level']] += 1
        GLOBAL_STATS['authors'][meta['author']] = GLOBAL_STATS['authors'].get(meta['author'], 0) + 1
        GLOBAL_STATS['logsources'][meta['logsource']] = GLOBAL_STATS['logsources'].get(meta['logsource'], 0) + 1

        return meta
    except Exception:
        GLOBAL_STATS['invalid_count'] += 1
        return None

def main():
    base = os.getcwd()
    log("Iniciando Xtreme Organizer v14.1...")

    # Cria estrutura de pastas (inclui Sigma e auxiliares)
    for t in MITRE_TACTICS + ['uncategorized']:
        os.makedirs(os.path.join(base, 'Sigma', t), exist_ok=True)
    for p in EXTRA_FOLDERS:
        os.makedirs(os.path.join(base, p), exist_ok=True)

    # Diretórios a ignorar completamente (não processar arquivos de dentro)
    # NOTA: 'Sigma' NÃO está mais na lista para que as regras existentes sejam lidas.
    ignored_dirs = {'.git', 'audit', 'img', 'research', 'tools'}
    ignored_files = {'README.md', 'metrics.json', SCRIPT_NAME, '.gitignore'}

    inventory = []

    # Primeira passada: processar TODOS os arquivos YAML (inclusive dentro de Sigma/)
    # e mover apenas os que estão fora do lugar.
    for root, dirs, files in os.walk(base, topdown=True):
        # Poda apenas os diretórios que queremos ignorar totalmente
        dirs[:] = [d for d in dirs if d not in ignored_dirs]

        for f in files:
            if f in ignored_files:
                continue
            old_path = os.path.join(root, f)
            destino = None

            if f.endswith(('.yml', '.yaml')):
                meta = processar_sigma(old_path)
                if meta:
                    # Destino ideal baseado na tática extraída
                    destino_ideal = os.path.join(base, 'Sigma', meta['tatica'], f)
                    # Adiciona ao inventário sempre (independente de onde está)
                    inventory.append({
                        'file': f,
                        'tactic': meta['tatica'],
                        'level': meta['level'],
                        'score': meta['score'],
                        'score_percent': meta['score_percent'],
                        'author': meta['author'],
                        'logsource': meta['logsource']
                    })
                    # Move apenas se não estiver no local correto
                    if old_path != destino_ideal:
                        destino = destino_ideal
                else:
                    log(f"Regra inválida ignorada: {f}")
            elif f.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
                # Move imagens soltas para img/
                if not old_path.startswith(os.path.join(base, 'img')):
                    destino = os.path.join(base, 'img', f)
            elif f.endswith('.md') and root == base:
                # Move markdown da raiz para research/pocs
                destino = os.path.join(base, 'research', 'pocs', f)

            if destino and old_path != destino:
                os.makedirs(os.path.dirname(destino), exist_ok=True)
                if not os.path.exists(destino):
                    shutil.move(old_path, destino)
                    log(f"Movido: {f} -> {destino}")
                else:
                    log(f"Pulando (já existe no destino): {f}")

    # Métricas
    total_rules = len(inventory)
    covered_set = {i['tactic'] for i in inventory if i['tactic'] != 'uncategorized'}
    taticas_cobertas = len(covered_set)
    missing = [t for t in MITRE_TACTICS if t not in covered_set]

    cov_global = round((taticas_cobertas / len(MITRE_TACTICS)) * 100, 2) if total_rules else 0
    density = round(total_rules / taticas_cobertas, 2) if taticas_cobertas else 0
    avg_quality = round(sum(i['score_percent'] for i in inventory) / total_rules, 2) if total_rules else 0

    high_impact = GLOBAL_STATS['severity']['critical'] + GLOBAL_STATS['severity']['high']
    impact_ratio = round((high_impact / total_rules) * 100, 2) if total_rules else 0

    # Ordenação SOC
    sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    sorted_inventory = sorted(
        inventory,
        key=lambda x: (sev_rank.get(x['level'], 0), x['score_percent']),
        reverse=True
    )

    emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}
    table = "| Nível | Tática | Regra | Qualidade |\n|:---:|:---|:---|:---:|\n"
    for item in sorted_inventory:
        table += f"| {emoji.get(item['level'], '⚪')} | {item['tactic'].replace('_', ' ').title()} | `{item['file']}` | {item['score_percent']}% |\n"

    gaps_section = ""
    if missing:
        gaps_section = "## 🚨 Coverage Gaps\n"
        for t in missing:
            gaps_section += f"- {t.replace('_', ' ').title()}\n"
    else:
        gaps_section = "## ✅ Cobertura Completa\nTodas as 14 táticas do MITRE ATT&CK possuem pelo menos uma detecção.\n"

    readme = f"""# 🛡️ Detection Engineering Portfolio

![MITRE Coverage](https://img.shields.io/badge/MITRE%20Coverage-{cov_global}%25-blueviolet)
![Active Density](https://img.shields.io/badge/Active%20Density-{density}-orange)
![High Impact](https://img.shields.io/badge/High%20Impact-{impact_ratio}%25-red)
![Avg Quality](https://img.shields.io/badge/Avg%20Quality-{avg_quality}%25-yellow)

## 📊 Executive Insights
- **Total de Regras:** {total_rules}
- **Táticas Cobertas:** {taticas_cobertas} / {len(MITRE_TACTICS)}
- **Densidade Real:** {density} regras por tática ativa
- **Qualidade Média:** {avg_quality}%
- **Regras Inválidas Ignoradas:** {GLOBAL_STATS['invalid_count']}
- **Impacto Alto (Critical/High):** {impact_ratio}% das regras

{gaps_section}

## 📋 Detection Inventory (ordenado por risco)
{table}

---
*Gerado via {SCRIPT_NAME} v14.1 em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

    safe_write(os.path.join(base, "README.md"), readme)

    full_metrics = {
        "global_coverage": cov_global,
        "active_density": density,
        "high_impact_ratio": impact_ratio,
        "average_quality": avg_quality,
        "total_rules": total_rules,
        "tactics_covered": taticas_cobertas,
        "missing_tactics": missing,
        "invalid_rules": GLOBAL_STATS['invalid_count'],
        "severity_distribution": GLOBAL_STATS['severity'],
        "top_authors": dict(sorted(GLOBAL_STATS['authors'].items(), key=lambda x: x[1], reverse=True)[:5]),
        "top_logsources": dict(sorted(GLOBAL_STATS['logsources'].items(), key=lambda x: x[1], reverse=True)[:5]),
        "last_update": datetime.now().isoformat()
    }
    safe_write(os.path.join(base, "metrics.json"), json.dumps(full_metrics, indent=4))

    append_audit_log(base, GLOBAL_STATS["audit_log"])

    log(f"Finalizado! Regras: {total_rules} | Cobertura: {cov_global}% | Densidade Ativa: {density} | High Impact: {impact_ratio}%")

if __name__ == "__main__":
    main()