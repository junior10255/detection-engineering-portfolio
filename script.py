#!/usr/bin/env python3
"""
Detection Engineering Portfolio Organizer - v6 (Production Ready)

Features:
- CLI (--dry-run, --verbose)
- Cache de metadados
- Proteção contra sobrescrita (rename incremental)
- Validação básica de regras Sigma
- Estrutura automática de pastas
- README dinâmico
- Export de métricas (metrics.json)
"""

import os
import shutil
import yaml
import argparse
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

# ================= CONFIG ================= #

MITRE_TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
]

ID_TO_TACTIC = {
    't1595': 'reconnaissance',
    't1566': 'initial_access',
    't1059': 'execution',
    't1047': 'execution',
    't1053': 'persistence',
    't1547': 'persistence',
    't1021': 'lateral_movement',
    't1485': 'impact'
}

CACHE = {}

# ================= LOG ================= #

def log(msg, verbose):
    if verbose:
        print(msg)

# ================= METADATA ================= #

def extrair_metadados_sigma(path, verbose=False):
    if path in CACHE:
        return CACHE[path]

    meta = {'tatica': 'execution', 'level': 'low'}

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            CACHE[path] = meta
            return meta

        meta['level'] = str(data.get('level', 'low')).lower()

        # Validação básica Sigma
        required_fields = ['title', 'logsource', 'detection']
        missing = [f for f in required_fields if f not in data]
        if missing:
            log(f"⚠️ Campos ausentes {missing} em {path}", verbose)

        tags = data.get('tags', [])
        if not isinstance(tags, list):
            tags = [tags]

        tags = [str(t).lower() for t in tags]

        # 1. Tática direta
        for tag in tags:
            if tag.startswith('attack.') and not tag.startswith('attack.t'):
                nome = tag.split('.')[1].replace('-', '_')
                if nome in MITRE_TACTICS:
                    meta['tatica'] = nome
                    CACHE[path] = meta
                    return meta

        # 2. Técnica ID
        for tag in tags:
            if tag.startswith('attack.t'):
                tid = tag.split('.')[1].split('.')[0]
                if tid in ID_TO_TACTIC:
                    meta['tatica'] = ID_TO_TACTIC[tid]
                    CACHE[path] = meta
                    return meta

    except yaml.YAMLError as e:
        log(f"❌ YAML inválido: {path} -> {e}", verbose)
    except Exception as e:
        log(f"❌ Erro ao processar {path}: {e}", verbose)

    CACHE[path] = meta
    return meta

# ================= FILE OPS ================= #

def safe_move(src, dst, dry_run=False, verbose=False):
    if not os.path.exists(dst):
        if not dry_run:
            shutil.move(src, dst)
        log(f"✔️ {src} -> {dst}", verbose)
        return

    base, ext = os.path.splitext(dst)
    counter = 1

    while True:
        new_dst = f"{base}_{counter}{ext}"
        if not os.path.exists(new_dst):
            if not dry_run:
                shutil.move(src, new_dst)
            log(f"⚠️ Renomeado: {src} -> {new_dst}", verbose)
            return
        counter += 1

# ================= STRUCTURE ================= #

def criar_pastas(base, verbose=False):
    # Pastas auxiliares
    for aux in ['research/pocs', 'img', 'tools']:
        os.makedirs(os.path.join(base, aux), exist_ok=True)

    sigma_path = os.path.join(base, "Sigma")
    os.makedirs(sigma_path, exist_ok=True)

    for t in MITRE_TACTICS:
        path = os.path.join(sigma_path, t)
        os.makedirs(path, exist_ok=True)

    # .gitkeep
    for root, dirs, files in os.walk(sigma_path):
        if not files:
            Path(os.path.join(root, ".gitkeep")).touch(exist_ok=True)

    log("📁 Estrutura criada", verbose)
    return sigma_path

# ================= ORGANIZER ================= #

def organizar(base, sigma_path, dry_run=False, verbose=False):
    script_name = os.path.basename(__file__)

    for item in os.listdir(base):
        if not os.path.isfile(item):
            continue

        if item in ['README.md', script_name]:
            continue

        lower = item.lower()
        destino = None

        if lower.endswith(('.yml', '.yaml')):
            meta = extrair_metadados_sigma(item, verbose)
            destino = os.path.join(sigma_path, meta['tatica'], item)

        elif lower.endswith('.md'):
            destino = os.path.join(base, "research", "pocs", item)

        elif lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            destino = os.path.join(base, "img", item)

        if destino:
            os.makedirs(os.path.dirname(destino), exist_ok=True)
            safe_move(item, destino, dry_run, verbose)

# ================= METRICS ================= #

def export_metrics(base, contagem, total):
    data = {
        "total_rules": total,
        "tactics": contagem,
        "last_update": datetime.now().isoformat()
    }

    with open(os.path.join(base, "metrics.json"), "w") as f:
        json.dump(data, f, indent=2)

# ================= README ================= #

def gerar_readme(base, sigma_path):
    total = 0
    contagem = {t: 0 for t in MITRE_TACTICS}
    tabela = ""

    for t in MITRE_TACTICS:
        pasta = os.path.join(sigma_path, t)
        if not os.path.exists(pasta):
            continue

        for arq in sorted(os.listdir(pasta)):
            if arq.endswith(('.yml', '.yaml')):
                total += 1
                contagem[t] += 1

                info = extrair_metadados_sigma(os.path.join(pasta, arq))

                cor = '🔴' if info['level'] in ['high', 'critical'] else '🟡' if info['level'] == 'medium' else '🔵'
                link = f"{os.path.basename(sigma_path)}/{t}/{arq}"

                tabela += f"| {cor} | {t.replace('_',' ').title()} | `{arq}` | [Link]({link}) |\n"

    progresso = int((sum(1 for v in contagem.values() if v > 0) / len(MITRE_TACTICS)) * 100)
    data = quote(datetime.now().strftime("%d/%m/%Y %H:%M"))

    readme = f"""# 🛡️ Detection Engineering Portfolio

![Progress](https://img.shields.io/badge/PROGRESS-{progresso}%25-orange)
![Rules](https://img.shields.io/badge/Sigma-{total}-blue)
![Updated](https://img.shields.io/badge/Updated-{data}-green)

## 📊 Cobertura
| Tática | Qtd |
|---|---|
"""

    for t in MITRE_TACTICS:
        readme += f"| {t.replace('_',' ').title()} | {contagem[t]} |\n"

    readme += f"""
## 📜 Regras
| Nível | Tática | Nome | Link |
|---|---|---|---|
{tabela if tabela else '| - | - | - | - |'}

---
*Auto-generated*
"""

    with open(os.path.join(base, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    export_metrics(base, contagem, total)
    return total

# ================= CLI ================= #

def main():
    parser = argparse.ArgumentParser(description="Detection Portfolio Organizer v6")
    parser.add_argument("--dry-run", action="store_true", help="Simula execução")
    parser.add_argument("--verbose", action="store_true", help="Logs detalhados")

    args = parser.parse_args()
    base = os.path.abspath('.')

    print("🚀 Organizer v6 iniciado")

    sigma_path = criar_pastas(base, args.verbose)
    organizar(base, sigma_path, args.dry_run, args.verbose)
    total_rules = gerar_readme(base, sigma_path)

    print(f"✅ Finalizado | {total_rules} regras Sigma | {len(CACHE)} arquivos analisados")

if __name__ == "__main__":
    main()