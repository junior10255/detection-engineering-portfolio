#!/usr/bin/env python3
"""
Detection Engineering Portfolio Organizer - Ultimate v7.0
=========================================================
✔ Corrige erro __file__ (ambiente interativo)
✔ Cria TODAS as pastas auxiliares automaticamente
✔ .gitkeep em toda estrutura
✔ Proteção contra sobrescrita
✔ Contador de regras inválidas
✔ Cache de leitura YAML (performance)
✔ Melhor identificação MITRE (nome + ID + heurística)
✔ Log final completo (regras + inválidas + cache)

Requer: pip install pyyaml
"""

import os
import shutil
import yaml
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

# --- CONFIG ---
MITRE_TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
]

EXTRA_FOLDERS = ['research/pocs', 'img', 'tools']

# Cache global
CACHE = {}
INVALID_RULES = 0


# =========================
# UTIL
# =========================
def get_script_name():
    try:
        return os.path.basename(__file__)
    except NameError:
        return "interactive_script"


def log(msg, verbose=True):
    if verbose:
        print(msg)


# =========================
# EXTRAÇÃO DE METADADOS
# =========================
def extrair_metadados(path, verbose=False):
    global INVALID_RULES

    if path in CACHE:
        return CACHE[path]

    meta = {'tatica': 'execution', 'level': 'low'}

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            CACHE[path] = meta
            return meta

        # level
        meta['level'] = str(data.get('level', 'low')).lower()

        # validação mínima
        if 'title' not in data or 'logsource' not in data:
            INVALID_RULES += 1
            log(f"⚠️ Regra incompleta: {path}", verbose)

        tags = data.get('tags', [])
        if not isinstance(tags, list):
            tags = [tags]

        # 1. Nome da tática (prioridade)
        for tag in tags:
            tag = str(tag).lower()
            if tag.startswith('attack.') and not tag.startswith('attack.t'):
                nome = tag.split('.')[1].replace('-', '_')
                if nome in MITRE_TACTICS:
                    meta['tatica'] = nome
                    CACHE[path] = meta
                    return meta

        # 2. Técnica ID (tXXXX)
        for tag in tags:
            tag = str(tag).lower()
            if tag.startswith('attack.t'):
                tid = tag.split('.')[1].split('.')[0]

                ID_MAP = {
                    't1059': 'execution',
                    't1047': 'execution',
                    't1053': 'persistence',
                    't1547': 'persistence',
                    't1021': 'lateral_movement',
                    't1003': 'credential_access',
                    't1562': 'defense_evasion',
                    't1486': 'impact'
                }

                if tid in ID_MAP:
                    meta['tatica'] = ID_MAP[tid]
                    CACHE[path] = meta
                    return meta

                # 3. Heurística fallback
                if tid.startswith('t1'):
                    meta['tatica'] = 'initial_access'
                elif tid.startswith('t2'):
                    meta['tatica'] = 'execution'
                elif tid.startswith('t3'):
                    meta['tatica'] = 'persistence'

                CACHE[path] = meta
                return meta

    except Exception as e:
        log(f"⚠️ Erro ao ler {path}: {e}", verbose)

    CACHE[path] = meta
    return meta


# =========================
# ESTRUTURA
# =========================
def criar_pastas(base):
    # Sigma
    for t in MITRE_TACTICS:
        os.makedirs(os.path.join(base, 'Sigma', t), exist_ok=True)

    # Extras
    for p in EXTRA_FOLDERS:
        os.makedirs(os.path.join(base, p), exist_ok=True)


def criar_gitkeep(base):
    for root, dirs, files in os.walk(base):
        if '.git' in root:
            continue
        if not files and not dirs:
            Path(os.path.join(root, '.gitkeep')).touch(exist_ok=True)


# =========================
# ORGANIZAÇÃO
# =========================
def organizar(base, verbose=False):
    script_name = get_script_name()

    for item in os.listdir(base):
        full_path = os.path.join(base, item)

        if not os.path.isfile(full_path):
            continue

        if item in ['README.md', script_name]:
            continue

        destino = None
        lower = item.lower()

        if lower.endswith(('.yml', '.yaml')):
            meta = extrair_metadados(full_path, verbose)
            destino = os.path.join(base, 'Sigma', meta['tatica'], item)

        elif lower.endswith('.md'):
            destino = os.path.join(base, 'research/pocs', item)

        elif lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            destino = os.path.join(base, 'img', item)

        if destino:
            if os.path.exists(destino):
                log(f"⚠️ Ignorado (já existe): {item}", verbose)
            else:
                shutil.move(full_path, destino)
                log(f"✔️ {item} -> {destino}", verbose)


# =========================
# README
# =========================
def gerar_readme(base):
    total = 0
    tabela = ""
    contagem = {t: 0 for t in MITRE_TACTICS}

    for t in MITRE_TACTICS:
        pasta = os.path.join(base, 'Sigma', t)

        if not os.path.exists(pasta):
            continue

        for f in sorted(os.listdir(pasta)):
            if f.endswith(('.yml', '.yaml')):
                total += 1
                contagem[t] += 1

                info = extrair_metadados(os.path.join(pasta, f))

                cor = (
                    '🔴' if info['level'] in ['high', 'critical']
                    else '🟡' if info['level'] == 'medium'
                    else '🔵'
                )

                link = f"Sigma/{t}/{f}"

                tabela += f"| {cor} | {t.replace('_',' ').title()} | `{f}` | ✅ | [Abrir]({link}) |\n"

    progresso = int((sum(1 for v in contagem.values() if v > 0) / 14) * 100)
    data = quote(datetime.now().strftime("%d/%m/%Y %H:%M"))

    readme = f"""# 🛡️ Detection Engineering Portfolio

![Progress](https://img.shields.io/badge/PROGRESS-{progresso}%25-orange)
![Rules](https://img.shields.io/badge/Sigma-{total}-blue)
![Updated](https://img.shields.io/badge/Updated-{data}-green)

## 📊 Cobertura MITRE
| Tática | Qtd |
| :--- | :---: |
"""

    for t in MITRE_TACTICS:
        if contagem[t] > 0:
            readme += f"| {t.replace('_',' ').title()} | {contagem[t]} |\n"

    readme += f"""
## 📜 Regras
| Nível | Tática | Nome | Status | Link |
| :---: | :--- | :--- | :---: | :--- |
{tabela if tabela else '| - | - | Nenhuma regra | - | - |'}

---
*Auto-generated*
"""

    with open(os.path.join(base, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)

    return total


# =========================
# MAIN
# =========================
def main(verbose=True):
    base = os.path.abspath('.')

    print("🚀 Organizer v7 iniciado\n")

    criar_pastas(base)
    organizar(base, verbose)
    criar_gitkeep(base)
    total = gerar_readme(base)

    print("\n" + "="*50)
    print(f"✅ Finalizado")
    print(f"📊 {total} regras Sigma")
    print(f"⚠️ {INVALID_RULES} regras com problemas")
    print(f"⚡ {len(CACHE)} arquivos analisados")
    print("="*50)


if __name__ == "__main__":
    main()