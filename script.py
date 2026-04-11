#!/usr/bin/env python3
"""
Detection Engineering Portfolio Organizer - Senior Edition
=========================================================
Automatiza a estruturação de regras Sigma conforme o MITRE ATT&CK.
Gera um README dinâmico com métricas e tabela de regras.

Melhorias implementadas:
- Cache de metadados para performance.
- Proteção contra sobrescrita de arquivos.
- Normalização de IDs MITRE (Technique vs Sub-technique).
- Persistência recursiva de pastas (.gitkeep).
- Codificação de URLs para Badges.

Requer: pyyaml (pip install pyyaml)
Autor: junior10255
"""

import os
import shutil
import yaml
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

# --- CONFIGURAÇÃO ---
NOME_USUARIO = "junior10255"
REPO_NAME = "detection-engineering-portfolio"

# Lista oficial das 14 táticas do MITRE ATT&CK Enterprise
MITRE_TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
]

# Mapeamento preciso de IDs para Táticas (Normalizado sem sub-técnicas)
ID_TO_TACTIC = {
    't1595': 'reconnaissance', 't1592': 'reconnaissance',
    't1583': 'resource_development', 't1588': 'resource_development',
    't1566': 'initial_access', 't1190': 'initial_access', 't1133': 'initial_access',
    't1059': 'execution', 't1204': 'execution', 't1047': 'execution',
    't1053': 'persistence', 't1136': 'persistence', 't1547': 'persistence',
    't1548': 'privilege_escalation', 't1068': 'privilege_escalation',
    't1562': 'defense_evasion', 't1070': 'defense_evasion', 't1027': 'defense_evasion',
    't1003': 'credential_access', 't1555': 'credential_access', 't1212': 'credential_access',
    't1087': 'discovery', 't1082': 'discovery', 't1018': 'discovery',
    't1021': 'lateral_movement', 't1091': 'lateral_movement', 't1570': 'lateral_movement',
    't1005': 'collection', 't1074': 'collection', 't1114': 'collection',
    't1071': 'command_and_control', 't1090': 'command_and_control', 't1105': 'command_and_control',
    't1048': 'exfiltration', 't1041': 'exfiltration',
    't1485': 'impact', 't1486': 'impact', 't1489': 'impact'
}

EXTRA_FOLDERS = ['research/pocs', 'img', 'tools']

# Cache global para evitar múltiplas leituras de arquivo
METADATA_CACHE = {}

def extrair_metadados_sigma(caminho_arquivo):
    """Extrai tática e severidade com cache e normalização de tags."""
    caminho_str = str(caminho_arquivo)
    if caminho_str in METADATA_CACHE:
        return METADATA_CACHE[caminho_str]

    metadados = {'tatica': 'execution', 'level': 'low'}

    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if not data or not isinstance(data, dict):
                return metadados

        metadados['level'] = str(data.get('level', 'low')).lower()

        tags = data.get('tags', [])
        if not isinstance(tags, list):
            tags = [tags]

        for tag in tags:
            tag = str(tag).lower().strip()

            # Caso 1: Nome da tática explícito (attack.execution)
            if tag.startswith('attack.') and not tag.startswith('attack.t'):
                t_name = tag.split('.')[1].replace('-', '_')
                if t_name in MITRE_TACTICS:
                    metadados['tatica'] = t_name
                    METADATA_CACHE[caminho_str] = metadados
                    return metadados

            # Caso 2: ID da técnica (attack.t1059.001)
            elif tag.startswith('attack.t'):
                # Normaliza: remove sub-técnica (ex: t1059.001 -> t1059)
                tid = tag.split('.')[1].split('.')[0]
                if tid in ID_TO_TACTIC:
                    metadados['tatica'] = ID_TO_TACTIC[tid]
                    METADATA_CACHE[caminho_str] = metadados
                    return metadados

    except Exception as e:
        print(f"    ⚠️ Erro ao processar {caminho_arquivo}: {e}")

    METADATA_CACHE[caminho_str] = metadados
    return metadados


def criar_estrutura_pastas():
    """Cria pastas e garante .gitkeep recursivo para manter a estrutura no Git."""
    print("📁 Criando estrutura de diretórios...")

    pastas_alvo = [os.path.join('sigma', t) for t in MITRE_TACTICS] + EXTRA_FOLDERS
    
    for pasta in pastas_alvo:
        os.makedirs(pasta, exist_ok=True)

    # Garante .gitkeep em todas as pastas vazias para persistência no repositório
    for root, dirs, files in os.walk('.'):
        # Ignora pastas de sistema
        if '.git' in root or '__pycache__' in root:
            continue
        
        # Se a pasta está vazia (ou só tem subpastas vazias), cria .gitkeep
        if not files:
            Path(os.path.join(root, '.gitkeep')).touch(exist_ok=True)

    print("    ✅ Estrutura e persistência (.gitkeep) prontas.")


def mover_arquivos_soltos():
    """Organiza arquivos da raiz com proteção contra sobrescrita."""
    print("📦 Organizando arquivos soltos...")

    arquivos_ignorados = {
        os.path.basename(__file__),
        'README.md', 'LICENSE', '.gitignore', '.gitattributes', 'requirements.txt'
    }

    for arquivo in os.listdir('.'):
        if not os.path.isfile(arquivo) or arquivo in arquivos_ignorados:
            continue

        destino = None
        nome_lower = arquivo.lower()

        if nome_lower.endswith(('.yml', '.yaml')):
            meta = extrair_metadados_sigma(arquivo)
            destino = os.path.join('sigma', meta['tatica'], arquivo)
        
        elif nome_lower.endswith('.md'):
            destino = os.path.join('research', 'pocs', arquivo)

        elif nome_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            destino = os.path.join('img', arquivo)

        if destino:
            if os.path.exists(destino):
                print(f"    ⚠️ Ignorado: {arquivo} já existe em {os.path.dirname(destino)}")
            else:
                os.makedirs(os.path.dirname(destino), exist_ok=True)
                shutil.move(arquivo, destino)
                print(f"    ✔️ Movido: {arquivo} -> {destino}")


def gerar_readme():
    """Gera README dinâmico com métricas reais e badges seguras."""
    print("📝 Atualizando Dashboard do Portfólio...")

    total_regras = 0
    regras_por_tatica = {t: 0 for t in MITRE_TACTICS}
    tabela_corpo = ""

    # Percorre a árvore organizada para coletar dados reais
    for tatica in MITRE_TACTICS:
        pasta_t = os.path.join('sigma', tatica)
        if os.path.exists(pasta_t):
            arquivos = [f for f in os.listdir(pasta_t) if f.endswith(('.yml', '.yaml'))]
            for arquivo in sorted(arquivos):
                total_regras += 1
                regras_por_tatica[tatica] += 1
                
                info = extrair_metadados_sigma(os.path.join(pasta_t, arquivo))
                cor = '🔴' if info['level'] in ['high', 'critical'] else '🟡' if info['level'] == 'medium' else '🔵'
                label_tatica = tatica.replace('_', ' ').title()
                link = f"sigma/{tatica}/{arquivo}"
                tabela_corpo += f"| {cor} | {label_tatica} | [{arquivo}]({link}) | ✅ |\n"

    taticas_cobertas = sum(1 for count in regras_por_tatica.values() if count > 0)
    progresso = int((taticas_cobertas / 14) * 100)
    data_atual = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    # Badge URL encoding
    data_encoded = quote(data_atual)

    readme_content = f"""# 🛡️ Detection Engineering Portfolio <img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExNHJndmR4N3R4N3R4N3R4N3R4N3R4N3R4N3R4N3R4N3R4JmVwPXYxX2ludGVybmFsX2dpZl9ieV9pZCZjdD1n/qgQUggAC3Pfv687qPC/giphy.gif" width="40">

> Repositório profissional para detecção de ameaças e emulação de adversários.

![MITRE Coverage](https://geps.dev/progress/{progresso}?dangerColor=ff4b2b&warningColor=f9d423&successColor=00ff87)
![Sigma Rules](https://img.shields.io/badge/Sigma_Rules-{total_regras}-orange?style=for-the-badge)
![Last Update](https://img.shields.io/badge/Updated-{data_encoded}-blue?style=for-the-badge)

## 📊 Cobertura MITRE ATT&CK®
| Tática | Quantidade |
| :--- | :---: |
"""
    for t in MITRE_TACTICS:
        readme_content += f"| {t.replace('_', ' ').title()} | {regras_por_tatica[t]} |\n"

    readme_content += f"""
## 📋 Catálogo de Detecções Ativas
| Nível | Tática | Regra (Artefato) | Status |
| :---: | :--- | :--- | :---: |
{tabela_corpo if tabela_corpo else '| - | - | Nenhuma regra catalogada | - |'}

---
*Script de automação v2.1 (Senior Edition) - Mantido por {NOME_USUARIO}*
"""
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)


if __name__ == "__main__":
    print("=" * 50)
    print("🚀 DETECTION PORTFOLIO ORGANIZER PRO")
    print("=" * 50)
    criar_estrutura_pastas()
    mover_arquivos_soltos()
    gerar_readme()
    print("=" * 50)
    print(f"✨ Concluído! {len(METADATA_CACHE)} arquivos processados.")