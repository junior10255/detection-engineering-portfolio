#!/usr/bin/env python3
"""
Detection Engineering Portfolio Organizer - Senior Edition v3.0
=========================================================
Correção Crítica: Case Sensitivity (Sigma vs sigma) e Links de Tabela.
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

# Mapeamento de táticas (Normalizado para minúsculas internamente)
MITRE_TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
]

ID_TO_TACTIC = {
    't1595': 'reconnaissance', 't1566': 'initial_access', 
    't1059': 'execution', 't1047': 'execution',
    't1053': 'persistence', 't1021': 'lateral_movement',
    't1485': 'impact', 't1486': 'impact'
}

def extrair_metadados_sigma(caminho_arquivo):
    """Lê o YAML e extrai o nível e a tática via tags."""
    metadados = {'tatica': 'execution', 'level': 'medium'}
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8', errors='ignore') as f:
            data = yaml.safe_load(f)
            if not data: return metadados
            
            metadados['level'] = str(data.get('level', 'medium')).lower()
            tags = data.get('tags', [])
            if not isinstance(tags, list): tags = [tags]

            for tag in tags:
                tag = str(tag).lower()
                if 'attack.' in tag:
                    # Tenta ID (t1047)
                    for tid, tac in ID_TO_TACTIC.items():
                        if tid in tag:
                            metadados['tatica'] = tac
                            return metadados
                    # Tenta Nome direto
                    for tac in MITRE_TACTICS:
                        if tac in tag.replace('-', '_'):
                            metadados['tatica'] = tac
                            return metadados
    except:
        pass
    return metadados

def organizar_e_gerar():
    print("🚀 Iniciando Sincronização de Portfólio...")
    base_path = os.path.abspath('.')
    
    # 1. Localizar a pasta Sigma (independente de maiúsculas)
    sigma_folder_name = "Sigma" # Padrão desejado
    atual_sigma = None
    for d in os.listdir(base_path):
        if d.lower() == "sigma" and os.path.isdir(d):
            atual_sigma = d
            sigma_folder_name = d # Mantém o que o usuário já tem (ex: "Sigma")
            break
    
    if not atual_sigma:
        os.makedirs(sigma_folder_name, exist_ok=True)
        atual_sigma = sigma_folder_name

    # 2. Criar subpastas de táticas dentro de Sigma
    for t in MITRE_TACTICS:
        path = os.path.join(atual_sigma, t)
        os.makedirs(path, exist_ok=True)
        if not os.path.exists(os.path.join(path, ".gitkeep")):
            Path(os.path.join(path, ".gitkeep")).touch()

    # 3. Mover ficheiros soltos na raiz para as pastas corretas
    for item in os.listdir(base_path):
        if item.lower().endswith(('.yml', '.yaml')):
            meta = extrair_metadados_sigma(item)
            dest = os.path.join(atual_sigma, meta['tatica'], item)
            print(f"📦 Movendo {item} -> {meta['tatica']}")
            shutil.move(item, dest)

    # 4. Gerar o README Estilizado (conforme as imagens)
    print("📝 Construindo README.md...")
    total_regras = 0
    tabela_regras = ""
    regras_por_tatica = {t: 0 for t in MITRE_TACTICS}

    # Varrer a pasta Sigma para a tabela
    for tatica in MITRE_TACTICS:
        pasta_t = os.path.join(atual_sigma, tatica)
        if os.path.exists(pasta_t):
            arquivos = [f for f in os.listdir(pasta_t) if f.lower().endswith(('.yml', '.yaml'))]
            for arq in sorted(arquivos):
                total_regras += 1
                regras_por_tatica[tatica] += 1
                info = extrair_metadados_sigma(os.path.join(pasta_t, arq))
                
                # Ícone de Nível
                cor = '🔴' if info['level'] in ['high', 'critical'] else '🟡' if info['level'] == 'medium' else '🔵'
                
                # Link formatado para o GitHub
                link_arq = f"{sigma_folder_name}/{tatica}/{arq}"
                
                tabela_regras += f"| {cor} | {tatica.replace('_', ' ').title()} | `{arq}` | ✅ | [Analisar Regra]({link_arq}) |\n"

    taticas_ativas = sum(1 for c in regras_por_tatica.values() if c > 0)
    progresso = int((taticas_ativas / 14) * 100)
    data_att = datetime.now().strftime("%d/%m/%Y %H:%M")

    readme_content = f"""# 🛡️ Detection Engineering Portfolio

| Portfólio focado na criação de detecções e mapeamento ao framework MITRE ATT&CK®. |
| :--- |

![{progresso}%](https://img.shields.io/badge/PROGRESSO-{progresso}%25-orange)
![Regras Sigma](https://img.shields.io/badge/Regras_Sigma-{total_regras}-orange)
![Atualizado](https://img.shields.io/badge/Atualizado-{quote(data_att)}-green?color=97ca00)

## 📊 Cobertura por Tática
| Tática | Qtd Regras |
| :--- | :---: |
"""
    for t in MITRE_TACTICS:
        if regras_por_tatica[t] > 0:
            readme_content += f"| {t.replace('_', ' ').title()} | {regras_por_tatica[t]} |\n"

    readme_content += f"""
## 📜 Acervo de Regras (Sigma Rules)
| Nível | Tática | Regra (Artefato) | Validação | Link |
| :---: | :--- | :--- | :---: | :--- |
{tabela_regras if tabela_regras else '| - | - | Nenhuma regra encontrada | - | - |'}

---
*README atualizado automaticamente via script de automação.*
"""
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    print(f"✨ Sucesso! {total_regras} regras catalogadas.")

if __name__ == "__main__":
    organizar_e_gerar()