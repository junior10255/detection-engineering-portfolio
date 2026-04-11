import os
import shutil
import yaml  # pip install pyyaml
from datetime import datetime
from pathlib import Path

# --- CONFIGURAÇÃO ---
# Lista oficial de táticas para pastas e validação
MITRE_TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
]

# Mapeamento de IDs do ATT&CK para pastas (Fallback de precisão)
TACTIC_ID_MAP = {
    't1595': 'reconnaissance', 't1583': 'resource_development', 't1190': 'initial_access',
    't1204': 'execution', 't1053': 'persistence', 't1548': 'privilege_escalation',
    't1562': 'defense_evasion', 't1003': 'credential_access', 't1087': 'discovery',
    't1021': 'lateral_movement', 't1074': 'collection', 't1071': 'command_and_control',
    't1048': 'exfiltration', 't1485': 'impact'
}

def extrair_info_sigma(caminho_arquivo):
    """Extrai tática (via tag ou ID) e nível de severidade da regra."""
    info = {'tatica': 'execution', 'level': 'low'}
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if not data: return info
            
            info['level'] = str(data.get('level', 'low')).lower()
            tags = data.get('tags', [])
            
            for tag in tags:
                tag = str(tag).lower()
                # 1. Tentar por nome direto (attack.execution)
                if tag.startswith('attack.') and not tag.startswith('attack.t'):
                    t_name = tag.split('.')[1].replace('-', '_')
                    if t_name in MITRE_TACTICS:
                        info['tatica'] = t_name
                        return info
                
                # 2. Tentar por ID (attack.t1059)
                if tag.startswith('attack.t'):
                    t_id = tag.split('.')[1]
                    # Verifica se o ID mapeia para uma tática principal
                    for prefix, t_name in TACTIC_ID_MAP.items():
                        if t_id.startswith(prefix[:3]): # Checa o radical do ID
                            info['tatica'] = t_name
                            return info
    except Exception as e:
        print(f"⚠️ Erro ao ler {caminho_arquivo}: {e}")
    return info

def organizar_projeto():
    """Cria pastas e move arquivos soltos."""
    print("📂 Organizando estrutura MITRE...")
    os.makedirs("sigma", exist_ok=True)
    os.makedirs("research/pocs", exist_ok=True)
    os.makedirs("img", exist_ok=True)
    
    for t in MITRE_TACTICS:
        os.makedirs(f"sigma/{t}", exist_ok=True)
    
    arquivos = [f for f in os.listdir('.') if os.path.isfile(f)]
    for arquivo in arquivos:
        if arquivo in ['setup_portfolio_pro.py', 'README.md', '.gitignore']:
            continue
            
        if arquivo.endswith(('.yml', '.yaml')):
            info = extrair_info_sigma(arquivo)
            destino = f"sigma/{info['tatica']}/{arquivo}"
            shutil.move(arquivo, destino)
            print(f"✔️ {arquivo} -> {info['tatica']}")
            
        elif arquivo.endswith('.md'):
            shutil.move(arquivo, f"research/pocs/{arquivo}")
            
        elif arquivo.endswith(('.png', '.jpg', '.jpeg', '.svg')):
            shutil.move(arquivo, f"img/{arquivo}")

def gerar_readme():
    """Gera o README limpo com contagem total de regras."""
    print("📝 Atualizando README...")
    total_regras = 0
    tabela_corpo = ""
    
    if os.path.exists("sigma"):
        for t_pasta in MITRE_TACTICS:
            caminho_t = f"sigma/{t_pasta}"
            if os.path.exists(caminho_t):
                arquivos = [f for f in os.listdir(caminho_t) if f.endswith(('.yml', '.yaml'))]
                for arquivo in sorted(arquivos):
                    total_regras += 1
                    info = extrair_info_sigma(os.path.join(caminho_t, arquivo))
                    cor = '🔴' if info['level'] in ['high', 'critical'] else '🟡' if info['level'] == 'medium' else '🔵'
                    tatica_label = t_pasta.replace('_', ' ').title()
                    tabela_corpo += f"| {cor} | {tatica_label} | `{arquivo}` | ✅ |\n"

    data_hj = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    conteudo = f"""# 🛡️ Detection Engineering Portfolio

> Repositório focado no desenvolvimento de detecções e mapeamento ao framework MITRE ATT&CK®.

**Total de Regras Ativas:** {total_regras}  
**Última Atualização:** {data_hj}

## 📋 Acervo de Regras (Sigma Rules)
| Nível | Tática | Regra (Artefato) | Status |
| :---: | :--- | :--- | :---: |
{tabela_corpo if tabela_corpo else '| - | - | Nenhuma regra encontrada | - |'}

---
*README gerado automaticamente por script de automação.*
"""
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(conteudo)
    return total_regras

if __name__ == "__main__":
    print("-" * 40)
    organizar_projeto()
    total = gerar_readme()
    print("-" * 40)
    print(f"🚀 Sucesso! Portfólio atualizado com {total} regras.")