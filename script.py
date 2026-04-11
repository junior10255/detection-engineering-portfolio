import os
import shutil
import yaml  # pip install pyyaml
from datetime import datetime
from pathlib import Path

# --- CONFIGURAÇÃO ---
MITRE_TACTICS = [
    'reconnaissance', 'resource_development', 'initial_access', 'execution',
    'persistence', 'privilege_escalation', 'defense_evasion', 'credential_access',
    'discovery', 'lateral_movement', 'collection', 'command_and_control',
    'exfiltration', 'impact'
]

def extrair_info_simples(caminho_arquivo):
    """Extrai o nível e a tática básica da regra Sigma com mais precisão."""
    # Fallback 'uncategorized' demonstra maior maturidade técnica
    info = {'tatica': 'uncategorized', 'level': 'low'}
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if not data:
                return info
                
            info['level'] = str(data.get('level', 'low')).lower()
            
            # Busca precisa por tags attack.tatica
            for tag in data.get('tags', []):
                tag = str(tag).lower()
                if tag.startswith('attack.') and not tag.startswith('attack.t'):
                    try:
                        tatica_extraida = tag.split('.')[1]
                        if tatica_extraida in MITRE_TACTICS:
                            info['tatica'] = tatica_extraida
                            break
                    except IndexError:
                        continue
    except Exception as e:
        print(f"⚠️ Erro ao processar {caminho_arquivo}: {e}")
        
    return info

def organizar_projeto():
    """Garante a estrutura de pastas e organiza os arquivos soltos com segurança."""
    print("📂 Organizando pastas...")
    # Garante a criação da pasta base
    os.makedirs("sigma", exist_ok=True)
    
    for t in MITRE_TACTICS + ['uncategorized']:
        os.makedirs(f"sigma/{t}", exist_ok=True)
    
    # Move arquivos .yml da raiz para as pastas sigma correspondentes
    for arquivo in os.listdir('.'):
        if arquivo.endswith(('.yml', '.yaml')) and arquivo not in ['README.md']:
            info = extrair_info_simples(arquivo)
            destino = os.path.join("sigma", info['tatica'], arquivo)
            
            # Evita sobrescrever arquivos existentes
            if not os.path.exists(destino):
                shutil.move(arquivo, destino)
                print(f"✔️ {arquivo} -> {info['tatica']}")
            else:
                print(f"⏩ Pulado (já existe): {arquivo} em {info['tatica']}")

def gerar_readme_limpo():
    """Gera o README sem links, focando na contagem total de regras."""
    print("📝 Atualizando README...")
    total_regras = 0
    tabela_corpo = ""
    
    # Ordem de exibição: Táticas oficiais primeiro, depois uncategorized
    pastas_para_exibir = MITRE_TACTICS + ['uncategorized']
    
    for t_pasta in pastas_para_exibir:
        caminho_t = os.path.join("sigma", t_pasta)
        if os.path.exists(caminho_t):
            for arquivo in os.listdir(caminho_t):
                if arquivo.endswith(('.yml', '.yaml')):
                    total_regras += 1
                    info = extrair_info_simples(os.path.join(caminho_t, arquivo))
                    
                    # Ícones Visuais de Severidade
                    cor = '🔴' if info['level'] in ['high', 'critical'] else '🟡' if info['level'] == 'medium' else '🔵'
                    tatica_display = t_pasta.replace('_', ' ').title()
                    
                    # Tabela limpa para portfólio (apenas texto)
                    tabela_corpo += f"| {cor} | {tatica_display} | `{arquivo}` | ✅ |\n"

    data_hj = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    conteudo = f"""# 🛡️ Detection Engineering Portfolio

> Repositório focado no desenvolvimento de detecções e mapeamento ao framework MITRE ATT&CK®.

**Total de Regras:** {total_regras}  
**Última Atualização:** {data_hj}

## 📋 Acervo de Regras (Sigma Rules)
| Nível | Tática | Regra (Artefato) | Status |
| :---: | :--- | :--- | :---: |
{tabela_corpo if tabela_corpo else '| - | - | Nenhuma regra encontrada | - |'}

---
*README atualizado automaticamente via script de automação.*
"""
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(conteudo)

if __name__ == "__main__":
    print("-" * 40)
    organizar_projeto()
    gerar_readme_limpo()
    print("-" * 40)
    print("🚀 Sucesso! Script atualizado com tratamento de erros e links removidos.")