import os
import shutil
import yaml  # pip install pyyaml
import json
from datetime import datetime
from pathlib import Path
# --- CONFIGURAÇÃO ---
NOME_USUARIO = "junior10255"
REPO_NAME = "detection-engineering-portfolio"

# Mapeamento oficial de táticas MITRE ATT&CK
MITRE_TACTICS_MAP = {
    'reconnaissance': ['reconnaissance', 'recon'],
    'resource_development': ['resource_development', 'resource'],
    'initial_access': ['initial_access', 'initial'],
    'execution': ['execution', 'exec'],
    'persistence': ['persistence', 'persist'],
    'privilege_escalation': ['privilege_escalation', 'priv_esc', 'privilege'],
    'defense_evasion': ['defense_evasion', 'defense', 'evasion'],
    'credential_access': ['credential_access', 'credential', 'creds'],
    'discovery': ['discovery', 'discover'],
    'lateral_movement': ['lateral_movement', 'lateral'],
    'collection': ['collection', 'collect'],
    'command_and_control': ['command_and_control', 'c2', 'c&c'],
    'exfiltration': ['exfiltration', 'exfil'],
    'impact': ['impact']
}

PASTAS_SIGMA = [f"sigma/{t}" for t in MITRE_TACTICS_MAP.keys()]
ESTRUTURA_EXTRA = ["research/pocs", "research/notes", "img", "docs", "tools"]

CACHE_METADADOS = {}

def validar_regra_sigma(data):
    """Verifica se a regra possui os campos obrigatórios do padrão Sigma."""
    if not isinstance(data, dict):
        return False
    campos_obrigatorios = ['title', 'logsource', 'detection']
    return all(campo in data for campo in campos_obrigatorios)

def extrair_metadados_sigma(caminho_arquivo):
    """Extrai tática, nível de severidade e validação da regra."""
    if caminho_arquivo in CACHE_METADADOS:
        return CACHE_METADADOS[caminho_arquivo]

    metadados = {'tatica': 'execution', 'level': 'low', 'valida': False}
    
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if not data:
                return metadados

        metadados['valida'] = validar_regra_sigma(data)
        metadados['level'] = str(data.get('level', 'low')).lower()

        if 'tags' in data:
            for tag in data['tags']:
                tag = str(tag).lower()
                if tag.startswith('attack.') and not tag.startswith('attack.t'):
                    tatica_bruta = tag.split('.')[1]
                    for tatica_oficial, aliases in MITRE_TACTICS_MAP.items():
                        if tatica_bruta in aliases or tatica_bruta == tatica_oficial:
                            metadados['tatica'] = tatica_oficial
                            break
    except Exception:
        pass
        
    CACHE_METADADOS[caminho_arquivo] = metadados
    return metadados

def criar_pastas():
    """Cria a estrutura de diretórios e arquivos .gitkeep para pastas vazias."""
    print("🛠️  Organizando estrutura de pastas...")
    for pasta in PASTAS_SIGMA + ESTRUTURA_EXTRA:
        os.makedirs(pasta, exist_ok=True)
    
    for root, dirs, files in os.walk('.'):
        if any(x in root for x in ['.git', '.venv', '__pycache__']): continue
        if not files and not dirs:
            Path(os.path.join(root, '.gitkeep')).touch()

def organizar_arquivos_raiz():
    """Move arquivos Sigma e Markdown da raiz para as pastas corretas."""
    print("📦 Organizando arquivos soltos na raiz...")
    ignorados = ['setup_portfolio_pro.py', 'script.py', 'README.md', 'LICENSE', '.gitignore', 'metrics.json']
    for arquivo in os.listdir('.'):
        if os.path.isfile(arquivo) and arquivo not in ignorados:
            destino = None
            if arquivo.endswith(('.yml', '.yaml')):
                m = extrair_metadados_sigma(arquivo)
                destino = os.path.join("sigma", m['tatica'], arquivo)
            elif arquivo.endswith('.md'):
                destino = os.path.join("research/pocs", arquivo)
            
            if destino:
                os.makedirs(os.path.dirname(destino), exist_ok=True)
                shutil.move(arquivo, destino)
                print(f"   ➡️  Movido: {arquivo} para {destino}")

def gerar_readme_dinamico():
    """Gera o README.md com links funcionais e porcentagem de cobertura real."""
    print("📝 Atualizando Dashboard e links...")
    total_regras = 0
    regras_por_tatica = {}
    linhas_tabela = ""
    
    if os.path.exists("sigma"):
        for root, dirs, files in os.walk("sigma"):
            for file in files:
                if file.endswith(('.yml', '.yaml')) and not file.startswith('.'):
                    total_regras += 1
                    caminho_original = os.path.join(root, file)
                    
                    # CORREÇÃO DE LINK: Força barras '/' para funcionamento no GitHub
                    link_github = caminho_original.replace("\\", "/")
                    
                    m = extrair_metadados_sigma(caminho_original)
                    tatica_nome = m['tatica'].replace('_', ' ').title()
                    regras_por_tatica[tatica_nome] = regras_por_tatica.get(tatica_nome, 0) + 1
                    
                    sev_icon = '🔴' if m['level'] in ['critical', 'high'] else '🟡' if m['level'] == 'medium' else '🔵'
                    status = "✅" if m['valida'] else "⚠️"
                    
                    linhas_tabela += f"| {sev_icon} | {tatica_nome} | `{file}` | {status} | [Analisar Regra]({link_github}) |\n"

    # CORREÇÃO DE PORCENTAGEM: (Táticas Únicas / 14 táticas totais)
    taticas_cobertas = len(regras_por_tatica)
    progresso_mitre = int((taticas_cobertas / 14) * 100)
    
    ultima_atualizacao = datetime.now().strftime("%d/%m/%Y %H:%M")

    stats_taticas = ""
    for t, c in sorted(regras_por_tatica.items()):
        stats_taticas += f"| {t} | {c} |\n"

    conteudo = f"""# 🛡️ Detection Engineering Portfolio

> Portfólio focado na criação de detecções e mapeamento ao framework MITRE ATT&CK®.

![Cobertura MITRE](https://geps.dev/progress/{progresso_mitre}?dangerColor=ff4b2b&warningColor=f9d423&successColor=00ff87)
![Regras](https://img.shields.io/badge/Regras_Sigma-{total_regras}-orange)
![Update](https://img.shields.io/badge/Atualizado-{ultima_atualizacao.replace(' ', '_')}-green)

## 📊 Cobertura por Tática
| Tática | Qtd Regras |
| :--- | :---: |
{stats_taticas if stats_taticas else '| Nenhuma mapeada | 0 |'}

## 📋 Acervo de Regras (Sigma Rules)
| Nível | Tática | Regra (Artefato) | Validação | Link |
| :---: | :--- | :--- | :---: | :---: |
{linhas_tabela if linhas_tabela else '| - | - | Nenhuma regra encontrada | - | - |'}

---
*README atualizado automaticamente via script de automação.*
"""
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(conteudo)

    # Exportar métricas para JSON
    metrics = {
        "total_rules": total_regras,
        "tactics_covered": taticas_cobertas,
        "coverage_pct": progresso_mitre,
        "updated_at": ultima_atualizacao
    }
    with open("metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)

if __name__ == "__main__":
    print("-" * 50)
    criar_pastas()
    organizar_arquivos_raiz()
    gerar_readme_dinamico()
    print("-" * 50)
    print("🚀 Processo concluído com sucesso!")