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

# 3. CORREÇÃO: Cache para evitar ler o mesmo arquivo YAML múltiplas vezes
CACHE_METADADOS = {}

def validar_regra_sigma(data):
    """5. CORREÇÃO: Validação básica do schema Sigma"""
    if not isinstance(data, dict):
        return False
    campos_obrigatorios = ['title', 'logsource', 'detection']
    for campo in campos_obrigatorios:
        if campo not in data:
            return False
    return True

def extrair_metadados_sigma(caminho_arquivo):
    """Lê o YAML, valida e extrai a tática correta e a severidade (level)"""
    # Retorna do cache se já processou esse arquivo hoje
    if caminho_arquivo in CACHE_METADADOS:
        return CACHE_METADADOS[caminho_arquivo]

    metadados = {'tatica': 'execution', 'level': 'low', 'valida': False}
    
    try:
        with open(caminho_arquivo, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            if not data:
                CACHE_METADADOS[caminho_arquivo] = metadados
                return metadados

        metadados['valida'] = validar_regra_sigma(data)
        metadados['level'] = str(data.get('level', 'low')).lower()

        if 'tags' in data:
            for tag in data['tags']:
                tag = str(tag).lower()
                if tag.startswith('attack.') and not tag.startswith('attack.t'):
                    tatica_bruta = tag.split('.')[1]
                    
                    # 4. CORREÇÃO: Normalização segura da tática
                    encontrou = False
                    for tatica_oficial, aliases in MITRE_TACTICS_MAP.items():
                        if tatica_bruta in aliases or tatica_bruta == tatica_oficial:
                            metadados['tatica'] = tatica_oficial
                            encontrou = True
                            break
                    
                    if not encontrou:
                        metadados['tatica'] = 'execution'
                    break

    except Exception as e:
        print(f"⚠️ Erro ao processar o YAML de {caminho_arquivo}: {e}")
        
    CACHE_METADADOS[caminho_arquivo] = metadados
    return metadados

def criar_pastas():
    print("🛠️  Criando estrutura de pastas corporativa...")
    pastas_criadas = 0
    
    for pasta in PASTAS_SIGMA + ESTRUTURA_EXTRA:
        if not os.path.exists(pasta):
            os.makedirs(pasta, exist_ok=True)
            pastas_criadas += 1

    pastas_ignoradas = ['.git', '.github', '.venv', '__pycache__']
    
    for root, dirs, files in os.walk('.'):
        ignorar = any(ign in root for ign in pastas_ignoradas)
        # 1. CORREÇÃO: Cria .gitkeep apenas se a pasta realmente não tem arquivos
        if not ignorar and not files:
            gitkeep_path = os.path.join(root, '.gitkeep')
            Path(gitkeep_path).touch()

    print(f"   ✅ {pastas_criadas} novas pastas criadas na estrutura.")

def organizar_arquivos_raiz():
    print("📦 Procurando arquivos soltos na raiz...")
    
    arquivos = [f for f in os.listdir('.') if os.path.isfile(f)]
    arquivos_ignorados = ['setup_portfolio_pro.py', 'README.md', 'LICENSE', '.gitignore', '.gitattributes', 'metrics.json']
    
    for arquivo in arquivos:
        if arquivo in arquivos_ignorados:
            continue
            
        destino = None
        if arquivo.endswith(('.yml', '.yaml')):
            metadados = extrair_metadados_sigma(arquivo)
            destino = os.path.join("sigma", metadados['tatica'], arquivo)
        elif arquivo.endswith('.md'):
            destino = os.path.join("research/pocs", arquivo)
        elif arquivo.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg')):
            destino = os.path.join("img", arquivo)

        if destino:
            os.makedirs(os.path.dirname(destino), exist_ok=True)
            if os.path.exists(destino):
                print(f"   ⚠️ Aviso: O arquivo '{arquivo}' já existe no destino. Ignorando a movimentação.")
            else:
                shutil.move(arquivo, destino)
                # Atualiza o cache do caminho do arquivo se ele for movido
                if arquivo in CACHE_METADADOS:
                    CACHE_METADADOS[destino] = CACHE_METADADOS.pop(arquivo)
                print(f"   ➡️ Movido: {arquivo} -> {destino}")

def gerar_readme_dinamico():
    print("📝 Compilando o README Dinâmico...")
    
    # 2. CORREÇÃO: Evitar erro caso a pasta sigma não exista
    if not os.path.exists("sigma"):
        print("   ⚠️ Pasta 'sigma' não encontrada. Gerando README padrão.")
        return

    total_regras = 0
    regras_validas = 0
    regras_por_tatica = {}
    linhas_tabela = ""
    
    for root, dirs, files in os.walk("sigma"):
        for file in files:
            if file.endswith(('.yml', '.yaml')) and not file.startswith('.'):
                total_regras += 1
                caminho_completo = os.path.join(root, file)
                
                metadados = extrair_metadados_sigma(caminho_completo)
                if metadados['valida']:
                    regras_validas += 1

                tatica_formatada = metadados['tatica'].replace('_', ' ').title()
                regras_por_tatica[tatica_formatada] = regras_por_tatica.get(tatica_formatada, 0) + 1
                
                nivel = metadados['level']
                if nivel in ['critical', 'high']:
                    severidade = '🔴'
                elif nivel == 'medium':
                    severidade = '🟡'
                elif nivel in ['low', 'informational']:
                    severidade = '🔵'
                else:
                    severidade = '⚪'

                caminho_relativo = caminho_completo.replace('\\', '/')
                status_validacao = "✅" if metadados['valida'] else "⚠️"
                linhas_tabela += f"| {severidade} | {tatica_formatada} | `{file}` | {status_validacao} | [Analisar Regra]({caminho_relativo}) |\n"

    taticas_cobertas = len(regras_por_tatica)
    progresso = min(int((taticas_cobertas / 14) * 100), 100)
    ultima_atualizacao = datetime.now().strftime("%d/%m/%Y %H:%M")

    stats_taticas = ""
    for tatica, count in sorted(regras_por_tatica.items()):
        stats_taticas += f"| {tatica} | {count} |\n"

    if not linhas_tabela:
        linhas_tabela = "| - | Nenhuma regra mapeada ainda | - | - | - |\n"
        stats_taticas = "| Nenhuma tática mapeada | 0 |\n"

    conteudo = f"""# 🛡️ Detection Engineering Portfolio <img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExNHJndmR4N3R4N3R4N3R4N3R4N3R4N3R4N3R4N3R4N3R4JmVwPXYxX2ludGVybmFsX2dpZl9ieV9pZCZjdD1n/qgQUggAC3Pfv687qPC/giphy.gif" width="40">

> 🎯 Repositório corporativo focado na pesquisa e engenharia de regras de detecção orientadas ao framework MITRE ATT&CK®.

![Cobertura MITRE](https://geps.dev/progress/{progresso}?dangerColor=ff4b2b&warningColor=f9d423&successColor=00ff87)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapeado-blue?style=for-the-badge&logo=mitre-attack)
![Regras Sigma](https://img.shields.io/badge/Regras_Sigma-{total_regras}-orange?style=for-the-badge&logo=semanticweb)
![Última Atualização](https://img.shields.io/badge/Última_Atualização-{ultima_atualizacao.replace(' ', '_')}-green?style=for-the-badge)

---

## 📊 Métricas de Cobertura

### Densidade por Tática (MITRE ATT&CK®)
| Tática | Quantidade de Regras |
| :--- | :---: |
{stats_taticas}

---

## 📋 Acervo de Detecções (Sigma Rules)

| Sev | Tática | Regra (Artefato) | Validação | Referência |
| :---: | :--- | :--- | :---: | :---: |
{linhas_tabela}

---
### 🏗️ Arquitetura e Organização
Este repositório é gerenciado através de automação Python para garantir conformidade contínua de nomenclatura, categorização de Táticas e validação de schema YAML.
"""
    
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(conteudo)
    print("   ✅ README gerado com sucesso!")

    # 7. CORREÇÃO: Exportação de métricas para JSON
    metrics = {
        "total_rules": total_regras,
        "valid_rules": regras_validas,
        "coverage_percentage": progresso,
        "tactics_covered": taticas_cobertas,
        "rules_by_tactic": regras_por_tatica,
        "last_update": ultima_atualizacao
    }
    with open("metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=4)
    print("   ✅ metrics.json exportado com sucesso!")

if __name__ == "__main__":
    print("-" * 50)
    criar_pastas()
    organizar_arquivos_raiz()
    gerar_readme_dinamico()
    print("-" * 50)
    # 6. CORREÇÃO: Mensagem mais neutra e profissional
    print("🚀 Processo concluído com sucesso!")