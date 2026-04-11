# 🛡️ Detection Engineering Portfolio <img src="https://media.giphy.com/media/v1.Y2lkPTc5MGI3NjExNHJndmR4N3R4N3R4N3R4N3R4N3R4N3R4N3R4N3R4N3R4JmVwPXYxX2ludGVybmFsX2dpZl9ieV9pZCZjdD1n/qgQUggAC3Pfv687qPC/giphy.gif" width="40">

> 🎯 Repositório corporativo focado na pesquisa e engenharia de regras de detecção orientadas ao framework MITRE ATT&CK®.

![Cobertura MITRE](https://geps.dev/progress/14?dangerColor=ff4b2b&warningColor=f9d423&successColor=00ff87)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapeado-blue?style=for-the-badge&logo=mitre-attack)
![Regras Sigma](https://img.shields.io/badge/Regras_Sigma-2-orange?style=for-the-badge&logo=semanticweb)
![Última Atualização](https://img.shields.io/badge/Última_Atualização-11/04/2026_15:51-green?style=for-the-badge)

---

## 📊 Métricas de Cobertura

### Densidade por Tática (MITRE ATT&CK®)
| Tática | Quantidade de Regras |
| :--- | :---: |
| Execution | 1 |
| Impact | 1 |


---

## 📋 Acervo de Detecções (Sigma Rules)

| Sev | Tática | Regra (Artefato) | Validação | Referência |
| :---: | :--- | :--- | :---: | :---: |
| 🔴 | Impact | `01_manipulating_shadow_copies_via_WMIC.yml` | ✅ | [Analisar Regra](sigma/impact/LOLBAS/WMIC/01_manipulating_shadow_copies_via_WMIC.yml) |
| 🔴 | Execution | `01_proc_creation_win_wmic_lateral_movement_ip.yml` | ✅ | [Analisar Regra](sigma/lateral_movement/LOLBAS/WMIC/01_proc_creation_win_wmic_lateral_movement_ip.yml) |


---
### 🏗️ Arquitetura e Organização
Este repositório é gerenciado através de automação Python para garantir conformidade contínua de nomenclatura, categorização de Táticas e validação de schema YAML.
