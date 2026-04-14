# 🛡️ Detection Engineering Portfolio

![MITRE Coverage](https://img.shields.io/badge/MITRE%20Coverage-21.43%25-blueviolet)
![Active Density](https://img.shields.io/badge/Active%20Density-1.0-orange)
![High Impact](https://img.shields.io/badge/High%20Impact-66.67%25-red)
![Avg Quality](https://img.shields.io/badge/Avg%20Quality-100.0%25-yellow)
![Avg Confidence](https://img.shields.io/badge/Avg%20Confidence-40%25-green)

## 📊 Executive Insights
- **Total de Regras:** 3
- **Táticas Cobertas:** 3 / 14
- **Densidade Real:** 1.0 regras por tática ativa
- **Qualidade Média:** 100.0%
- **Confiança Média:** 40%
- **Regras Inválidas:** 0
- **Regras Duplicadas Ignoradas:** 0
- **Impacto Alto (Critical/High):** 66.67% das regras

## 📈 Qualidade por Tática
| Tática | Qualidade Média |
|:---|:---:|
| Impact | 100.0% |
| Lateral Movement | 100.0% |
| Persistence | 100.0% |


## 🚨 Coverage Gaps
- Reconnaissance
- Resource Development
- Initial Access
- Execution
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Collection
- Command And Control
- Exfiltration


## 📋 Top 30 Regras Mais Relevantes

| Nível | Tática(s) | Regra | Qualidade | Conf. | Link |
|:---:|:---|:---|:---:|:---:|:---:|
| 🟠 | Impact | `01_manipulating_shadow_copies_via_WMIC.yml` | 100.0% | 19% | [📄 Ver](Sigma/impact/manipulacao_de_shadow_copies_via_wmic/01_manipulating_shadow_copies_via_WMIC.yml) |
| 🟠 | Lateral Movement | `01_proc_creation_win_wmic_lateral_movement_ip.yml` | 100.0% | 22% | [📄 Ver](Sigma/lateral_movement/movimentacao_lateral_via_wmic_com_execucao_remota/01_proc_creation_win_wmic_lateral_movement_ip.yml) |
| 🟡 | Persistence | `01_persistence_via_run_registry_key.yml` | 100.0% | 79% | [📄 Ver](Sigma/persistence/persistence_via_run_registry_key/01_persistence_via_run_registry_key.yml) |

---
*Gerado via script.py v19.0 em 2026-04-13 22:19:12*
