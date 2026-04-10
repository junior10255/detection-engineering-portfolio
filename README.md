# 🛡️ Portfólio de Detection Engineering

Repositório dedicado ao desenvolvimento de regras de detecção, casos de threat hunting e pesquisas em segurança focadas na identificação de comportamentos maliciosos em ambientes corporativos.

Todas as detecções são mapeadas ao framework MITRE ATT&CK® e projetadas para apoiar operações de SOC, Resposta a Incidentes e Threat Hunting.

---

## 🎯 Objetivos

* Desenvolver regras de detecção de alta fidelidade
* Reduzir falsos positivos através de tuning
* Mapear detecções para técnicas reais de ataque
* Aumentar a visibilidade do Blue Team
* Apoiar atividades de threat hunting

---

## 📂 Estrutura do Repositório

```id="f0r2k9"
sigma/
 ├── reconnaissance/
 ├── resource_development/
 ├── initial_access/
 ├── execution/
 ├── persistence/
 ├── privilege_escalation/
 ├── defense_evasion/
 ├── credential_access/
 ├── discovery/
 ├── lateral_movement/
 ├── collection/
 ├── command_and_control/
 ├── exfiltration/
 └── impact/

---

## 🛠️ Fontes de Dados

* Logs de Segurança do Windows
* Sysmon
* Microsoft Defender for Endpoint
* Elastic Stack (ELK)

---

## 📜 Padrão das Regras

Cada regra segue os seguintes critérios:

* Formato Sigma
* Mapeamento MITRE ATT&CK
* Análise de falso positivo
* Classificação de severidade
* Validação em laboratório

---

## 🧪 Validação em Laboratório

As detecções são testadas utilizando:

* Atomic Red Team
* Simulação manual de ataques
* Técnicas com PowerShell
* Cenários de persistência e pós-exploração

---

## 👨‍💻 Autor

**Luiz Junior**
Detection Engineer | Blue Team | Threat Hunting

Foco: Detection Engineering & Threat Hunting
Especialização: Sigma • SIEM • MITRE ATT&CK

---

## 📌 Aviso

Este repositório é destinado exclusivamente para fins educacionais e defesa em segurança da informação.

---

⭐ Se este projeto for útil para você, considere dar uma estrela.
