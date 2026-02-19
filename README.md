![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Sigma Rules](https://img.shields.io/badge/Detections-Sigma-blue)

# 🛡️ Detection Engineering Portfolio

Welcome to my Detection Engineering portfolio.

This repository contains detection rules, threat hunting use cases, and security research focused on identifying adversary behavior across enterprise environments.

All detections are mapped to the **MITRE ATT&CK® framework** and designed to support SOC operations, Incident Response, and Threat Hunting activities.

---

## 🎯 Objectives

* Develop high-fidelity detection rules
* Reduce false positives through tuning
* Map detections to real adversary techniques
* Strengthen Blue Team visibility
* Support proactive threat hunting

---

## 🧠 Detection Coverage

Current focus areas:

* Persistence
* Privilege Escalation
* Credential Access
* Defense Evasion
* Lateral Movement
* Execution

---

## 📂 Repository Structure

```
sigma/
 ├── persistence/
 ├── privilege_escalation/
 ├── credential_access/
 ├── defense_evasion/
 ├── lateral_movement/
 └── execution/

hunting/
 ├── hypotheses/
 └── queries/

conversions/
 ├── elastic/
 ├── sentinel/
 └── splunk/

mappings/
 └── mitre_attack_mapping.md
```

---

## 🛠️ Data Sources & Technologies

* Windows Security Logs
* Sysmon
* Microsoft Defender for Endpoint
* Microsoft Sentinel
* Elastic Stack (ELK)
* Azure / Entra ID
* Office 365 Audit Logs

---

## 📜 Rule Development Standard

Each rule follows:

* Sigma format
* MITRE ATT&CK mapping
* Atomic Red Team validation (when applicable)
* False positive analysis
* Severity classification

---

## 🧪 Lab Validation

Detections are tested using:

* Atomic Red Team
* Manual adversary simulation
* PowerShell tradecraft
* Registry & persistence techniques

---

## 🚀 Featured Use Cases

| MITRE Technique | Detection Use Case           |
| --------------- | ---------------------------- |
| T1547.001       | Run Registry Key Persistence |
| T1053           | Scheduled Task Creation      |
| T1546           | Event Triggered Execution    |
| T1112           | Registry Modification        |

---

## 👨‍💻 Author

**Luiz Junior**
Detection Engineer | Blue Team | Threat Detection

* Focus: Detection Engineering & Threat Hunting
* Specialization: Sigma • SIEM • MITRE ATT&CK

---

## 📌 Disclaimer

This repository is for educational and defensive security purposes only.
All detections are based on publicly known adversary techniques.

---

⭐ If you find this repository useful, feel free to star it.
