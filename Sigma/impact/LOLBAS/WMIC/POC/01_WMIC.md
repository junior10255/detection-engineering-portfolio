# 🛡️ Prova de Conceito (POC) - WMIC Shadow Copy 

### 1. Cenário Ofensivo (Ataque)
Para simular o comportamento de um Ransomware que tenta impedir a recuperação de dados do sistema, utilizei o seguinte comando no **PowerShell** com privilégios de Administrador:

```powershell
wmic shadowcopy delete
```
<img width="772" height="278" alt="image" src="https://github.com/user-attachments/assets/56e36909-4e31-493c-9229-129b838b99e9" />

Nota: Este comando remove todos os pontos de restauração (Volume Shadow Copies) do Windows.

Para capturar essa ação, utilizei Sysmon. A query abaixo identifica a execução do binário wmic.exe interagindo com comandos de manipulação de backup.

Query LUCENE (Elastic):

```event.code:"1" AND winlog.event_data.Image:(*wmic.exe OR *WMIC.exe) AND winlog.event_data.CommandLine:(*shadowcopy* AND (*create* OR *delete* OR *resize*))```

<img width="1910" height="504" alt="image" src="https://github.com/user-attachments/assets/327c752f-60af-47ef-a037-8532c82ead01" />
