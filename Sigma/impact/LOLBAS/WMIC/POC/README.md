Teste Ofensivo vs. Detecção Defensiva

1. Ação do Atacante Para simular a limpeza de backups antes de um Ransomware, usei este comando no PowerShell como Administrador:

wmic shadowcopy delete

<img width="815" height="426" alt="image" src="https://github.com/user-attachments/assets/c46d575e-dc80-450f-8f07-dae62a694358" />


Esse comando deleta instantaneamente todos os pontos de restauração do sistema.

2. Detecção no SIEM Para pegar essa ação, utilizei os logs do Sysmon (Event ID 1). A query abaixo identifica exatamente quando o wmic.exe tenta manipular as shadowcopy.

Query KQL:

event.code:"1" AND winlog.event_data.Image:(*wmic.exe OR *WMIC.exe) AND winlog.event_data.CommandLine:(*shadowcopy* AND (*create* OR *delete* OR *resize*))

3. Resultado O comando foi detectado com sucesso, gerando um alerta de alta prioridade no dashboard do Elastic.

<img width="1892" height="412" alt="image" src="https://github.com/user-attachments/assets/e86c7320-5fa9-4d1f-9f96-b298520fe8a7" />

