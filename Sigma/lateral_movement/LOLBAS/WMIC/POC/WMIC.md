🛡️ Prova de Conceito (POC) - Movimentação Lateral via WMIC

1. Cenário Ofensivo
Neste cenário, simulei a técnica de Movimentação Lateral. O objetivo do atacante é utilizar o binário legítimo wmic.exe para executar comandos em uma máquina remota (192.168.0.1), ignorando a necessidade de ferramentas de terceiros e utilizando apenas um endereço IP para evitar detecções baseadas em nomes de host

Comando executado no host de origem:

```wmic.exe /node:"192.168.0.1" process call create "cmd /c c:\windows\system32\calc.exe"```
<img width="788" height="176" alt="image" src="https://github.com/user-attachments/assets/a57f5aae-3803-45a2-ae4c-22cc118f0686" />

Cenário Defensivo
A detecção foi projetada para ser de Alta Fidelidade, cruzando o comportamento do binário, a lógica de criação de processo e a presença de padrões de rede (IP).

Query KQL (Elastic):

```event.code:"1" AND winlog.event_data.Image:(*wmic.exe OR *WMIC.exe) AND winlog.event_data.CommandLine:(*process* AND *call* AND *create*) AND winlog.event_data.CommandLine:/.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*/```

<img width="1902" height="497" alt="image" src="https://github.com/user-attachments/assets/5615cfa8-dd34-46db-8ee3-430c9d0d8aff" />
