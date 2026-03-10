# AptumNet - Network Monitoring & Security Platform

Plataforma completa de monitoramento de rede e segurança com scanner de rede, detecção de intrusão, análise de vulnerabilidades e visualização de topologia.

## Funcionalidades

- **Scanner de Rede**: Descoberta de hosts, scan de portas, identificação de serviços
- **Monitoramento SNMP**: Coleta de métricas via SNMP v1/v2c/v3
- **Agente de Monitoramento**: Agente leve para coleta de informações dos hosts
- **Topologia de Rede**: Visualização gráfica da topologia de rede
- **IDS**: Sistema de detecção de intrusão baseado em regras
- **Pentest**: Ferramentas integradas de teste de penetração
- **Análise de Logs**: Coleta e análise centralizada de logs
- **Detecção de Anomalias**: Identificação automática de comportamentos anômalos
- **Dashboard**: Portal web com visualização em tempo real

## Instalação

```bash
pip install -r requirements.txt
```

## Execução

```bash
# Iniciar o servidor
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# Iniciar o agente (nos hosts monitorados)
python -m app.agent.agent_client --server http://servidor:8000
```

## Arquitetura

```
┌─────────────────────────────────────────────────┐
│                 Dashboard Web                    │
│    (Topologia │ Métricas │ Alertas │ Segurança)  │
├─────────────────────────────────────────────────┤
│                  FastAPI Backend                 │
├────────┬────────┬────────┬────────┬─────────────┤
│Scanner │  SNMP  │ Agent  │  IDS   │  Pentest    │
│  Rede  │Collect │ System │ Engine │  Scanner    │
├────────┴────────┴────────┴────────┴─────────────┤
│            Anomaly Detection Engine              │
├─────────────────────────────────────────────────┤
│              SQLite Database                     │
└─────────────────────────────────────────────────┘
```
