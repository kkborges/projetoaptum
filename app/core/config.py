"""Configuração central da aplicação AptumNet."""
import os

DATABASE_URL = os.getenv("APTUM_DATABASE_URL", "sqlite:///./aptumnet.db")
SECRET_KEY = os.getenv("APTUM_SECRET_KEY", "aptumnet-default-secret-change-in-production")
SCAN_TIMEOUT = int(os.getenv("APTUM_SCAN_TIMEOUT", "5"))
SNMP_COMMUNITY = os.getenv("APTUM_SNMP_COMMUNITY", "public")
AGENT_PORT = int(os.getenv("APTUM_AGENT_PORT", "9100"))
SCAN_THREADS = int(os.getenv("APTUM_SCAN_THREADS", "100"))
LOG_LEVEL = os.getenv("APTUM_LOG_LEVEL", "INFO")
ALERT_RETENTION_DAYS = int(os.getenv("APTUM_ALERT_RETENTION_DAYS", "90"))
