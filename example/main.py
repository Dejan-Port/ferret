#!/usr/bin/env python3
"""
ServisniPortal agent — primer kompletne konfiguracije.

Kopirati agent.conf.example → agent.conf i podesiti parametre.
Pokretanje: python main.py
Systemd:    ExecStart=/usr/bin/python3 /opt/sp-agent/main.py
"""
import configparser
import logging
import os

from outbound_agent import Agent
from outbound_agent.handlers import AmiHandler, SmsHandler, AiHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%d.%m.%Y %H:%M:%S",
)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "agent.conf")

cfg = configparser.ConfigParser()
cfg.read(CONFIG_FILE)

PORTAL_URL   = cfg.get("agent", "portal_url",   fallback="wss://servisniportal.rs/ws/agent")
TOKEN        = cfg.get("agent", "token",         fallback="")
RECONNECT_S  = int(cfg.get("agent", "reconnect_sec", fallback="10"))

AMI_ENABLED  = cfg.getboolean("ami", "enabled", fallback=False)
SMS_ENABLED  = cfg.getboolean("sms", "enabled", fallback=False)
WEB_ENABLED  = cfg.getboolean("web", "enabled", fallback=False)
AI_ENABLED   = cfg.getboolean("ai",  "enabled", fallback=False)

# Dodatni poznati SMS pošiljaoci iz [senders] sekcije
extra_senders = {}
if cfg.has_section("senders"):
    for key, val in cfg.items("senders"):
        extra_senders[key.upper()] = val

# ── Agent ─────────────────────────────────────────────────────────────────────

agent = Agent(url=PORTAL_URL, token=TOKEN, reconnect_sec=RECONNECT_S)

if AMI_ENABLED or SMS_ENABLED:
    ami = AmiHandler(
        host     = cfg.get("ami", "host",     fallback="localhost"),
        port     = int(cfg.get("ami", "port", fallback="5038")),
        user     = cfg.get("ami", "user",     fallback=""),
        password = cfg.get("ami", "password", fallback=""),
        dongle   = cfg.get("ami", "modem",    fallback=""),
    )
    if AMI_ENABLED:
        ami.register(agent)

if SMS_ENABLED:
    sms = SmsHandler(
        ami_host     = cfg.get("ami", "host",     fallback="localhost"),
        ami_port     = int(cfg.get("ami", "port", fallback="5038")),
        ami_user     = cfg.get("ami", "user",     fallback=""),
        ami_password = cfg.get("ami", "password", fallback=""),
        ami_dongle   = cfg.get("ami", "modem",    fallback=""),
        incoming_log = cfg.get("sms", "incoming_log", fallback="/var/log/asterisk/sms.txt"),
        sent_log     = cfg.get("sms", "sent_log",     fallback=os.path.join(BASE_DIR, "sent.txt")),
        portal_url   = PORTAL_URL,
        portal_token = TOKEN,
        known_senders = extra_senders,
        web_enabled  = WEB_ENABLED,
        web_port     = int(cfg.get("web", "port", fallback="7000")),
    )
    sms.register(agent)

if AI_ENABLED:
    ai = AiHandler(
        ollama_url = cfg.get("ai", "ollama_url", fallback="http://localhost:11434"),
        model      = cfg.get("ai", "model",      fallback="llava:7b-v1.6-mistral-q4_0"),
    )
    ai.register(agent)

if __name__ == "__main__":
    agent.run()
