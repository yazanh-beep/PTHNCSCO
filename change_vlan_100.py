#!/usr/bin/env python3
import paramiko
import time
import sys
import logging
import re
import getpass
import pandas as pd
from typing import Tuple, List, Dict

# ========================= USER CONFIG =========================
# Leave these blank to be prompted at runtime
AGG_IP = "192.168.1.6"  
USERNAME = "admin"
PASSWORD = "cisco"

TIMEOUT = 10
MAX_READ = 65535
VLAN_ID = 100

# Retry configuration
AGG_MAX_RETRIES = 3
AGG_RETRY_DELAY = 5
TARGET_MAX_RETRIES = 10
TARGET_RETRY_DELAY = 30
TARGET_SSH_TIMEOUT = 30
# ===============================================================

# ========================= LOGGING SETUP =======================
class LiveFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[41m', # Red Background
    }
    RESET = '\033[0m'

    def format(self, record):
        try:
            if sys.stdout.isatty():
                color = self.COLORS.get(record.levelname, self.RESET)
                record.levelname = f"{color}{record.levelname}{self.RESET}"
        except Exception: pass
        return super().format(record)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Console Handler
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG) 
ch.setFormatter(LiveFormatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
logger.addHandler(ch)

# File Handler
fh = logging.FileHandler('vlan_fix.log', mode='a')
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s'))
logger.addHandler(fh)

# ========================= SSH HELPERS =========================
def expect_prompt(shell, patterns=("#", ">"), timeout=TIMEOUT, log_output=True):
    buf, end = "", time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(MAX_READ).decode("utf-8", "ignore")
            buf += data
            if log_output and data.strip():
                logger.debug(f"[RECV] {data.strip()[-100:]}") 
            for p in patterns:
                if p in buf: return buf
        time.sleep(0.05)
    return buf

def send_cmd(shell, cmd, patterns=("#", ">"), timeout=TIMEOUT):
    logger.debug(f"[SEND] {cmd}")
    shell.send(cmd + "\n")
    return expect_prompt(shell, patterns, timeout)

# ========================= CORE CONNECT ========================
def connect_to_agg(retry=0):
    global AGG_IP, USERNAME, PASSWORD
    if not AGG_IP: AGG_IP = input("Aggregation Switch IP: ").strip()
    if not USERNAME: USERNAME = input("Username: ").strip()
    if not PASSWORD: PASSWORD = getpass.getpass("Password: ").strip()

    try:
        logger.info(f"[CONNECT] Attempt {retry+1}/{AGG_MAX_RETRIES} to Aggregation: {AGG_IP}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(AGG_IP, username=USERNAME, password=PASSWORD,
                       look_for_keys=False, allow_agent=False, timeout=10)
        shell = client.invoke_shell()
        
        # 1. Clear initial banner/prompt
        expect_prompt(shell, ("#", ">"), timeout=15)
        
        # 2. Handle Enable - FORCE WAIT for Password or #
        # We REMOVE '>' from patterns here so it doesn't trigger early
        out = send_cmd(shell, "enable", patterns=("assword:", "Password:", "#"), timeout=5)
        
        # 3. Send Password if requested
        if "assword:" in
