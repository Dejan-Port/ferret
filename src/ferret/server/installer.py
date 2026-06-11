"""
Generisanje install skriptova za agenta.

Skript ima ugrađeno sve — token, server URL, CA sertifikat, klijentski
sertifikat i privatni ključ. Korisnik preuzme jedan fajl i pokrene.

VAŽNO: Skript sadrži privatni ključ — treba ga tretirati kao tajnu.
       Preuzimanje je zaštićeno admin tokenom.

Korisnik pokrene:
  Linux:   sudo bash install.sh
  Windows: PowerShell -ExecutionPolicy Bypass -File install.ps1
"""


def generate_linux(
    agent_name: str,
    token: str,
    server_url: str,
    ca_pem: str = "",
    cert_pem: str = "",
    key_pem: str = "",
    ca_fp: str = "",
    handlers: str = "proxy,tun",
) -> str:
    ca_line   = f"ca_fingerprint = {ca_fp}" if ca_fp else "# ca_fingerprint ="
    cert_block = _linux_cert_block(ca_pem, cert_pem, key_pem)

    return f"""#!/bin/bash
# ============================================================
# Outbound Agent installer za: {agent_name}
# Generiše: ferret-server
# PAŽNJA: Ovaj fajl sadrži privatni ključ — čuvaj ga tajnim!
# ============================================================
set -e

TOKEN="{token}"
SERVER="{server_url}"
HANDLERS="{handlers}"
CONF_DIR="/etc/ferret"
CONF_FILE="$CONF_DIR/agent.conf"
CERT_FILE="$CONF_DIR/client.pem"
SERVICE="ferret"

echo "=== Outbound Agent installer ==="
echo "  Agent  : {agent_name}"
echo "  Server : $SERVER"
echo ""

# ── Python ────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "Instaliram Python3..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3 python3-pip
    elif command -v yum &>/dev/null; then
        yum install -y -q python3 python3-pip
    elif command -v dnf &>/dev/null; then
        dnf install -y -q python3 python3-pip
    else
        echo "Greška: ne mogu da instaliram Python. Instaliraj ručno i ponovi."
        exit 1
    fi
fi

if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
    curl -sSL https://bootstrap.pypa.io/get-pip.py | python3
fi

# ── ferret ────────────────────────────────────────────
echo "Instaliram ferret..."
python3 -m pip install --quiet --upgrade ferret

# ── sertifikati ───────────────────────────────────────────────
mkdir -p "$CONF_DIR"
{cert_block}

# ── config fajl ──────────────────────────────────────────────
cat > "$CONF_FILE" << 'CONF_EOF'
server = {server_url}
token = {token}
handlers = {handlers}
log_level = INFO
{ca_line}
{"cert_file = /etc/ferret/client.pem" if cert_pem else ""}
CONF_EOF
chmod 600 "$CONF_FILE"
echo "Config: $CONF_FILE"

# ── systemd servis ────────────────────────────────────────────
AGENT_BIN=$(python3 -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable),'ferret'))" 2>/dev/null || echo "ferret")

cat > /etc/systemd/system/$SERVICE.service << UNIT_EOF
[Unit]
Description=Outbound Agent - {agent_name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_BIN --config $CONF_FILE
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT_EOF

systemctl daemon-reload
systemctl enable --now $SERVICE

echo ""
echo "=== Instalacija završena ==="
echo "  Status : systemctl status $SERVICE"
echo "  Logovi : journalctl -u $SERVICE -f"
echo "  Restart: systemctl restart $SERVICE"
"""


def generate_windows(
    agent_name: str,
    token: str,
    server_url: str,
    ca_pem: str = "",
    cert_pem: str = "",
    key_pem: str = "",
    ca_fp: str = "",
    handlers: str = "proxy,tun",
) -> str:
    ca_line   = f"ca_fingerprint = {ca_fp}" if ca_fp else ""
    cert_line = "cert_file = C:\\ProgramData\\ferret\\client.pem" if cert_pem else ""
    cert_block = _windows_cert_block(ca_pem, cert_pem, key_pem)

    return f"""# ============================================================
# Outbound Agent installer za: {agent_name}
# Generiše: ferret-server
# PAŽNJA: Ovaj fajl sadrži privatni ključ — čuvaj ga tajnim!
# Pokretanje: PowerShell -ExecutionPolicy Bypass -File install.ps1
# ============================================================

$ErrorActionPreference = "Stop"

$TOKEN     = "{token}"
$SERVER    = "{server_url}"
$CONF_DIR  = "C:\\ProgramData\\ferret"
$CONF_FILE = "$CONF_DIR\\agent.conf"
$CERT_FILE = "$CONF_DIR\\client.pem"
$SVC_NAME  = "ferret"

Write-Host "=== Outbound Agent installer ===" -ForegroundColor Cyan
Write-Host "  Agent  : {agent_name}"
Write-Host "  Server : $SERVER"
Write-Host ""

# ── Python ────────────────────────────────────────────────────
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {{
    Write-Host "Instaliram Python..." -ForegroundColor Yellow
    $inst = "$env:TEMP\\python-installer.exe"
    Invoke-WebRequest "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe" `
                      -OutFile $inst -UseBasicParsing
    Start-Process $inst -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    Remove-Item $inst
}}

# ── ferret ────────────────────────────────────────────
Write-Host "Instaliram ferret..." -ForegroundColor Yellow
python -m pip install --quiet --upgrade ferret

# ── sertifikati ──────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $CONF_DIR | Out-Null
{cert_block}

# ── config fajl ──────────────────────────────────────────────
@"
server = {server_url}
token = {token}
handlers = {handlers}
log_level = INFO
{ca_line}
{cert_line}
"@ | Set-Content -Path $CONF_FILE -Encoding UTF8

# Zaštiti config i cert fajl
foreach ($f in @($CONF_FILE, $CERT_FILE)) {{
    if (Test-Path $f) {{
        $acl = Get-Acl $f
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "SYSTEM","FullControl","Allow")))
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators","FullControl","Allow")))
        Set-Acl $f $acl
    }}
}}

Write-Host "Config: $CONF_FILE" -ForegroundColor Green

# ── Windows servis ────────────────────────────────────────────
$agentExe = (Get-Command ferret -ErrorAction SilentlyContinue)?.Source
if (-not $agentExe) {{
    $agentExe = python -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable),'Scripts','ferret.exe'))"
}}

$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {{
    nssm install $SVC_NAME $agentExe "--config `"$CONF_FILE`""
    nssm set    $SVC_NAME DisplayName "Outbound Agent - {agent_name}"
    nssm set    $SVC_NAME Start SERVICE_AUTO_START
    nssm start  $SVC_NAME
}} else {{
    sc.exe create $SVC_NAME `
        binPath= "`"$agentExe`" --config `"$CONF_FILE`"" `
        start= auto `
        DisplayName= "Outbound Agent - {agent_name}"
    sc.exe start $SVC_NAME
}}

Write-Host ""
Write-Host "=== Instalacija završena ===" -ForegroundColor Green
Write-Host "  Status : Get-Service $SVC_NAME"
Write-Host "  Restart: Restart-Service $SVC_NAME"
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _linux_cert_block(ca_pem: str, cert_pem: str, key_pem: str) -> str:
    if not cert_pem and not ca_pem:
        return "# Nema sertifikata"

    bundle = ""
    if ca_pem:
        bundle += f"# CA sertifikat\n{ca_pem.strip()}\n"
    if cert_pem:
        bundle += f"\n# Klijentski sertifikat\n{cert_pem.strip()}\n"
    if key_pem:
        bundle += f"\n# Privatni ključ\n{key_pem.strip()}\n"

    # Heredoc sa slučajnim delimiter-om da PEM sadržaj ne može da "pobegne"
    return f"""cat > "$CERT_FILE" << 'CERT_EOF'
{bundle}
CERT_EOF
chmod 600 "$CERT_FILE"
echo "Sertifikat: $CERT_FILE" """


def _windows_cert_block(ca_pem: str, cert_pem: str, key_pem: str) -> str:
    if not cert_pem and not ca_pem:
        return "# Nema sertifikata"

    bundle = ""
    if ca_pem:
        bundle += f"# CA sertifikat\r\n{ca_pem.strip()}\r\n"
    if cert_pem:
        bundle += f"\r\n# Klijentski sertifikat\r\n{cert_pem.strip()}\r\n"
    if key_pem:
        bundle += f"\r\n# Privatni kljuc\r\n{key_pem.strip()}\r\n"

    # PowerShell here-string
    escaped = bundle.replace('"', '`"')
    return f"""@"
{escaped}
"@ | Set-Content -Path $CERT_FILE -Encoding UTF8"""


def generate_oneliner_linux(server_base_url: str, token: str) -> str:
    return (
        f'curl -sSL "{server_base_url}/agents/{token}/installer?os=linux" '
        f'| sudo bash'
    )


def generate_oneliner_windows(server_base_url: str, token: str) -> str:
    return (
        f'irm "{server_base_url}/agents/{token}/installer?os=windows" | iex'
    )
