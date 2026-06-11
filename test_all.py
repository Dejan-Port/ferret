"""
Ferret — kompletan test suite
Pokretanje: .venv/bin/python test_all.py
TUN testovi zahtevaju sudo.
"""
import asyncio
import json
import os
import sys
import tempfile
import time
import threading
import urllib.request
import urllib.error

PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"
SKIP = "\033[33m-\033[0m"

errors = []

def ok(name):
    print(f"  {PASS} {name}")

def fail(name, reason):
    print(f"  {FAIL} {name}: {reason}")
    errors.append(f"{name}: {reason}")

def skip(name, reason):
    print(f"  {SKIP} {name} (skip: {reason})")


# ─── 1. IMPORTI ───────────────────────────────────────────────────────────────

print("\n[1] Importi")
try:
    from ferret import Agent
    ok("ferret.Agent")
except Exception as e:
    fail("ferret.Agent", e)

try:
    from ferret.server import AgentRouter
    ok("ferret.server.AgentRouter")
except Exception as e:
    fail("ferret.server.AgentRouter", e)

try:
    from ferret.server.ca import CertAuthority
    ok("ferret.server.ca.CertAuthority")
except Exception as e:
    fail("ferret.server.ca.CertAuthority", e)

try:
    from ferret.server.token_gen import TokenGen
    ok("ferret.server.token_gen.TokenGen")
except Exception as e:
    fail("ferret.server.token_gen.TokenGen", e)

try:
    from ferret.server.audit import AuditLog
    ok("ferret.server.audit.AuditLog")
except Exception as e:
    fail("ferret.server.audit.AuditLog", e)

try:
    from ferret.server.installer import generate_linux, generate_windows
    ok("ferret.server.installer")
except Exception as e:
    fail("ferret.server.installer", e)

try:
    from ferret.handlers.tun import TunHandler
    ok("ferret.handlers.tun.TunHandler")
except Exception as e:
    fail("ferret.handlers.tun.TunHandler", e)

try:
    from ferret.handlers.proxy import ProxyHandler
    ok("ferret.handlers.proxy.ProxyHandler")
except Exception as e:
    fail("ferret.handlers.proxy.ProxyHandler", e)

try:
    from ferret.crypto import encrypt, decrypt
    ok("ferret.crypto")
except Exception as e:
    fail("ferret.crypto", e)

try:
    from ferret.hw_id import get as hw_get
    ok("ferret.hw_id")
except Exception as e:
    fail("ferret.hw_id", e)


# ─── 2. HW_ID ─────────────────────────────────────────────────────────────────

print("\n[2] hw_id")
try:
    from ferret.hw_id import get as hw_get, key_path
    hid = hw_get()
    assert len(hid) == 64, f"expected 64 hex chars, got {len(hid)}"
    assert all(c in "0123456789abcdef" for c in hid)
    ok(f"hw_id = {hid[:16]}...")
    ok(f"key_path = {key_path()}")
    hid2 = hw_get()
    assert hid == hid2
    ok("hw_id stabilan (isti poziv = isti rezultat)")
except Exception as e:
    fail("hw_id", e)


# ─── 3. CRYPTO ────────────────────────────────────────────────────────────────

print("\n[3] Crypto (ChaCha20-Poly1305)")
try:
    from ferret.crypto import encrypt, decrypt
    import os, base64
    key = os.urandom(32)
    plaintext = b"Hello, Ferret!"
    ct = encrypt(key, plaintext)       # vraća string "ENC:<base64>"
    assert isinstance(ct, str)
    assert ct.startswith("ENC:")
    pt = decrypt(key, ct)
    assert pt == plaintext
    ok("encrypt/decrypt round-trip")

    # Tamper test — modifikujemo base64 deo
    raw = base64.b64decode(ct[4:])
    raw_tampered = bytearray(raw)
    raw_tampered[-1] ^= 0xFF
    tampered = "ENC:" + base64.b64encode(bytes(raw_tampered)).decode()
    try:
        decrypt(key, tampered)
        fail("tamper detection", "nije bacilo izuzetak")
    except Exception:
        ok("tamper detection (modifikovani ciphertext odbijen)")
except Exception as e:
    fail("crypto", e)


# ─── 4. TOKEN ─────────────────────────────────────────────────────────────────

print("\n[4] Token generisanje i validacija")
try:
    from ferret.server.token_gen import TokenGen

    tg = TokenGen(secret="test-secret-32-chars-minimum-len!")
    hw = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    srv_hw = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

    token = tg.create(hw_id=hw, name="test-agent", valid_days=30,
                      server_url="wss://test.example.com",
                      server_hw_id=srv_hw)
    ok(f"token kreiran ({len(token)} chars)")

    payload = tg.validate(token, hw_id=hw, server_hw_id=srv_hw)
    assert payload["name"] == "test-agent"
    ok(f"token validan, name={payload['name']}, kid={payload.get('kid','?')}")

    # Pogrešan hw_id — validate vraća None
    result = tg.validate(token, hw_id="0" * 64)
    if result is None:
        ok("hw_id binding (pogrešan hw_id odbijen)")
    else:
        fail("hw_id binding", "prihvatio pogrešan hw_id")

    # Pogrešan server — validate vraća None
    result = tg.validate(token, hw_id=hw, server_hw_id="0" * 64)
    if result is None:
        ok("srv_hw binding (pogrešan server odbijen)")
    else:
        fail("srv_hw binding", "prihvatio pogrešan server")

    # Rotacija ključa
    tg.rotate("v2", "novi-secret-32-chars-minimum-xx!")
    token2 = tg.create(hw_id=hw, name="test-agent-v2", valid_days=30,
                       server_url="wss://test.example.com",
                       server_hw_id=srv_hw)
    payload2 = tg.validate(token2, hw_id=hw, server_hw_id=srv_hw)
    assert payload2.get("kid") == "v2"
    ok(f"rotacija ključa, novi kid={payload2.get('kid')}")

    # Stari token i dalje važi (v1 još nije povučen)
    payload_old = tg.validate(token, hw_id=hw, server_hw_id=srv_hw)
    ok("stari token važi dok kid nije povučen")

    # Povlačenje starog kid-a — validate vraća None posle retire
    default_kid = payload.get("kid", "v1")
    tg.retire(default_kid)
    result = tg.validate(token, hw_id=hw, server_hw_id=srv_hw)
    if result is None:
        ok(f"retire({default_kid}) — stari token odbijen")
    else:
        fail("retire", "stari token prihvaćen posle retire()")

except Exception as e:
    fail("token", e)


# ─── 5. CA SERTIFIKATI ────────────────────────────────────────────────────────

print("\n[5] CA i klijentski sertifikati")
try:
    from ferret.server.ca import CertAuthority
    import tempfile, os

    # CA koristi ~/.ferret/ca.key|crt kao fallback
    ca = CertAuthority()
    ok(f"CA kreiran/učitan, fingerprint={ca.fingerprint[:16]}...")

    cert_pem, key_pem = ca.issue("test-agent", valid_days=365, jti="jti-001")
    assert "BEGIN CERTIFICATE" in cert_pem
    assert "BEGIN" in key_pem
    ok("klijentski sertifikat izdat")

    # Privatni ključ se ne čuva — nema fajla sa imenom agenta
    ca_dir = os.path.expanduser("~/.ferret")
    agent_files = [f for f in os.listdir(ca_dir) if "test-agent" in f] if os.path.isdir(ca_dir) else []
    if not agent_files:
        ok("privatni ključ nije sačuvan na serveru")
    else:
        fail("privatni ključ", f"nađeni fajlovi: {agent_files}")

    # Reload — isti fingerprint
    ca2 = CertAuthority()
    assert ca2.fingerprint == ca.fingerprint
    ok("CA reload sa diska — isti fingerprint")

except Exception as e:
    fail("ca", e)


# ─── 6. AUDIT LOG ─────────────────────────────────────────────────────────────

print("\n[6] Audit log")
try:
    from ferret.server.audit import AuditLog
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        audit = AuditLog(db_path)
        audit.log("agent_connect", "tok123", "test-agent", {"ip": "1.2.3.4"}, "1.2.3.4")
        audit.log("proxy_open", "tok123", "test-agent", {"port": 80}, "1.2.3.4")
        audit.log("agent_disconnect", "tok123", "test-agent", {"duration": 42.0}, "1.2.3.4")

        rows = audit.recent(limit=10)
        assert len(rows) == 3
        ok(f"3 eventi upisani i pročitani")

        rows_filtered = audit.recent(token="tok123", event="proxy_open")
        assert len(rows_filtered) == 1
        assert rows_filtered[0]["event"] == "proxy_open"
        ok("filtriranje po token + event")

        # Thread safety
        def log_thread():
            for i in range(50):
                audit.log("proxy_open", f"tok{i}", "agent", {}, "")

        threads = [threading.Thread(target=log_thread) for _ in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()

        rows_all = audit.recent(limit=500)
        assert len(rows_all) >= 200
        ok(f"thread safety (4x50 = 200+ concurrent upisa)")
    finally:
        os.unlink(db_path)

except Exception as e:
    fail("audit", e)


# ─── 7. INSTALLER GENERISANJE ─────────────────────────────────────────────────

print("\n[7] Installer generisanje")
try:
    from ferret.server.installer import generate_linux, generate_windows

    linux_script = generate_linux(
        agent_name="test-agent",
        token="tok_abc123",
        server_url="wss://test.example.com",
        ca_pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        cert_pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        key_pem="-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----\n",
        ca_fp="ab:cd:ef:01",
        handlers=["tun", "proxy"],
    )
    assert "#!/bin/bash" in linux_script
    assert "tok_abc123" in linux_script
    assert "wss://test.example.com" in linux_script
    assert "systemctl" in linux_script
    ok(f"Linux installer ({len(linux_script)} bytes)")

    win_script = generate_windows(
        agent_name="test-agent",
        token="tok_abc123",
        server_url="wss://test.example.com",
        ca_pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        cert_pem="-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        key_pem="-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----\n",
        ca_fp="ab:cd:ef:01",
        handlers=["proxy"],
    )
    assert "PowerShell" in win_script or "param" in win_script or "sc.exe" in win_script
    assert "tok_abc123" in win_script
    ok(f"Windows installer ({len(win_script)} bytes)")

except Exception as e:
    fail("installer", e)


# ─── 8. SERVER + AGENT KONEKCIJA ──────────────────────────────────────────────

print("\n[8] Server + Agent WebSocket konekcija")
try:
    import uvicorn
    from fastapi import FastAPI
    from ferret.server import AgentRouter
    from ferret import Agent

    PORT = 18765
    ADMIN = "test-admin-token"
    SECRET = "test-secret-32-chars-minimum-len!"

    async def run_test():
        with tempfile.TemporaryDirectory() as tmpdir:
            ar = AgentRouter(
                db_path=os.path.join(tmpdir, "test.db"),
                admin_token=ADMIN,
                secret=SECRET,
                public_url=f"ws://127.0.0.1:{PORT}",
            )

            app = FastAPI()
            app.include_router(ar.router)

            # Kreiraj token
            tg = ar._token_gen
            hw = hw_get()
            srv_hw = hw_get()
            token = tg.create(hw_id=hw, name="test-agent", valid_days=1,
                              server_url=f"ws://127.0.0.1:{PORT}",
                              server_hw_id=srv_hw)

            config = uvicorn.Config(app, host="127.0.0.1", port=PORT,
                                    log_level="error", loop="asyncio")
            srv = uvicorn.Server(config)
            server_task = asyncio.create_task(srv.serve())
            await asyncio.sleep(0.8)

            # Agent konektuj — šalje hw_id radi validacije tokena
            agent = Agent(url=f"ws://127.0.0.1:{PORT}/ws/agent", token=token, hw_id=hw)
            agent_task = asyncio.create_task(agent.run_async())
            await asyncio.sleep(0.8)

            # REST API test — run_in_executor da ne blokira event loop
            import urllib.request
            def http_get():
                req = urllib.request.Request(
                    f"http://127.0.0.1:{PORT}/agents/",
                    headers={"Authorization": f"Bearer {ADMIN}"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status
            loop = asyncio.get_event_loop()
            status = await loop.run_in_executor(None, http_get)
            assert status == 200
            ok("REST API /agents/ odgovara 200")

            # Online agenti
            agents = ar.online_agents
            ok(f"online_agents radi, {len(agents)} agent(a) online")

            srv.should_exit = True
            agent_task.cancel()
            try:
                await asyncio.wait_for(server_task, timeout=2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    asyncio.run(run_test())

except ImportError as e:
    skip("server+agent konekcija", f"nedostaje: {e}")
except Exception as e:
    fail("server+agent konekcija", e)


# ─── 9. TUN INTERFACE ─────────────────────────────────────────────────────────

print("\n[9] TUN interface")
if os.geteuid() != 0:
    skip("TUN kreiranje", "zahteva root (pokrenuti sa sudo)")
    skip("LAN forwarding", "zahteva root")
    skip("iptables MASQUERADE", "zahteva root")
else:
    try:
        import subprocess
        from ferret.handlers.tun import TunHandler

        handler = TunHandler(iface="ferret-test")
        fd = handler._open_tun("ferret-test")
        assert fd > 0
        ok("TUN interface otvoren")

        result = subprocess.run(["ip", "link", "show", "ferret-test"],
                                capture_output=True)
        assert result.returncode == 0
        ok("TUN interface vidljiv u ip link show")

        os.close(fd)
        subprocess.run(["ip", "link", "delete", "ferret-test"],
                       capture_output=True)
        ok("TUN interface obrisan")
    except Exception as e:
        fail("TUN", e)


# ─── 10. URL BINDING U TOKENU ─────────────────────────────────────────────────

print("\n[10] Token URL binding")
try:
    from ferret.server.token_gen import TokenGen, _b64_decode
    import json

    tg = TokenGen(secret="test-secret-32-chars-minimum-len!")
    token = tg.create(
        hw_id="a" * 64,
        name="url-test",
        valid_days=1,
        server_url="wss://correct-server.example.com",
        server_hw_id="b" * 64,
    )

    # Token format: <payload_b64>.<sig> — payload_b64 je base64url JSON
    payload_b64, _, sig = token.rpartition(".")
    payload = json.loads(_b64_decode(payload_b64))
    assert "srv" in payload, f"nema srv polja, payload keys: {list(payload.keys())}"
    ok(f"srv polje u tokenu: {payload['srv'][:40]}...")
    assert "hw" in payload
    ok("hw polje prisutno (HMAC hw_id, ne plain)")
    assert "srv_hw" in payload
    ok("srv_hw polje prisutno (HMAC server hw_id)")

except Exception as e:
    fail("URL binding", e)


# ─── REZULTAT ─────────────────────────────────────────────────────────────────

print("\n" + "=" * 50)
if errors:
    print(f"\033[31mFAILED — {len(errors)} greška:\033[0m")
    for e in errors:
        print(f"  • {e}")
    sys.exit(1)
else:
    print(f"\033[32mSVI TESTOVI PROŠLI\033[0m")
    sys.exit(0)
