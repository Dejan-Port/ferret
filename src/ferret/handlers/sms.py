"""
SMS handler — GSM dongle putem Asterisk AMI.

Funkcionalnosti:
  - Slanje SMS-a prema broju (DongleSendSMS)
  - Praćenje dolaznih poruka iz log fajla (sms.txt)
  - In-memory istorija poslatih i primljenih poruka
  - Lookup naziva kontakta (cache + portal API + statički rečnik)
  - Opcioni Web UI (localhost HTTP) za pregled i slanje SMS-a

Zavisnosti od AmiHandler-a: koristi iste AMI konekcione parametre za slanje.
"""
import asyncio
import collections
import json
import logging
import os
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Callable, Awaitable

log = logging.getLogger("ferret.sms")

# Poznati alfanumerički sender ID-ovi (dopunjuju se iz known_senders argumenta)
_DEFAULT_KNOWN_SENDERS = {
    "DEXPRESS":  "D Express",
    "D-EXPRESS": "D Express",
    "DEXPR":     "D Express",
    "DIGIPRO":   "DigiPro",
    "POSTA":     "Pošta Srbije",
    "POSTASRB":  "Pošta Srbije",
    "BEXPRESS":  "BEX Express",
    "CITYEXPR":  "City Express",
    "AKS":       "AKS Express",
    "GLOVO":     "Glovo",
}


class SmsHandler:
    """
    Handler za SMS putem Asterisk GSM dongle-a.

    Upotreba:
        sms = SmsHandler(
            ami_host="localhost", ami_port=5038,
            ami_user="admin", ami_password="tajno",
            ami_dongle="dongle0",
            incoming_log="/var/log/asterisk/sms.txt",
            sent_log="/opt/agent/sent.txt",
            portal_url="wss://portal.rs/ws/agent",
            portal_token="xxx",
        )
        sms.register(agent)

    Opcioni Web UI:
        sms = SmsHandler(..., web_enabled=True, web_port=7000)
    """

    def __init__(
        self,
        ami_host: str = "localhost",
        ami_port: int = 5038,
        ami_user: str = "",
        ami_password: str = "",
        ami_dongle: str = "",
        incoming_log: str = "/var/log/asterisk/sms.txt",
        sent_log: str = "",
        portal_url: str = "",
        portal_token: str = "",
        known_senders: dict = None,
        web_enabled: bool = False,
        web_port: int = 7000,
    ):
        self._ami_host     = ami_host
        self._ami_port     = ami_port
        self._ami_user     = ami_user
        self._ami_password = ami_password
        self._ami_dongle   = ami_dongle
        self._incoming_log = incoming_log
        self._sent_log     = sent_log or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "sent.txt"
        )
        self._portal_url   = portal_url
        self._portal_token = portal_token
        self._web_enabled  = web_enabled
        self._web_port     = web_port

        self._log: collections.deque = collections.deque(maxlen=5000)
        self._name_cache: dict = {}
        self._known_senders = {**_DEFAULT_KNOWN_SENDERS, **(known_senders or {})}

    def register(self, agent):
        """Registruje SMS handler i pozadinske taskove na agentu."""
        agent.register_handler("sms", self.handle_send, capability="sms")
        agent.add_background(self._watch_incoming)
        if self._web_enabled:
            agent.add_background(self._web_server)
        self._load_history()

    # ── Slanje SMS-a ──────────────────────────────────────────────────────────

    async def handle_send(self, data: dict, send: Callable[..., Awaitable]):
        req_id  = data.get("id")
        number  = data.get("number", "")
        message = data.get("message", "")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._ami_host, self._ami_port), timeout=10
            )
            await reader.readline()

            def _send_ami(fields):
                writer.write(
                    ("".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n").encode()
                )

            async def _read_ami():
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
                    if not chunk:
                        break
                    buf += chunk
                return buf.decode(errors="replace")

            _send_ami({"Action": "Login", "Username": self._ami_user, "Secret": self._ami_password})
            await writer.drain()
            resp = await _read_ami()
            if "Success" not in resp:
                raise Exception("AMI login neuspešan")

            _send_ami({"Action": "DongleSendSMS", "Device": self._ami_dongle,
                       "Number": number, "Message": message})
            await writer.drain()
            await asyncio.sleep(1)
            resp = await asyncio.wait_for(reader.read(2048), timeout=5)

            _send_ami({"Action": "Logoff"})
            await writer.drain()
            writer.close()

            ok = b"Success" in resp or b"queued" in resp.lower()
            log.info("SMS %s: %s", "poslat" if ok else "greška", number)
            if ok:
                name = self._name_cache.get(number) or await self._lookup_name(number)
                self._add(number, message, "out", name)
                self._append_sent(number, message)
            await send({"type": "sms_response", "id": req_id, "ok": ok})

        except Exception as e:
            log.error("SMS greška: %s", e)
            await send({"type": "sms_response", "id": req_id, "ok": False, "error": str(e)})

    # ── Praćenje dolaznih ─────────────────────────────────────────────────────

    async def _watch_incoming(self, send: Callable[..., Awaitable]):
        if not os.path.exists(self._incoming_log):
            log.info("incoming_log ne postoji: %s", self._incoming_log)
            return
        try:
            pos = os.path.getsize(self._incoming_log)
        except Exception:
            pos = 0
        while True:
            await asyncio.sleep(5)
            try:
                size = os.path.getsize(self._incoming_log)
                if size <= pos:
                    continue
                with open(self._incoming_log, "r", encoding="utf-8") as f:
                    f.seek(pos)
                    new_lines = f.read().splitlines()
                pos = size
                for entry in self._parse_lines(new_lines, "in"):
                    name = await self._lookup_name(entry["number"])
                    entry["name"] = name
                    self._log.append(entry)
                    log.info("Novi SMS od %s", entry["number"])
                    await send({
                        "type":    "ami_event",
                        "event":   "incoming_sms",
                        "number":  entry["number"],
                        "message": entry["body"],
                    })
            except Exception as e:
                log.warning("sms.txt watcher greška: %s", e)

    # ── Učitavanje istorije pri startu ────────────────────────────────────────

    def _load_history(self):
        for path, direction in [(self._incoming_log, "in"), (self._sent_log, "out")]:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    lines = f.read().strip().splitlines()
                for entry in self._parse_lines(lines, direction):
                    self._log.append(entry)
                log.info("Učitano %d poruka iz %s", len(lines), path)
            except Exception as e:
                log.warning("Nije moguće čitati %s: %s", path, e)

    def _parse_lines(self, lines: list, direction: str) -> list:
        result = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                parts = line.split(" - ", 2)
                if len(parts) < 3:
                    continue
                ts   = parts[0].strip()
                rest = parts[2].strip()
                number, _, body = rest.partition(": ")
                result.append({
                    "dir":    direction,
                    "number": number.strip(),
                    "name":   self._name_cache.get(number.strip(), number.strip()),
                    "body":   body.strip(),
                    "ts":     ts,
                })
            except Exception:
                continue
        return result

    def _add(self, number: str, body: str, direction: str, name: str = ""):
        self._log.append({
            "dir":    direction,
            "number": number,
            "name":   name or number,
            "body":   body,
            "ts":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    def _append_sent(self, number: str, message: str):
        try:
            ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"{ts} - {self._ami_dongle} - {number}: {message}\n"
            with open(self._sent_log, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            log.warning("Nije moguće upisati u sent.txt: %s", e)

    # ── Lookup naziva kontakta ────────────────────────────────────────────────

    async def _lookup_name(self, number: str) -> str:
        if number in self._name_cache:
            return self._name_cache[number]
        known = self._known_senders.get(number.upper())
        if known:
            self._name_cache[number] = known
            return known
        digits_only = "".join(c for c in number if c.isdigit())
        if len(digits_only) < 6:
            return number
        if not self._portal_token or not self._portal_url:
            return number
        try:
            base = self._portal_url.replace("wss://", "https://").replace("ws://", "http://")
            base = base.split("/ws/")[0]
            url = (
                f"{base}/api/agent/kontakt"
                f"?tel={urllib.parse.quote(number)}&token={self._portal_token}"
            )
            loop = asyncio.get_running_loop()
            def _fetch():
                with urllib.request.urlopen(url, timeout=5) as r:
                    return json.loads(r.read())
            data = await loop.run_in_executor(None, _fetch)
            if data.get("found"):
                name = (data.get("naziv") or "").strip() or number
                self._name_cache[number] = name
                return name
        except Exception as e:
            log.warning("Kontakt lookup greška za %s: %s", number, e)
        return number

    # ── Web SMS UI (opciono) ──────────────────────────────────────────────────

    async def _web_server(self, send: Callable[..., Awaitable]):
        server = await asyncio.start_server(
            lambda r, w: self._http_handler(r, w, send), "0.0.0.0", self._web_port
        )
        log.info("Web SMS UI: http://localhost:%d", self._web_port)
        async with server:
            await server.serve_forever()

    async def _http_handler(self, reader, writer, send):
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
                if not chunk:
                    break
                raw += chunk

            text = raw.decode(errors="replace")
            head, _, body_raw = text.partition("\r\n\r\n")
            req_line  = head.split("\r\n")[0]
            parts     = req_line.split(" ")
            method    = parts[0] if parts else "GET"
            full_path = parts[1] if len(parts) > 1 else "/"
            path, _, qs = full_path.partition("?")

            params = {}
            for kv in qs.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)

            content_length = 0
            for line in head.split("\r\n")[1:]:
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
            if method == "POST" and content_length > 0:
                body_bytes = body_raw.encode()
                while len(body_bytes) < content_length:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
                    if not chunk:
                        break
                    body_bytes += chunk
                body_raw = body_bytes.decode(errors="replace")

            status = 200
            content_type = "application/json"
            resp_body = b""

            if path in ("/", "/index.html"):
                from ferret.handlers._sms_web_ui import render_html
                resp_body    = render_html(self._ami_dongle).encode("utf-8")
                content_type = "text/html; charset=utf-8"

            elif method == "GET" and path == "/api/sms":
                entries = [
                    {**e, "name": self._name_cache.get(e["number"], e["name"])}
                    for e in self._log
                ]
                resp_body = json.dumps(entries).encode()

            elif method == "POST" and path == "/api/sms/send":
                try:
                    data = json.loads(body_raw)
                    number  = data.get("number", "").strip()
                    message = data.get("message", "").strip()
                    if not number or not message:
                        raise ValueError("Broj i poruka su obavezni")
                    result = {}
                    async def _capture(r):
                        result.update(r)
                    await self.handle_send(
                        {"number": number, "message": message, "id": "web"}, _capture
                    )
                    if result.get("ok"):
                        self._name_cache[number] = await self._lookup_name(number)
                        resp_body = json.dumps({"ok": True}).encode()
                    else:
                        resp_body = json.dumps(
                            {"ok": False, "error": result.get("error", "Greška")}
                        ).encode()
                except Exception as e:
                    status    = 400
                    resp_body = json.dumps({"ok": False, "error": str(e)}).encode()

            elif method == "GET" and path == "/api/contacts":
                tel  = params.get("tel", "")
                name = await self._lookup_name(tel) if tel else ""
                resp_body = json.dumps({"name": name}).encode()

            elif method == "GET" and path == "/api/debug":
                resp_body = json.dumps({
                    "sms_count":   len(self._log),
                    "cache_count": len(self._name_cache),
                    "cache_sample": dict(list(self._name_cache.items())[:5]),
                    "sms_sample":  list(self._log)[-3:],
                }).encode()

            else:
                status    = 404
                resp_body = b'{"error":"Not found"}'

            response = (
                f"HTTP/1.1 {status} OK\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(resp_body)}\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + resp_body
            writer.write(response)
            await writer.drain()

        except Exception as e:
            log.debug("HTTP handler greška: %s", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass
