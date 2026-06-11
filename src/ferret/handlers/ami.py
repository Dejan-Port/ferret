"""
AMI handler — Asterisk Manager Interface.

Podržava:
  - stream_events: prati dolazne pozive i SMS događaje, prosleđuje portalu
  - handle_originate: inicira pozive prema lokalnom Asterisk-u
  - handle_query: proverava da li su PJSIP ekstenzije registrovane
"""
import asyncio
import logging
from typing import Callable, Awaitable

log = logging.getLogger("ferret.ami")


class AmiHandler:
    """
    Handler za Asterisk AMI konekciju.

    Upotreba:
        ami = AmiHandler(host="localhost", port=5038, user="admin", password="tajno", dongle="dongle0")
        ami.register(agent)

    Ili ručno:
        agent.register_handler("originate", ami.handle_originate, capability="ami")
        agent.register_handler("ami_query", ami.handle_query, capability="ami")
        agent.add_background(ami.stream_events)
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5038,
        user: str = "",
        password: str = "",
        dongle: str = "",
    ):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.dongle = dongle

    def register(self, agent):
        """Registruje sve AMI handler-e i pozadinski task na agentu."""
        agent.register_handler("originate", self.handle_originate, capability="ami")
        agent.register_handler("ami_query", self.handle_query,     capability="ami")
        agent.add_background(self.stream_events)

    # ── Streaming AMI događaja ────────────────────────────────────────────────

    async def stream_events(self, send: Callable[..., Awaitable]):
        """Pozadinski task: čita AMI i prosleđuje portalu ringing/hangup/DongleNewSMS."""
        while True:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=10
                )
                await reader.readline()  # AMI banner
                writer.write(
                    f"Action: Login\r\nUsername: {self.user}\r\nSecret: {self.password}\r\n\r\n"
                    .encode()
                )
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(2048), timeout=5)
                if b"Success" not in resp:
                    writer.close()
                    log.warning("AMI login neuspešan")
                    await asyncio.sleep(30)
                    continue

                log.info("AMI konektovan na %s:%d", self.host, self.port)
                buf = ""
                while True:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=120)
                    if not chunk:
                        break
                    buf += chunk.decode(errors="ignore")
                    while "\r\n\r\n" in buf:
                        block, buf = buf.split("\r\n\r\n", 1)
                        fields = {}
                        for line in block.split("\r\n"):
                            if ": " in line:
                                k, v = line.split(": ", 1)
                                fields[k] = v
                        await self._dispatch_event(fields, send)
                writer.close()

            except Exception as e:
                log.warning("AMI stream prekinut: %s", e)
                await asyncio.sleep(10)

    async def _dispatch_event(self, fields: dict, send):
        event = fields.get("Event", "")
        if event == "Newchannel":
            num = fields.get("CallerIDNum", "")
            ctx = fields.get("Context", "").lower()
            if num and len("".join(c for c in num if c.isdigit())) >= 6:
                if not any(x in ctx for x in ("internal", "local", "users", "default")):
                    log.info("Ringing: %s", num)
                    await send({"type": "ami_event", "event": "ringing", "caller": num})

        elif event == "Hangup":
            await send({"type": "ami_event", "event": "hangup"})

        elif event == "DongleNewSMS":
            number  = fields.get("From", "")
            message = fields.get("Message", "")
            if number and message:
                log.info("Dolazni SMS od %s", number)
                await send({"type": "ami_event", "event": "incoming_sms",
                            "number": number, "message": message})

    # ── Originate (iniciranje poziva) ─────────────────────────────────────────

    async def handle_originate(self, data: dict, send):
        """Portal šalje zahtev za pozivom; agent ga izvršava na lokalnom AMI."""
        req_id     = data.get("id")
        ami_host   = data.get("ami_host",   self.host)
        ami_port   = int(data.get("ami_port", self.port))
        ami_user   = data.get("ami_user",   self.user)
        ami_pass   = data.get("ami_pass",   self.password)
        ami_dongle = data.get("ami_dongle", self.dongle)
        sip_ext    = data.get("sip_ext",    "")
        destination = data.get("destination", "")
        caller_id  = data.get("caller_id",  destination)
        tech_ext   = data.get("tech_ext",   "")
        auto_answer = data.get("auto_answer", False)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ami_host, ami_port), timeout=10
            )
            await reader.readline()

            def _send_ami(fields):
                msg = "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n"
                writer.write(msg.encode())

            async def _read_ami():
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
                    if not chunk:
                        break
                    buf += chunk
                return buf.decode(errors="replace")

            _send_ami({"Action": "Login", "Username": ami_user, "Secret": ami_pass})
            await writer.drain()
            resp = await _read_ami()
            if "Success" not in resp:
                raise Exception("AMI login neuspešan")

            if tech_ext:
                dial_data = f"PJSIP/{tech_ext}"
                channel   = f"PJSIP/{sip_ext}"
            else:
                dial_data = f"Dongle/{ami_dongle}/{destination}"
                channel   = f"PJSIP/{sip_ext}"

            originate = {
                "Action":      "Originate",
                "Channel":     channel,
                "Application": "Dial",
                "Data":        dial_data,
                "Timeout":     "30000",
                "CallerID":    caller_id,
                "Async":       "true",
            }
            if auto_answer:
                originate["Variable"] = (
                    "PJSIP_HEADER(add,Call-Info)=<sip:servisniportal.rs>;answer-after=0"
                )

            _send_ami(originate)
            await writer.drain()
            resp = await _read_ami()
            _send_ami({"Action": "Logoff"})
            await writer.drain()
            writer.close()

            if "Error" in resp:
                err = resp.split("Message:")[-1].strip().split("\r")[0]
                raise Exception(err)

            log.info("Originate OK: %s → %s", sip_ext, destination)
            await send({"type": "originate_response", "id": req_id, "ok": True})

        except Exception as e:
            log.error("Originate greška: %s", e)
            await send({"type": "originate_response", "id": req_id, "ok": False, "error": str(e)})

    # ── ExtensionState query ──────────────────────────────────────────────────

    async def handle_query(self, data: dict, send):
        """Proverava da li su PJSIP ekstenzije registrovane na lokalnom Asterisk-u."""
        req_id     = data.get("id")
        extensions = data.get("extensions", [])
        ami_host   = data.get("ami_host",  self.host)
        ami_port   = int(data.get("ami_port", self.port))
        ami_user   = data.get("ami_user",  self.user)
        ami_pass   = data.get("ami_pass",  self.password)

        status = {}
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ami_host, ami_port), timeout=8
            )
            await reader.readline()

            def _send_ami(fields):
                msg = "".join(f"{k}: {v}\r\n" for k, v in fields.items()) + "\r\n"
                writer.write(msg.encode())

            async def _read_block():
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=5)
                    if not chunk:
                        break
                    buf += chunk
                return buf.decode(errors="replace")

            _send_ami({"Action": "Login", "Username": ami_user, "Secret": ami_pass})
            await writer.drain()
            await _read_block()

            for ext in extensions:
                _send_ami({"Action": "ExtensionState", "Exten": ext, "Context": "from-internal"})
                await writer.drain()
                resp = await _read_block()
                online = False
                for line in resp.split("\r\n"):
                    if line.startswith("Status:"):
                        val = line.split(":", 1)[1].strip()
                        online = val not in ("-1", "4")
                        break
                status[ext] = online

            _send_ami({"Action": "Logoff"})
            await writer.drain()
            writer.close()

        except Exception as e:
            log.warning("AMI query greška: %s", e)

        await send({"type": "ami_query_response", "id": req_id, "status": status})
