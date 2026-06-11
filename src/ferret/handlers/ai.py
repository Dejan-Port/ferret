"""
AI handler — lokalni Ollama model (vision/OCR).

Portal šalje sliku (base64) i prompt; handler poziva Ollamu i vraća odgovor.
"""
import asyncio
import json
import logging
import urllib.request
from typing import Callable, Awaitable

log = logging.getLogger("ferret.ai")


class AiHandler:
    """
    Handler za lokalni Ollama model.

    Upotreba:
        ai = AiHandler(
            ollama_url="http://localhost:11434",
            model="llava:7b-v1.6-mistral-q4_0",
        )
        ai.register(agent)
    """

    def __init__(
        self,
        ollama_url: str = "http://localhost:11434",
        model: str = "llava:7b-v1.6-mistral-q4_0",
    ):
        self._url   = ollama_url
        self._model = model

    def register(self, agent):
        """Registruje AI handler na agentu."""
        agent.register_handler("ai_request", self.handle_request, capability="ai")

    async def handle_request(self, data: dict, send: Callable[..., Awaitable]):
        req_id    = data.get("id")
        image_b64 = data.get("image")
        prompt    = data.get("prompt", "Izvuci sve numeričke vrednosti merenja sa slike. Vrati JSON.")

        try:
            body = json.dumps({
                "model":  self._model,
                "prompt": prompt,
                "images": [image_b64],
                "stream": False,
            }).encode()
            req = urllib.request.Request(
                f"{self._url}/api/generate",
                data=body,
                headers={"Content-Type": "application/json"},
            )
            loop = asyncio.get_running_loop()
            def _call():
                with urllib.request.urlopen(req, timeout=60) as r:
                    return json.loads(r.read())
            result = await loop.run_in_executor(None, _call)
            await send({"type": "ai_response", "id": req_id, "ok": True,
                        "result": result.get("response", "")})
            log.info("AI odgovor poslat za zahtev %s", req_id)

        except Exception as e:
            log.error("AI greška: %s", e)
            await send({"type": "ai_response", "id": req_id, "ok": False, "error": str(e)})
