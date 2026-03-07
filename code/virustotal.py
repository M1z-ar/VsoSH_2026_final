import asyncio
import base64
import time
from typing import Any

import aiohttp

import settings
from exceptions import FatalError, RateError, TempError


class Vt:
    def __init__(self, key: str) -> None:
        self.key = key
        self.base = "https://www.virustotal.com/api/v3"
        self.sess: aiohttp.ClientSession | None = None
        self._lock = asyncio.Lock()
        self._next = 0.0
        self._gap = float(settings.app.vt_min_gap)

    async def _sess(self) -> aiohttp.ClientSession:
        if self.sess is None or self.sess.closed:
            self.sess = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120),
                headers={"x-apikey": self.key},
            )
        return self.sess

    async def close(self) -> None:
        if self.sess and not self.sess.closed:
            await self.sess.close()

    async def _pace(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._next = time.monotonic() + self._gap

    async def _req(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        await self._pace()

        sess = await self._sess()
        url = f"{self.base}/{path.lstrip('/')}"

        try:
            async with sess.request(method, url, **kwargs) as resp:
                if resp.status == 429:
                    raise RateError("VirusTotal rate limit")
                if resp.status >= 500:
                    raise TempError(f"VirusTotal server error {resp.status}: {await resp.text()}")
                if resp.status >= 400:
                    raise FatalError(f"VirusTotal error {resp.status}: {await resp.text()}")
                return await resp.json()
        except asyncio.TimeoutError as e:
            raise TempError("VirusTotal timeout") from e
        except aiohttp.ClientError as e:
            raise TempError(f"VirusTotal network error: {e}") from e

    async def _done(self, scan_id: str) -> dict[str, Any]:
        for _ in range(settings.app.vt_tries):
            data = await self._req("GET", f"analyses/{scan_id}")
            state = data.get("data", {}).get("attributes", {}).get("status")
            if state == "completed":
                return data
            await asyncio.sleep(settings.app.vt_sleep)
        raise TempError("VirusTotal analysis timeout")

    async def scan_url(self, url: str) -> dict[str, Any]:
        sent = await self._req("POST", "urls", data={"url": url})
        scan_id = sent.get("data", {}).get("id")
        await self._done(scan_id)

        vt_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return await self._req("GET", f"urls/{vt_id}")

    async def scan_file(self, body: bytes, file_name: str) -> dict[str, Any]:
        form = aiohttp.FormData()
        form.add_field("file", body, filename=file_name)

        sent = await self._req("POST", "files", data=form)
        scan_id = sent.get("data", {}).get("id")
        return await self._done(scan_id)


def get_stats(data: dict[str, Any]) -> dict[str, int]:
    attrs = data.get("data", {}).get("attributes", {})
    numbers = attrs.get("stats") or attrs.get("last_analysis_stats") or {}
    return {
        "malicious": int(numbers.get("malicious", 0) or 0),
        "suspicious": int(numbers.get("suspicious", 0) or 0),
        "harmless": int(numbers.get("harmless", 0) or 0),
        "undetected": int(numbers.get("undetected", 0) or 0),
    }


def make_verdict(data: dict[str, Any], *, is_url: bool) -> dict[str, Any]:
    stats = get_stats(data)
    attrs = data.get("data", {}).get("attributes", {})

    bad = stats["malicious"]
    warn = stats["suspicious"]

    cat_hit = False
    if is_url:
        cats = attrs.get("categories", {}) or {}
        for item in cats.values():
            if str(item).strip().lower() in {"phishing", "malware", "scam", "fraud"}:
                cat_hit = True
                break

    if bad >= settings.app.vt_bad or cat_hit:
        level = "danger"
        label = "⚠️ Опасно"
    elif warn >= settings.app.vt_warn:
        level = "suspicious"
        label = "❓ Подозрительно"
    else:
        level = "safe"
        label = "✅ Безопасно"

    return {
        "engine": "virustotal",
        "title": "VirusTotal",
        "level": level,
        "label": label,
        "stats": stats,
        "raw": data,
    }


def view(result: dict[str, Any]) -> str:
    s = result["stats"]
    return (
        f"🛡 **Вердикт VirusTotal:** {result['label']}\n\n"
        f"Результаты анализа:\n"
        f"🔴 вредоносных: {s['malicious']}\n"
        f"🟡 подозрительных: {s['suspicious']}\n"
    )
