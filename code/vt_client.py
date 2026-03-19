import asyncio
import base64
import time
from typing import Any

import aiohttp

import config
from errors import FatalError, RateError, TempError


class Vt:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session: aiohttp.ClientSession | None = None
        self.lock = asyncio.Lock()
        self.next_request_at = 0.0

    async def get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=120),
                headers={"x-apikey": self.api_key},
            )
        return self.session

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()

    async def wait_turn(self) -> None:
        async with self.lock:
            now = time.monotonic()
            delay = self.next_request_at - now
            if delay > 0:
                await asyncio.sleep(delay)
            self.next_request_at = time.monotonic() + float(config.app.vt_min_gap)

    async def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        await self.wait_turn()
        session = await self.get_session()
        url = f"{self.base_url}/{path.lstrip('/')}"

        try:
            async with session.request(method, url, **kwargs) as resp:
                if resp.status == 429:
                    raise RateError("VirusTotal rate limit")
                if resp.status >= 500:
                    raise TempError(f"VirusTotal server error {resp.status}")
                if resp.status >= 400:
                    raise FatalError(f"VirusTotal error {resp.status}: {await resp.text()}")
                return await resp.json()
        except asyncio.TimeoutError as err:
            raise TempError("VirusTotal timeout") from err
        except aiohttp.ClientError as err:
            raise TempError(f"VirusTotal network error: {err}") from err

    async def wait_report(self, analysis_id: str) -> dict[str, Any]:
        for _ in range(config.app.vt_wait_cycles):
            data = await self.request("GET", f"analyses/{analysis_id}")
            status = data.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
            await asyncio.sleep(config.app.vt_poll_delay)
        raise TempError("VirusTotal analysis timeout")

    async def scan_url(self, url: str) -> dict[str, Any]:
        sent = await self.request("POST", "urls", data={"url": url})
        analysis_id = sent.get("data", {}).get("id")
        await self.wait_report(analysis_id)

        vt_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return await self.request("GET", f"urls/{vt_id}")

    async def scan_file(self, file_bytes: bytes, file_name: str) -> dict[str, Any]:
        form = aiohttp.FormData()
        form.add_field("file", file_bytes, filename=file_name)

        sent = await self.request("POST", "files", data=form)
        analysis_id = sent.get("data", {}).get("id")
        return await self.wait_report(analysis_id)



def get_stats(data: dict[str, Any]) -> dict[str, int]:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("stats") or attrs.get("last_analysis_stats") or {}
    return {
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
    }



def make_verdict(data: dict[str, Any], *, is_url: bool) -> dict[str, Any]:
    stats = get_stats(data)
    attrs = data.get("data", {}).get("attributes", {})

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    bad_category = False

    if is_url:
        categories = attrs.get("categories", {}) or {}
        for value in categories.values():
            if str(value).strip().lower() in {"phishing", "malware", "scam", "fraud"}:
                bad_category = True
                break

    if malicious >= config.app.vt_bad_threshold or bad_category:
        level = "danger"
        label = "⚠️ Опасно"
    elif suspicious >= config.app.vt_warn_threshold:
        level = "warn"
        label = "Подозрительно"
    else:
        level = "safe"
        label = "✅ Чисто"

    return {
        "engine": "virustotal",
        "title": "VirusTotal",
        "level": level,
        "label": label,
        "stats": stats,
        "raw": data,
    }



def view(result: dict[str, Any]) -> str:
    stats = result["stats"]
    lines = [f"VirusTotal: {result['label']}"]
    lines.append(f"— вредоносных: {stats['malicious']}")
    lines.append(f"— подозрительных: {stats['suspicious']}")
    return "\n".join(lines)
