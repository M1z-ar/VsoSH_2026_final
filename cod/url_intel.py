import asyncio
from typing import Any

import aiohttp

from exceptions import FatalError, RateError, TempError


class Urlhaus:
    def __init__(self, key: str | None) -> None:
        self.key = key
        self.api = "https://urlhaus-api.abuse.ch/v1/url/"
        self._s: aiohttp.ClientSession | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    async def _sess(self) -> aiohttp.ClientSession:
        if self._s is None or self._s.closed:
            self._s = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=25),
                headers={"Auth-Key": self.key or ""},
            )
        return self._s

    async def close(self) -> None:
        if self._s and not self._s.closed:
            await self._s.close()

    async def check(self, url: str) -> dict[str, Any]:
        if not self.enabled:
            return {"engine": "urlhaus", "hit": False, "note": "disabled"}

        s = await self._sess()
        try:
            async with s.post(self.api, data={"url": url}) as resp:
                if resp.status == 429:
                    raise RateError("URLhaus rate limit")
                if resp.status >= 500:
                    raise TempError(f"URLhaus server error {resp.status}")
                if resp.status >= 400:
                    raise FatalError(f"URLhaus error {resp.status}: {await resp.text()}")
                data = await resp.json()

            status = str(data.get("query_status", "")).lower()
            return {"engine": "urlhaus", "hit": status == "ok", "raw": data}
        except asyncio.TimeoutError as e:
            raise TempError("URLhaus timeout") from e
        except aiohttp.ClientError as e:
            raise TempError(f"URLhaus network error: {e}") from e


class SafeBrowsing:
    def __init__(self, key: str | None) -> None:
        self.key = key
        self.api = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self._s: aiohttp.ClientSession | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.key)

    async def _sess(self) -> aiohttp.ClientSession:
        if self._s is None or self._s.closed:
            self._s = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=25))
        return self._s

    async def close(self) -> None:
        if self._s and not self._s.closed:
            await self._s.close()

    async def check(self, url: str) -> dict[str, Any]:
        if not self.enabled:
            return {"engine": "safebrowsing", "hit": False, "note": "disabled"}

        s = await self._sess()
        payload = {
            "client": {"clientId": "tg-bot", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with s.post(self.api, params={"key": self.key}, json=payload) as resp:
                if resp.status == 429:
                    raise RateError("Safe Browsing rate limit")
                if resp.status >= 500:
                    raise TempError(f"Safe Browsing server error {resp.status}")
                if resp.status >= 400:
                    raise FatalError(f"Safe Browsing error {resp.status}: {await resp.text()}")
                data = await resp.json()

            matches = data.get("matches") or []
            return {"engine": "safebrowsing", "hit": bool(matches), "raw": data}
        except asyncio.TimeoutError as e:
            raise TempError("Safe Browsing timeout") from e
        except aiohttp.ClientError as e:
            raise TempError(f"Safe Browsing network error: {e}") from e


def format_hit_line(results: list[dict[str, Any]]) -> str | None:
    hits = [r["engine"] for r in results if r.get("hit")]
    if not hits:
        return None
    return f"🧷 **База угроз:** найдено совпадение ({', '.join(hits)})"