import asyncio
from typing import Any

import aiohttp

from errors import FatalError, RateError, TempError


class Urlhaus:
    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key
        self.api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        self.session: aiohttp.ClientSession | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            headers = {"Auth-Key": self.api_key} if self.api_key else {}
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=25),
                headers=headers,
            )
        return self.session

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()

    async def check(self, url: str) -> dict[str, Any]:
        if not self.enabled:
            return {"engine": "urlhaus", "hit": False, "note": "disabled"}

        session = await self.get_session()

        try:
            async with session.post(self.api_url, data={"url": url}) as resp:
                if resp.status == 429:
                    raise RateError("URLhaus rate limit")
                if resp.status >= 500:
                    raise TempError(f"URLhaus server error {resp.status}")
                if resp.status >= 400:
                    raise FatalError(f"URLhaus error {resp.status}: {await resp.text()}")
                data = await resp.json()
        except asyncio.TimeoutError as err:
            raise TempError("URLhaus timeout") from err
        except aiohttp.ClientError as err:
            raise TempError(f"URLhaus network error: {err}") from err

        return {
            "engine": "urlhaus",
            "hit": str(data.get("query_status", "")).strip().lower() == "ok",
            "raw": data,
        }


class SafeBrowsing:
    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key
        self.api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.session: aiohttp.ClientSession | None = None

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=25)
            )
        return self.session

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()

    async def check(self, url: str) -> dict[str, Any]:
        if not self.enabled:
            return {"engine": "safebrowsing", "hit": False, "note": "disabled"}

        session = await self.get_session()
        payload = {
            "client": {
                "clientId": "tg-bot",
                "clientVersion": "1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with session.post(
                self.api_url,
                params={"key": self.api_key},
                json=payload,
            ) as resp:
                if resp.status == 429:
                    raise RateError("Safe Browsing rate limit")
                if resp.status >= 500:
                    raise TempError(f"Safe Browsing server error {resp.status}")
                if resp.status >= 400:
                    raise FatalError(f"Safe Browsing error {resp.status}: {await resp.text()}")
                data = await resp.json()
        except asyncio.TimeoutError as err:
            raise TempError("Safe Browsing timeout") from err
        except aiohttp.ClientError as err:
            raise TempError(f"Safe Browsing network error: {err}") from err

        return {
            "engine": "safebrowsing",
            "hit": bool(data.get("matches") or []),
            "raw": data,
        }
