import asyncio
from typing import Any

import aiohttp

import config
from errors import FatalError, RateError, TempError


class Hybrid:
    def __init__(self, api_key: str | None) -> None:
        self.api_key = api_key
        self.base_url = "https://hybrid-analysis.com/api/v2"
        self.session: aiohttp.ClientSession | None = None

    @property
    def ok(self) -> bool:
        return bool(config.app.hybrid_enabled and self.api_key)

    async def get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=config.app.hybrid_timeout),
                headers={
                    "api-key": self.api_key or "",
                    "User-Agent": config.app.hybrid_user_agent,
                    "Accept": "application/json",
                },
            )
        return self.session

    async def close(self) -> None:
        if self.session and not self.session.closed:
            await self.session.close()

    async def request(self, method: str, path: str, **kwargs: Any) -> Any:
        if not self.ok:
            raise FatalError("Hybrid disabled")

        session = await self.get_session()
        url = f"{self.base_url}/{path.lstrip('/')}"

        try:
            async with session.request(method, url, **kwargs) as resp:
                text = await resp.text()

                if resp.status == 429:
                    raise RateError("Hybrid Analysis rate limit")
                if resp.status in {401, 403}:
                    raise FatalError(f"Hybrid Analysis auth error {resp.status}: {text}")
                if resp.status >= 500:
                    raise TempError(f"Hybrid Analysis server error {resp.status}: {text}")
                if resp.status >= 400:
                    raise FatalError(f"Hybrid Analysis request error {resp.status}: {text}")

                if "application/json" in resp.headers.get("Content-Type", ""):
                    return await resp.json()
                return text
        except asyncio.TimeoutError as err:
            raise TempError("Hybrid Analysis timeout") from err
        except aiohttp.ClientError as err:
            raise TempError(f"Hybrid Analysis network error: {err}") from err

    async def wait_report(self, report_id: str) -> None:
        for _ in range(config.app.hybrid_wait_cycles):
            data = await self.request("GET", f"report/{report_id}/state")
            state = str(data.get("state", "")).strip().lower()

            if state in {"success", "finished", "done"}:
                return
            if state in {"error", "failed"}:
                raise TempError(f"Hybrid Analysis state error: {data}")

            await asyncio.sleep(config.app.hybrid_poll_delay)

        raise TempError("Hybrid Analysis analysis timeout")

    async def scan_url(self, url: str) -> dict[str, Any]:
        payload = {
            "url": url,
            "environment_id": str(config.app.hybrid_env_id),
        }
        sent = await self.request("POST", "submit/url", data=payload)

        report_id = sent.get("job_id") or sent.get("submission_id")
        if not report_id:
            raise FatalError(f"Hybrid Analysis submit/url unexpected response: {sent}")

        await self.wait_report(str(report_id))
        summary = await self.request("GET", f"report/{report_id}/summary")

        return {"summary": summary}

    async def scan_file(self, file_bytes: bytes, file_name: str) -> dict[str, Any]:
        form = aiohttp.FormData()
        form.add_field("file", file_bytes, filename=file_name)
        form.add_field("environment_id", str(config.app.hybrid_env_id))

        sent = await self.request("POST", "submit/file", data=form)

        report_id = sent.get("job_id") or sent.get("submission_id")
        if not report_id:
            raise FatalError(f"Hybrid Analysis submit/file unexpected response: {sent}")

        await self.wait_report(str(report_id))
        summary = await self.request("GET", f"report/{report_id}/summary")

        return {"summary": summary}



def make_verdict(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("summary", {}) or {}
    verdict = str(summary.get("verdict", "")).strip().lower()
    threat_level = summary.get("threat_level")
    threat_score = summary.get("threat_score")
    tags = summary.get("tags") or []
    ml = summary.get("machine_learning_models") or []

    words: list[str] = []

    for item in tags:
        if isinstance(item, dict):
            words.extend(str(v) for v in item.values() if v is not None)
        else:
            words.append(str(item))

    for item in ml:
        if isinstance(item, dict):
            words.extend(str(v) for v in item.values() if v is not None)
        else:
            words.append(str(item))

    words.append(verdict)
    if threat_level is not None:
        words.append(str(threat_level))
    if threat_score is not None:
        words.append(str(threat_score))

    text = " | ".join(words).lower()

    if any(word in text for word in ("malicious", "trojan", "ransom", "phishing", "stealer")):
        level = "danger"
        label = "⚠️ Опасно"
    elif "suspicious" in text:
        level = "warn"
        label = "Подозрительно"
    else:
        level = "safe"
        label = "✅ Безопасно"

    return {
        "engine": "hybrid",
        "title": "Hybrid Analysis",
        "level": level,
        "label": label,
        "verdict": summary.get("verdict"),
        "threat_level": threat_level,
        "threat_score": threat_score,
        "tags": tags,
        "raw": data,
    }



def view(result: dict[str, Any]) -> str:
    lines = [f"Hybrid Analysis: {result['label']}"]

    if result.get("verdict") is not None:
        lines.append(f"— вердикт: {result['verdict']}")

    if result.get("threat_level") is not None:
        lines.append(f"— уровень угрозы: {result['threat_level']}")

    if result.get("threat_score") is not None:
        lines.append(f"— оценка: {result['threat_score']} из 100")

    tags = result.get("tags") or []
    flat_tags: list[str] = []
    for item in tags[:5]:
        if isinstance(item, dict):
            flat_tags.extend(str(v) for v in item.values() if v is not None)
        else:
            flat_tags.append(str(item))

    if flat_tags:
        lines.append(f"— признаки: {', '.join(flat_tags[:5])}")

    return "\n".join(lines)
