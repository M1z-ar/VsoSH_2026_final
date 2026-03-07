import asyncio
from typing import Any

import aiohttp

import settings
from exceptions import FatalError, RateError, TempError


class Hybrid:
    def __init__(self, key: str | None) -> None:
        self.key = key
        self.base = "https://hybrid-analysis.com/api/v2"
        self.sess: aiohttp.ClientSession | None = None

    @property
    def ok(self) -> bool:
        return bool(settings.app.hybrid_on and self.key)

    async def _sess(self) -> aiohttp.ClientSession:
        if self.sess is None or self.sess.closed:
            self.sess = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=settings.app.hybrid_wait),
                headers={
                    "api-key": self.key or "",
                    "User-Agent": settings.app.hybrid_ua,
                    "Accept": "application/json",
                },
            )
        return self.sess

    async def close(self) -> None:
        if self.sess and not self.sess.closed:
            await self.sess.close()

    async def _req(self, method: str, path: str, **kwargs: Any) -> Any:
        if not self.ok:
            raise FatalError("Hybrid Analysis disabled")

        sess = await self._sess()
        url = f"{self.base}/{path.lstrip('/')}"

        try:
            async with sess.request(method, url, **kwargs) as resp:
                text = await resp.text()

                if resp.status == 429:
                    raise RateError("Hybrid Analysis rate limit (429)")
                if resp.status in {401, 403}:
                    raise FatalError(f"Hybrid Analysis auth/perm error ({resp.status}): {text}")
                if resp.status >= 500:
                    raise TempError(f"Hybrid Analysis server error ({resp.status}): {text}")
                if resp.status >= 400:
                    raise FatalError(f"Hybrid Analysis request error ({resp.status}): {text}")

                ctype = resp.headers.get("Content-Type", "")
                if "application/json" in ctype:
                    try:
                        return await resp.json()
                    except Exception:
                        return text
                return text
        except asyncio.TimeoutError as e:
            raise TempError("Hybrid Analysis timeout") from e
        except aiohttp.ClientError as e:
            raise TempError(f"Hybrid Analysis network error: {e}") from e

    async def _wait(self, report_id: str) -> dict[str, Any]:
        for _ in range(settings.app.hybrid_tries):
            data = await self._req("GET", f"report/{report_id}/state")
            state = str(data.get("state", "")).strip().lower()

            if state in {"success", "finished", "done"}:
                return data

            if state in {"error", "failed"}:
                raise TempError(f"Hybrid Analysis state error: {data}")

            await asyncio.sleep(settings.app.hybrid_sleep)

        raise TempError("Hybrid Analysis analysis timeout")

    async def scan_url(self, url: str) -> dict[str, Any]:
        payload = {
            "url": url,
            "environment_id": str(settings.app.hybrid_env),
        }
        sent = await self._req("POST", "submit/url", data=payload)

        report_id = sent.get("job_id") or sent.get("submission_id")
        if not report_id:
            raise FatalError(f"Hybrid Analysis submit/url unexpected response: {sent}")

        await self._wait(str(report_id))
        summary = await self._req("GET", f"report/{report_id}/summary")

        return {
            "submit": sent,
            "state": "success",
            "summary": summary,
        }

    async def scan_file(self, body: bytes, file_name: str) -> dict[str, Any]:
        form = aiohttp.FormData()
        form.add_field("file", body, filename=file_name)
        form.add_field("environment_id", str(settings.app.hybrid_env))

        sent = await self._req("POST", "submit/file", data=form)

        report_id = sent.get("job_id") or sent.get("submission_id")
        if not report_id:
            raise FatalError(f"Hybrid Analysis submit/file unexpected response: {sent}")

        await self._wait(str(report_id))
        summary = await self._req("GET", f"report/{report_id}/summary")

        return {
            "submit": sent,
            "state": "success",
            "summary": summary,
        }


def make_verdict(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("summary", {}) or {}
    state = str(summary.get("state", "")).strip()
    tags = summary.get("tags") or []
    ml = summary.get("machine_learning_models") or []
    verdict = str(summary.get("verdict", "")).strip().lower()
    threat_level = summary.get("threat_level")
    threat_score = summary.get("threat_score")

    level = "unknown"
    label = "ℹ️ Нет чёткого вердикта"

    pool: list[str] = []

    for item in tags:
        if isinstance(item, dict):
            pool.extend([str(v) for v in item.values() if v is not None])
        else:
            pool.append(str(item))

    for item in ml:
        if isinstance(item, dict):
            pool.extend([str(v) for v in item.values() if v is not None])
        else:
            pool.append(str(item))

    pool.append(verdict)
    if threat_level is not None:
        pool.append(str(threat_level))
    if threat_score is not None:
        pool.append(str(threat_score))

    hay = " | ".join(pool).lower()

    if any(x in hay for x in ("malicious", "trojan", "ransom", "phishing", "stealer")):
        level = "danger"
        label = "⚠️ Опасно"
    elif "suspicious" in hay:
        level = "suspicious"
        label = "❓ Подозрительно"
    elif state.lower() in {"success", "finished", "done"}:
        level = "safe"
        label = "✅ Явных угроз не найдено"

    return {
        "engine": "hybrid",
        "title": "Hybrid Analysis",
        "level": level,
        "label": label,
        "state": summary.get("state"),
        "tags": tags,
        "ml": ml,
        "verdict": summary.get("verdict"),
        "threat_level": summary.get("threat_level"),
        "threat_score": summary.get("threat_score"),
        "raw": data,
    }


def view(result: dict[str, Any]) -> str:
    rows = [f"🧪 **Hybrid Analysis:** {result['label']}"]

    if result.get("state"):
        state = str(result["state"]).strip().lower()
        if state == "success":
            state = "завершён"
        elif state == "failed":
            state = "ошибка"
        elif state == "error":
            state = "ошибка"
        rows.append(f"• статус анализа: {state}")

    if result.get("verdict") is not None:
        verdict = str(result["verdict"]).strip().lower()
        if verdict == "malicious":
            verdict = "вредоносный файл"
        elif verdict == "suspicious":
            verdict = "подозрительный файл"
        elif verdict == "no specific threat":
            verdict = "явных угроз не обнаружено"
        rows.append(f"• вердикт: {verdict}")

    if result.get("threat_level") is not None:
        level = result["threat_level"]
        if str(level) == "0":
            level_text = "нет угрозы"
        elif str(level) == "1":
            level_text = "низкий"
        elif str(level) == "2":
            level_text = "высокий"
        else:
            level_text = str(level)
        rows.append(f"• уровень угрозы: {level_text}")

    if result.get("threat_score") is not None:
        rows.append(f"• оценка угрозы: {result['threat_score']} из 100")

    tags = result.get("tags") or []
    if tags:
        plain = []
        for item in tags[:5]:
            if isinstance(item, dict):
                plain.extend([str(v) for v in item.values() if v is not None])
            else:
                plain.append(str(item))
        if plain:
            rows.append(f"• признаки: {', '.join(plain[:5])}")

    ml = result.get("ml") or []
    if ml:
        plain_ml = []
        for item in ml[:3]:
            if isinstance(item, dict):
                plain_ml.extend([str(v) for v in item.values() if v is not None])
            else:
                plain_ml.append(str(item))
        if plain_ml:
            rows.append(f"• модели ИИ: {', '.join(plain_ml[:3])}")

    return "\n".join(rows)