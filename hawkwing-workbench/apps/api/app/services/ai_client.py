from dataclasses import dataclass
from datetime import datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import AISettings


PROVIDER_DEFAULTS = {
    "openai": {
        "label": "OpenAI",
        "api_base": "https://api.openai.com/v1",
        "model": "gpt-4.1-mini",
        "compatible": "openai",
    },
    "claude": {
        "label": "Claude",
        "api_base": "https://api.anthropic.com/v1",
        "model": "claude-3-5-sonnet-latest",
        "compatible": "anthropic",
    },
    "deepseek": {
        "label": "DeepSeek",
        "api_base": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
        "compatible": "openai",
    },
    "custom": {
        "label": "Custom",
        "api_base": "",
        "model": "gpt-4.1-mini",
        "compatible": "openai",
    },
}

_READY_CACHE: dict[str, dict] = {}


@dataclass
class RuntimeAIConfig:
    provider: str
    api_base: str
    api_key: str
    model: str
    source: str


def normalize_provider(provider: str) -> str:
    value = (provider or "openai").strip().lower()
    return value if value in PROVIDER_DEFAULTS else "custom"


def resolve_ai_config(db: Session | None = None) -> RuntimeAIConfig:
    settings = get_settings()
    stored = db.get(AISettings, 1) if db else None
    provider = normalize_provider(stored.provider if stored else settings.ai_provider)
    defaults = PROVIDER_DEFAULTS[provider]
    api_base = (stored.api_base if stored else settings.ai_api_base) or defaults["api_base"]
    api_key = (stored.api_key if stored else settings.ai_api_key) or ""
    model = (stored.model if stored else settings.ai_model) or defaults["model"]
    return RuntimeAIConfig(provider=provider, api_base=api_base, api_key=api_key, model=model, source="database" if stored else "environment")


def upsert_ai_config(db: Session, provider: str, api_base: str, api_key: str, model: str) -> RuntimeAIConfig:
    provider = normalize_provider(provider)
    defaults = PROVIDER_DEFAULTS[provider]
    stored = db.get(AISettings, 1)
    if not stored:
        stored = AISettings(id=1)
        db.add(stored)
    stored.provider = provider
    stored.api_base = (api_base or defaults["api_base"]).strip()
    if api_key and not api_key.startswith("********"):
        stored.api_key = api_key.strip()
    stored.model = (model or defaults["model"]).strip()
    stored.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(stored)
    return resolve_ai_config(db)


def public_ai_config(config: RuntimeAIConfig) -> dict:
    defaults = PROVIDER_DEFAULTS[config.provider]
    return {
        "provider": config.provider,
        "provider_label": defaults["label"],
        "providers": PROVIDER_DEFAULTS,
        "api_base": config.api_base,
        "api_base_configured": bool(config.api_base),
        "api_key_configured": bool(config.api_key),
        "api_key_masked": "********" + config.api_key[-4:] if config.api_key else "",
        "model": config.model,
        "source": config.source,
    }


class AIClient:
    def __init__(self, db: Session | None = None) -> None:
        self.settings = get_settings()
        self.config = resolve_ai_config(db)

    async def chat(self, prompt: str, system: str = "你是网络攻防演练报告助手。") -> str:
        if not self.config.api_key:
            return "AI API 未配置。请在页面右上角 AI 配置中填写 API Key，或在 deploy/.env 中设置 AI_API_KEY。"

        provider_meta = PROVIDER_DEFAULTS[self.config.provider]
        if provider_meta["compatible"] == "anthropic":
            return await self._chat_anthropic(prompt, system)
        return await self._chat_openai_compatible(prompt, system)

    async def _chat_openai_compatible(self, prompt: str, system: str) -> str:
        if not self.config.api_base:
            return "AI Base URL 未配置。自定义供应商需要填写 OpenAI-compatible Base URL。"

        url = self.config.api_base.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.settings.ai_timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def _chat_anthropic(self, prompt: str, system: str) -> str:
        url = self.config.api_base.rstrip("/") + "/messages"
        payload = {
            "model": self.config.model,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048,
            "temperature": 0.2,
        }
        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.settings.ai_timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            parts = data.get("content", [])
            return "\n".join(part.get("text", "") for part in parts if part.get("type") == "text")


async def check_ai_ready(db: Session | None = None) -> dict:
    config = resolve_ai_config(db)
    cache_key = f"{config.provider}:{config.api_base}:{config.model}:{bool(config.api_key)}"
    cached = _READY_CACHE.get(cache_key)
    if cached and datetime.utcnow() - cached["checked_at"] < timedelta(seconds=60):
        return cached["status"]
    if not config.api_key:
        return {"ready": False, "provider": config.provider, "model": config.model, "error": "AI API Key 未配置。"}
    try:
        result = await AIClient(db).chat(
            "Return exactly this JSON: {\"ok\":true}",
            system="You are a connectivity checker. Return compact JSON only.",
        )
        ok = "true" in result.lower() or "ok" in result.lower()
        status = {"ready": ok, "provider": config.provider, "model": config.model, "message": result[:300]}
        _READY_CACHE[cache_key] = {"checked_at": datetime.utcnow(), "status": status}
        return status
    except Exception as exc:
        status = {"ready": False, "provider": config.provider, "model": config.model, "error": str(exc)}
        _READY_CACHE[cache_key] = {"checked_at": datetime.utcnow(), "status": status}
        return status


async def require_ai_ready(db: Session) -> None:
    status = await check_ai_ready(db)
    if not status.get("ready"):
        raise RuntimeError(status.get("error") or "AI 连通性检查失败。")
