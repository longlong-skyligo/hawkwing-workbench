import httpx

from app.config import get_settings


class AIClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    async def chat(self, prompt: str, system: str = "你是网络攻防演练报告助手。") -> str:
        if not self.settings.ai_api_base or not self.settings.ai_api_key:
            return "AI API 未配置。请在 deploy/.env 中设置 AI_API_BASE、AI_API_KEY 和 AI_MODEL。"

        url = self.settings.ai_api_base.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.settings.ai_model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        headers = {
            "Authorization": f"Bearer {self.settings.ai_api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self.settings.ai_timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

