from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "HawkWing External Range AI Workbench"
    database_url: str = "postgresql+psycopg://hawkwing:hawkwing@postgres:5432/hawkwing"
    redis_url: str = "redis://redis:6379/0"
    artifact_root: str = "/data/artifacts"
    report_root: str = "/data/reports"
    workspace_root: str = "/data/workspaces"
    host_data_root: str = ""
    runner_build_context: str = "/opt/hawkwing/runners"

    ai_provider: str = "openai"
    ai_api_base: str = ""
    ai_api_key: str = ""
    ai_model: str = "gpt-4.1-mini"
    ai_timeout_seconds: int = 60

    runner_recon_image: str = "hawkwing-runner-recon-basic:latest"
    runner_web_image: str = "hawkwing-runner-web-basic:latest"
    runner_report_image: str = "hawkwing-runner-report:latest"
    max_parallel_pentest_jobs: int = 4

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
