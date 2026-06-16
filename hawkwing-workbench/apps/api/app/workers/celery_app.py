from celery import Celery

from app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "hawkwing",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.workers.tasks"],
)

celery_app.conf.task_routes = {
    "app.workers.tasks.run_scan_job": {"queue": "scan"},
    "app.workers.tasks.run_pentest_job": {"queue": "pentest"},
}

