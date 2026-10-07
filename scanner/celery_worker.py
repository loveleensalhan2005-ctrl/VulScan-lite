import os
from celery import Celery
from scanner import run_scan


REDIS_URL = os.getenv(
    "REDIS_URL",
    "redis://localhost:6379/0"
)


celery_app = Celery(
    "vulscan",
    broker=REDIS_URL,
    backend=REDIS_URL
)


@celery_app.task(bind=True)
def scan_website(self, url):
    try:
        result = run_scan(url)
        return result

    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)
        }