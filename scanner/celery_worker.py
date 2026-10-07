from celery import Celery
from scanner import run_scan


celery_app = Celery(
    "vulscan",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
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