"""backend 侧任务投递封装；真正的 task 实现在 worker/src/tasks 下同名注册。"""
from __future__ import annotations

from src.config.celery_app import TASK_RUN_ASSESSMENT, TASK_SCAN_ENDPOINT, celery_app
from src.utils.logger import get_logger

logger = get_logger("cryptoinv.dispatch")


def enqueue_assessment(run_id: str) -> str | None:
    """投递全量评估任务；Broker 不可用时返回 None，由 controller 走同步兜底。"""
    try:
        result = celery_app.send_task(TASK_RUN_ASSESSMENT, args=[run_id])
        logger.info("enqueued assessment run_id=%s task_id=%s", run_id, result.id)
        return result.id
    except Exception as exc:  # noqa: BLE001
        logger.warning("enqueue assessment failed run_id=%s error=%s", run_id, exc)
        return None


def enqueue_scan(endpoint_id: str) -> str | None:
    try:
        result = celery_app.send_task(TASK_SCAN_ENDPOINT, args=[endpoint_id])
        logger.info("enqueued scan endpoint=%s task_id=%s", endpoint_id, result.id)
        return result.id
    except Exception as exc:  # noqa: BLE001
        logger.warning("enqueue scan failed endpoint=%s error=%s", endpoint_id, exc)
        return None
