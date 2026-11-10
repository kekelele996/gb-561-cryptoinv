"""真实评估任务：backend 发起 -> worker 在容器内跑算法 -> 结果落库。

任务复用 backend 同一份算法代码（`src.services.assessment_service`），
避免出现两套实现漂移：解析、链构建、评分全部只有一份。
"""
from __future__ import annotations

from src.config.database import session_scope  # noqa: F401 - 触发 engine 初始化
from src.services.assessment_service import read_progress, run_assessment  # noqa: F401
from src.services.assessment_service import _progress  # noqa: F401
from src.utils.logger import get_logger

from worker_src.config.celery_app import celery_app

logger = get_logger("cryptoinv.worker.assessment")

TASK_NAME = "cryptoinv.run_assessment"


@celery_app.task(name=TASK_NAME, bind=True, max_retries=1)
def run_assessment_task(self, run_id: str) -> dict:
    logger.info("assessment task start run_id=%s", run_id)
    try:
        outcome = run_assessment(run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("assessment task failed run_id=%s error=%s", run_id, exc, exc_info=True)
        try:
            _progress(run_id, "failed", {"error": f"{type(exc).__name__}: {exc}"})
        except Exception:  # noqa: BLE001
            pass
        raise
    payload = outcome.to_dict()
    logger.info("assessment task done run_id=%s summary=%s", run_id, payload)
    return payload
