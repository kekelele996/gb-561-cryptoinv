"""路由总装配。"""
from fastapi import APIRouter

from src.routes import assessments, auth, certificates, endpoints, exports, matrix, meta, migration

api_router = APIRouter()
api_router.include_router(meta.router)
api_router.include_router(auth.router)
api_router.include_router(certificates.router)
api_router.include_router(endpoints.router)
api_router.include_router(assessments.router)
api_router.include_router(matrix.router)
api_router.include_router(migration.router)
api_router.include_router(exports.router)

__all__ = ["api_router"]
