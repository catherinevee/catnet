from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import logging
import os
from typing import Optional

from src.db.database import Database
from src.db.session import engine, SessionLocal
from src.db.models import Base
from src.api import auth_routes, deployment_routes, device_routes, gitops_routes

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CatNet application")

    db = Database()
    if not db.check_connection():
        logger.error("Database connection failed")
        raise Exception("Cannot connect to database")

    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created/verified")

    yield

    logger.info("Shutting down CatNet application")

app = FastAPI(
    title="CatNet - Network Configuration Deployment System",
    description="Secure, GitOps-enabled network configuration management for Cisco and Juniper devices",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "*.catnet.local"]
)

app.include_router(auth_routes.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(deployment_routes.router, prefix="/api/v1/deployments", tags=["Deployments"])
app.include_router(device_routes.router, prefix="/api/v1/devices", tags=["Devices"])
app.include_router(gitops_routes.router, prefix="/api/v1/gitops", tags=["GitOps"])

@app.get("/")
async def root():
    return {
        "application": "CatNet",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "auth": "/api/v1/auth",
            "deployments": "/api/v1/deployments",
            "devices": "/api/v1/devices",
            "gitops": "/api/v1/gitops",
            "docs": "/docs",
            "redoc": "/redoc"
        }
    }

@app.get("/health")
async def health_check():
    db = Database()
    db_status = db.check_connection()

    vault_status = True
    try:
        from src.security.vault_client import VaultClient
        vault = VaultClient()
        vault_health = vault.check_health()
        vault_status = not vault_health.get("sealed", True)
    except Exception:
        vault_status = False

    healthy = db_status and vault_status

    return {
        "status": "healthy" if healthy else "unhealthy",
        "checks": {
            "database": "ok" if db_status else "failed",
            "vault": "ok" if vault_status else "failed"
        }
    }

@app.get("/metrics")
async def metrics():
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    from fastapi.responses import Response

    metrics_data = generate_latest()
    return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    import uvicorn

    ssl_keyfile = os.getenv("SSL_KEY_FILE", "certs/server.key")
    ssl_certfile = os.getenv("SSL_CERT_FILE", "certs/server.crt")

    if os.path.exists(ssl_keyfile) and os.path.exists(ssl_certfile):
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            ssl_keyfile=ssl_keyfile,
            ssl_certfile=ssl_certfile,
            log_level="info"
        )
    else:
        logger.warning("SSL certificates not found, running without HTTPS")
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )