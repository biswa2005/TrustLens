import os

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI

from .api.threat_reports import router

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="TrustLens", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)

__all__ = ["app"]


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
