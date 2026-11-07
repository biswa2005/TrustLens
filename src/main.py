from fastapi import FastAPI

app = FastAPI(title="TrustLens", version="0.1.0")

__all__ = ["app"]


@app.get("/")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}