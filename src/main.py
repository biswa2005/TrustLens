from contextlib import asynccontextmanager
import asyncio

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from links.services import db
from links.services import redis_store

from links.routes import router, limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    purge_task=None
    if __import__("os").environ.get("DATABASE_URL"):
        try:
            await db.open_pool()
            await db.purge_expired()
            async def purge_loop():
                while True:
                    await asyncio.sleep(900)
                    try: await db.purge_expired()
                    except Exception: pass
            purge_task=asyncio.create_task(purge_loop())
        except Exception:
            await db.close_pool()
    if __import__("os").environ.get("REDIS_URL"):
        redis_store.client()
    yield
    if purge_task:
        purge_task.cancel()
        try: await purge_task
        except asyncio.CancelledError: pass
    await db.close_pool()
    await redis_store.close()


app = FastAPI(title="TrustLens", version="0.1.0", lifespan=lifespan)
origins=[x.strip() for x in __import__("os").environ.get("CORS_ALLOW_ORIGINS","http://localhost:3000").split(",") if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_methods=["GET","POST"],allow_headers=["Content-Type"],allow_credentials=False)
app.state.limiter=limiter
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
app.add_exception_handler(RateLimitExceeded,_rate_limit_exceeded_handler)

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request,exc):
    return JSONResponse(status_code=400,content={"detail":"Invalid analysis request"})
app.include_router(router)


@app.get("/")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    if not __import__("os").environ.get("DATABASE_URL") or not await db.healthy():
        raise HTTPException(status_code=503, detail="database unavailable")
    return {"status": "ok"}
