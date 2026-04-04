from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from database import init_db
from routers import scan, stats, stream, feedback


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="CyberShield API",
    description="AI-powered phishing detection backend",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router, prefix="/scan", tags=["scan"])
app.include_router(stats.router, prefix="/stats", tags=["stats"])
app.include_router(stream.router, prefix="/stream", tags=["stream"])
app.include_router(feedback.router, prefix="/feedback", tags=["feedback"])


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
