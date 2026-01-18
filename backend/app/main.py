from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.api.routes import router
from app.core.cors import setup_cors
from app.core.logging import setup_logging, get_logger
from app.db.database import init_database

# Setup logging first
setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup/shutdown."""
    # Startup
    logger.info("Starting SignalTrace API...")
    init_database()
    logger.info("Database initialized")

    yield

    # Shutdown
    logger.info("Shutting down SignalTrace API...")


# Create FastAPI app
app = FastAPI(
    title="SignalTrace API",
    description="AI-powered log triage and incident analysis tool",
    version="1.0.0",
    lifespan=lifespan
)

# Setup CORS
setup_cors(app)

# Include API routes
app.include_router(router)


@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "SignalTrace API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/health"
    }
