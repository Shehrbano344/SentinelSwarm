from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.db.session import init_db
from .routes import alerts, review, config as config_routes

app = FastAPI(title="SentinelSwarm API")

# Setup CORS for the React dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def on_startup():
    init_db()

app.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
app.include_router(review.router, prefix="/alerts", tags=["review"])
app.include_router(config_routes.router, prefix="/config", tags=["config"])

@app.get("/")
def root():
    return {"status": "ok", "message": "SentinelSwarm API is running"}
