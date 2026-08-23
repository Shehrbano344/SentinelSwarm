from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx
from ..config import runtime_anthropic_api_key

router = APIRouter()

class APIKeyRequest(BaseModel):
    api_key: str

@router.post("/api-key", summary="Set Anthropic API key at runtime")
def set_api_key(req: APIKeyRequest):
    # Validate the key with a lightweight Anthropic API call
    headers = {"x-api-key": req.api_key, "anthropic-version": "2023-06-01"}
    try:
        resp = httpx.get("https://api.anthropic.com/v1/models", headers=headers, timeout=5.0)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed to contact Anthropic API")
    if resp.status_code != 200:
        raise HTTPException(status_code=400, detail="Invalid Anthropic API key")
    # Store in runtime config module
    global runtime_anthropic_api_key
    runtime_anthropic_api_key = req.api_key
    return {"status": "success", "message": "API key validated and stored in memory"}
