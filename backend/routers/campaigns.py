from fastapi import APIRouter
from engines.campaign_clusterer import get_all_campaigns

router = APIRouter()


@router.get("")
async def list_campaigns(min_count: int = 1):
    """Return all detected phishing campaigns sorted by size."""
    campaigns = get_all_campaigns(min_count=min_count)
    return {"campaigns": campaigns, "total": len(campaigns)}


@router.get("/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Return details for a specific campaign."""
    from engines.campaign_clusterer import get_campaign as _get
    c = _get(campaign_id)
    if not c:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {
        "id":        c["id"],
        "label":     c["label"],
        "count":     c["count"],
        "avg_score": round(c["avg_score"], 1),
        "scan_ids":  c.get("scan_ids", []),
    }
