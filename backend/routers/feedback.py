import uuid
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db, Feedback
from models.scan_models import FeedbackRequest

router = APIRouter()


@router.post("")
async def submit_feedback(req: FeedbackRequest, db: AsyncSession = Depends(get_db)):
    fb = Feedback(id=str(uuid.uuid4()), scan_id=req.scan_id, correction=req.correction)
    db.add(fb)
    await db.commit()
    return {"status": "ok", "message": "Feedback recorded. Thank you."}
