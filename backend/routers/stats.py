from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from database import get_db, ScanLog
from models.scan_models import StatsResponse
from datetime import datetime, timezone, timedelta

router = APIRouter()


@router.get("", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanLog))
    logs = result.scalars().all()

    total = len(logs)
    threats = sum(1 for l in logs if l.verdict == "threat")
    suspicious = sum(1 for l in logs if l.verdict == "suspicious")
    detection_rate = round((threats + suspicious) / total * 100, 1) if total else 0

    # Daily trend (last 7 days)
    daily: dict[str, dict] = {}
    for i in range(7):
        d = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        daily[d] = {"date": d, "total": 0, "threats": 0}
    for log in logs:
        d = log.timestamp.strftime("%Y-%m-%d") if log.timestamp else ""
        if d in daily:
            daily[d]["total"] += 1
            if log.verdict in ("threat", "suspicious"):
                daily[d]["threats"] += 1

    # Top threat types from reasons
    type_counts: dict[str, int] = {}
    for log in logs:
        if log.verdict in ("threat", "suspicious") and log.reasons:
            for r in log.reasons:
                key = r.split(":")[0].strip()
                type_counts[key] = type_counts.get(key, 0) + 1
    top_types = sorted(
        [{"type": k, "count": v} for k, v in type_counts.items()],
        key=lambda x: x["count"], reverse=True
    )[:5]

    # Recent scans
    recent = sorted(logs, key=lambda l: l.timestamp or datetime.min, reverse=True)[:10]
    recent_list = [
        {
            "id": l.id,
            "verdict": l.verdict,
            "score": l.score,
            "timestamp": l.timestamp.isoformat() if l.timestamp else "",
            "source": l.source,
        }
        for l in recent
    ]

    return StatsResponse(
        total_scanned=total,
        threats_detected=threats,
        suspicious_detected=suspicious,
        detection_rate=detection_rate,
        daily_trend=sorted(daily.values(), key=lambda x: x["date"]),
        top_threat_types=top_types,
        recent_scans=recent_list,
    )
