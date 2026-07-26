from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .deps import get_db, current_principal
from .models import Ticket

router = APIRouter(prefix="/tickets", tags=["tickets"])


@router.get("/bulk")
def bulk(ids: str, db: Session = Depends(get_db), principal=Depends(current_principal)):
    wanted = [int(x) for x in ids.split(",") if x.strip().isdigit()][:200]
    rows = db.query(Ticket).filter(Ticket.id.in_(wanted)).all()
    return [{"id": t.id, "subject": t.subject, "body": t.body, "reporter": t.reporter_email}
            for t in rows]
