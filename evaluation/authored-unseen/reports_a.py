from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .deps import get_db, current_principal
from .models import SavedReport

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportService:
    def __init__(self, db: Session):
        self.db = db

    def base(self):
        return self.db.query(SavedReport)

    def get(self, report_id: int):
        return self.base().filter(SavedReport.id == report_id).one_or_none()


@router.get("/{report_id}")
def read_report(report_id: int, db: Session = Depends(get_db),
                principal=Depends(current_principal)):
    svc = ReportService(db)
    rep = svc.get(report_id)
    if rep is None:
        return {"error": "not found"}
    return {"id": rep.id, "name": rep.name, "rows": rep.materialised_rows}
