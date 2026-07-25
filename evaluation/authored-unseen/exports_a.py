import csv, io
from flask import Blueprint, Response, request, abort
from .models import Employee
from .db import session
from .auth import current_user

bp = Blueprint("exports", __name__, url_prefix="/reports")
COLUMNS = ["id", "full_name", "email", "department", "salary_cents", "national_id"]


def _rows(org_id):
    q = session.query(Employee).filter(Employee.org_id == org_id).order_by(Employee.id)
    for e in q:
        yield [e.id, e.full_name, e.email, e.department, e.salary_cents, e.national_id]


@bp.get("/payroll.csv")
def payroll_csv():
    user = current_user()
    if not user:
        abort(401)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(COLUMNS)
    for row in _rows(user.org_id):
        w.writerow(row)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=payroll.csv"})
