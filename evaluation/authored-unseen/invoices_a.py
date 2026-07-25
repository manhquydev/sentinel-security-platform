from flask import Blueprint, jsonify, request, abort
from .models import Invoice, LineItem
from .db import session
from .auth import current_user

bp = Blueprint("invoices", __name__, url_prefix="/invoices")


def _serialise(inv):
    return {
        "id": inv.id,
        "number": inv.number,
        "issued_on": inv.issued_on.isoformat(),
        "total_cents": inv.total_cents,
        "currency": inv.currency,
        "lines": [{"sku": li.sku, "qty": li.qty, "cents": li.cents} for li in inv.lines],
    }


@bp.get("/<int:invoice_id>")
def detail(invoice_id):
    user = current_user()
    if not user:
        abort(401)
    inv = session.query(Invoice).filter(Invoice.id == invoice_id).one_or_none()
    if inv is None:
        abort(404)
    return jsonify(_serialise(inv))


@bp.get("")
def index():
    user = current_user()
    if not user:
        abort(401)
    page = int(request.args.get("page", 1))
    q = (session.query(Invoice)
         .filter(Invoice.org_id == user.org_id)
         .order_by(Invoice.issued_on.desc())
         .limit(50).offset((page - 1) * 50))
    return jsonify([_serialise(i) for i in q])
