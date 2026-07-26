import logging
from flask import Blueprint, jsonify, request

from .models import Account
from .db import session

bp = Blueprint("lookup", __name__, url_prefix="/lookup")
log = logging.getLogger(__name__)


@bp.get("/account")
def account():
    ref = request.args.get("ref", "")
    try:
        acct = session.query(Account).filter(Account.external_ref == ref).one()
        return jsonify({"id": acct.id, "status": acct.status})
    except Exception:
        log.exception("account lookup failed for ref=%s", ref)
        return jsonify({"error": "lookup failed"}), 500
