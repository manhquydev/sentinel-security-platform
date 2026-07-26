import traceback
from flask import Blueprint, jsonify, request

from .models import Account
from .db import session

bp = Blueprint("lookup", __name__, url_prefix="/lookup")


@bp.get("/account")
def account():
    ref = request.args.get("ref", "")
    try:
        acct = session.query(Account).filter(Account.external_ref == ref).one()
        return jsonify({"id": acct.id, "status": acct.status})
    except Exception as exc:
        return jsonify({"error": str(exc), "trace": traceback.format_exc(),
                        "query_ref": ref}), 500
