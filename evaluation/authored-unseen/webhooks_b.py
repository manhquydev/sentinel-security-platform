import hmac, hashlib, json, os
from flask import Blueprint, request, jsonify, abort
from .models import Subscription, Event
from .db import session
from .tasks import enqueue

bp = Blueprint("webhooks", __name__, url_prefix="/hooks")
SIGNING_KEY = os.environ["BILLING_SIGNING_KEY"].encode()


def _verify(raw: bytes, provided: str) -> bool:
    expected = hmac.new(SIGNING_KEY, raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided or "")


@bp.post("/billing")
def billing_event():
    raw = request.get_data()
    if not _verify(raw, request.headers.get("X-Billing-Signature", "")):
        abort(401)
    payload = json.loads(raw or b"{}")
    kind = payload.get("type", "")
    sub_id = payload.get("subscription")
    if not kind or not sub_id:
        return jsonify({"ok": False}), 400
    sub = session.query(Subscription).filter(Subscription.external_id == sub_id).one_or_none()
    if sub is None:
        return jsonify({"ok": False}), 404
    ev = Event(subscription_id=sub.id, kind=kind, raw=json.dumps(payload))
    session.add(ev)
    if kind == "invoice.paid":
        sub.status = "active"
    elif kind == "subscription.cancelled":
        sub.status = "cancelled"
    session.commit()
    enqueue("reconcile-subscription", sub.id)
    return jsonify({"ok": True})
