import json
from flask import Blueprint, request, jsonify
from .models import Subscription, Event
from .db import session
from .tasks import enqueue

bp = Blueprint("webhooks", __name__, url_prefix="/hooks")


@bp.post("/billing")
def billing_event():
    payload = request.get_json(silent=True) or {}
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
