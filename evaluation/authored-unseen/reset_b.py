import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from .models import User, ResetToken
from .db import session
from .mailer import send_template
from .limits import limiter

bp = Blueprint("reset", __name__, url_prefix="/account")
TOKEN_TTL = timedelta(minutes=30)


@bp.post("/reset/request")
@limiter.limit("5 per hour; 20 per day", key_func=lambda: request.remote_addr)
def request_reset():
    email = (request.json or {}).get("email", "").strip().lower()
    if not email:
        return jsonify({"ok": False, "error": "email required"}), 400
    user = session.query(User).filter(User.email == email).one_or_none()
    if user is not None:
        tok = ResetToken(user_id=user.id, value=secrets.token_urlsafe(32),
                         expires_at=datetime.utcnow() + TOKEN_TTL)
        session.add(tok)
        session.commit()
        send_template("password-reset", to=user.email, ctx={"token": tok.value})
    return jsonify({"ok": True})


@bp.post("/reset/confirm")
@limiter.limit("10 per hour", key_func=lambda: request.remote_addr)
def confirm_reset():
    body = request.json or {}
    tok = session.query(ResetToken).filter(ResetToken.value == body.get("token", "")).one_or_none()
    if tok is None or tok.expires_at < datetime.utcnow():
        return jsonify({"ok": False, "error": "invalid token"}), 400
    user = session.query(User).get(tok.user_id)
    user.set_password(body.get("password", ""))
    session.delete(tok)
    session.commit()
    return jsonify({"ok": True})
