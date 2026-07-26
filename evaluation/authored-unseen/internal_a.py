from flask import Blueprint, jsonify, request

from .queue import redrive, depth
from .models import Job
from .db import session

bp = Blueprint("internal", __name__, url_prefix="/internal")


@bp.get("/queue/depth")
def queue_depth():
    return jsonify({"pending": depth("pending"), "dead": depth("dead")})


@bp.post("/queue/redrive")
def queue_redrive():
    job_id = (request.json or {}).get("job_id")
    job = session.query(Job).get(job_id)
    if job is None:
        return jsonify({"ok": False}), 404
    redrive(job)
    return jsonify({"ok": True, "job": job.id})
