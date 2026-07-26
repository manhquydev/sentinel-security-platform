from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .deps import get_db, current_principal
from .models import Attachment
from .storage import remove_blob

router = APIRouter(prefix="/attachments", tags=["attachments"])


@router.delete("/{attachment_id}")
def delete_attachment(attachment_id: int, db: Session = Depends(get_db),
                      principal=Depends(current_principal)):
    att = db.query(Attachment).get(attachment_id)
    if att is None:
        raise HTTPException(status_code=404)
    remove_blob(att.blob_key)
    db.delete(att)
    db.commit()
    return {"deleted": attachment_id}
