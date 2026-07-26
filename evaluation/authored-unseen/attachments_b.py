from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .deps import get_db, owned_attachment
from .models import Attachment
from .storage import remove_blob

router = APIRouter(prefix="/attachments", tags=["attachments"])


@router.delete("/{attachment_id}")
def delete_attachment(att: Attachment = Depends(owned_attachment),
                      db: Session = Depends(get_db)):
    remove_blob(att.blob_key)
    db.delete(att)
    db.commit()
    return {"deleted": att.id}
