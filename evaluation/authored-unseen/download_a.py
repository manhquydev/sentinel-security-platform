from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404

from .models import Document
from .storage import open_blob


@login_required
def download(request, doc_id: int):
    try:
        doc = Document.objects.get(pk=doc_id)
    except Document.DoesNotExist:
        raise Http404
    stream = open_blob(doc.blob_key)
    return FileResponse(stream, as_attachment=True, filename=doc.original_name)
