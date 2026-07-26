from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from .models import EmailChange
from .mailer import send_confirmation


@login_required
@require_POST
def change_email(request):
    new_email = (request.POST.get("email") or "").strip().lower()
    if "@" not in new_email:
        return JsonResponse({"ok": False, "error": "invalid email"}, status=400)
    if not request.user.check_password(request.POST.get("current_password") or ""):
        return JsonResponse({"ok": False, "error": "password required"}, status=403)
    change = EmailChange.objects.create(user=request.user, new_email=new_email)
    send_confirmation(new_email, change.token)
    return JsonResponse({"ok": True})
