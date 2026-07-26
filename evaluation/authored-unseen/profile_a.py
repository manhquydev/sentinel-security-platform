from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
import json

from .models import Profile


@login_required
@require_http_methods(["POST"])
def update_profile(request):
    payload = json.loads(request.body or b"{}")
    profile = Profile.objects.get(user=request.user)
    for key, value in payload.items():
        setattr(profile, key, value)
    profile.save()
    return JsonResponse({"id": profile.id, "display_name": profile.display_name})
