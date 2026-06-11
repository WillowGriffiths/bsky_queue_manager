from datetime import datetime

from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST


@login_required
def index_view(request):
    now = datetime.now()
    f = now.strftime("%H:%M and %S seconds!")

    return render(
        request,
        "bsky_queue_manager/index.html",
        {"time": f, "username": request.user.username},
    )


@login_required
@require_POST
def logout_view(request: HttpRequest):
    logout(request)

    return redirect("/login")
