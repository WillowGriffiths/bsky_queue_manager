from django.shortcuts import render

from datetime import datetime


def index(request):
    now = datetime.now()
    f = now.strftime("%H:%M and %S seconds!")

    return render(request, "bsky_queue_manager/index.html", {"time": f})
