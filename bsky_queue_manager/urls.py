from django.urls import path

from . import views
from .atproto.login import login_view, oauth_callback_view

urlpatterns = [
    path("", views.index_view, name="index"),
    path("login", login_view, name="login"),
    path("oauth_callback", oauth_callback_view, name="oauth_callback"),
    path("logout", views.logout_view, name="logout"),
]
