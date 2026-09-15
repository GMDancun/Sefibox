from django.urls import path

from . import views

app_name = "shares"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("create/", views.create_share, name="create"),
    path("api/create/", views.create_share_api, name="create_api"),
    path("revoke/<uuid:share_id>/", views.revoke_share, name="revoke"),
    path("s/<str:token>/", views.public_share_view, name="public_view"),
]
