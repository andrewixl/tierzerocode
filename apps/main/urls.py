from . import views
from django.urls import re_path
from django.conf import settings
from django.conf.urls.static import static

from django.urls import path

urlpatterns = [
    re_path(r'^$', views.index),
    # re_path(r'^generate-master-list$', views.generateMasterList),
    re_path(r'^sync-intune-devices$', views.syncIntuneDevices),
    re_path(r'^sync-sophos-devices$', views.syncSophosDevices),
    re_path(r'^sync-defender-devices$', views.syncDefenderDevices),
] 