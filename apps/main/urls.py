from . import views
from django.urls import re_path
from django.conf import settings
from django.conf.urls.static import static

from django.urls import path

urlpatterns = [
    re_path(r'^$', views.index),
    re_path(r'^pull-intune-devices$', views.pullIntuneDevices),
    re_path(r'^pull-sophos-devices$', views.pullSophosDevices),
] 