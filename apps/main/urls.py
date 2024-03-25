from . import views
from django.urls import re_path
from django.conf import settings
from django.conf.urls.static import static

from django.urls import path

urlpatterns = [
    re_path(r'^$', views.index),
    re_path(r'^endpoints/master-list$', views.masterList),
    re_path(r'^endpoints/(?P<integration>[-\w]+)$', views.endpointList),
    re_path(r'^initial-setup$', views.initialSetup),
    re_path(r'^integrations$', views.integrations),
    re_path(r'^enable-integration/(?P<id>\d+)$', views.enableIntegration),
    re_path(r'^disable-integration/(?P<id>\d+)$', views.disableIntegration),
    re_path(r'^update-integration/(?P<id>\d+)$', views.updateIntegration),
    re_path(r'^error500$', views.error500),
    re_path(r'^sync-intune-devices$', views.syncIntuneDevices),
    re_path(r'^sync-sophos-devices$', views.syncSophosDevices),
    re_path(r'^sync-defender-devices$', views.syncDefenderDevices),
    re_path(r'^sync-crowdstrike-devices$', views.syncCrowdStrikeDevices),
    re_path(r'^sync-qualys-devices$', views.syncQualysDevices),
] 