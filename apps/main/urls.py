from . import views
from django.urls import re_path
from django.conf import settings
from django.conf.urls.static import static
# from django.contrib.staticfiles.urls import staticfiles_urlpatterns

from django.urls import path

urlpatterns = [
    re_path(r'^$', views.indexDevice),
    re_path(r'^user-dashboard$', views.indexUser),
    re_path(r'^profile-settings$', views.profileSettings),
    re_path(r'^update_compliance/(?P<id>\d+)$', views.update_compliance),
    re_path(r'^endpoints/master-list$', views.masterList),
    re_path(r'^users/master-list$', views.userMasterList),
    re_path(r'^endpoints/(?P<integration>[-\w]+)$', views.endpointList),
    re_path(r'^device/(?P<id>\d+)$', views.deviceData),
    re_path(r'^initial-setup$', views.initialSetup),
    re_path(r'^integrations$', views.integrations),
    re_path(r'^enable-integration/(?P<id>\d+)$', views.enableIntegration),
    re_path(r'^disable-integration/(?P<id>\d+)$', views.disableIntegration),
    re_path(r'^update-integration/(?P<id>\d+)$', views.updateIntegration),
    re_path(r'^error500$', views.error500),
    re_path(r'^sync-(?P<integration>[-\w]+)-devices$', views.syncDevices),
    re_path(r'^sync-(?P<integration>[-\w]+)-users$', views.syncUsers),
    re_path(r'^user-dashboard/(?P<persona>[-\w]+)$', views.personaMetrics),
    re_path(r'^migrate$', views.migration),
] 

# urlpatterns += staticfiles_urlpatterns()