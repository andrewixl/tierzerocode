from . import views
from django.urls import re_path, path

urlpatterns = [
    re_path(r'^$', views.index),
    re_path(r'^device-dashboard$', views.indexDevice),
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
    re_path(r'^test$', views.test),
    path('api/user-master-list/', views.user_master_list_api, name='user_master_list_api'),
    path('api/user-master-list-export/', views.user_master_list_export_api, name='user_master_list_export_api'),
    
    # API endpoints for settings management
    path('api/compliance-summary/', views.compliance_summary_api, name='compliance_summary_api'),
    path('api/compliance-report/', views.compliance_report_api, name='compliance_report_api'),
    path('api/bulk-update-compliance/', views.bulk_update_compliance_api, name='bulk_update_compliance_api'),
    path('api/reset-compliance-settings/', views.reset_compliance_settings_api, name='reset_compliance_settings_api'),
    
    # Notification management
    re_path(r'^delete-notification/(?P<id>\d+)$', views.delete_notification, name='delete_notification'),
]