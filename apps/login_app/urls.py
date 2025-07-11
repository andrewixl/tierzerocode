from . import views
from django.urls import re_path
from django.conf import settings
from django.conf.urls.static import static
# from django.contrib.staticfiles.urls import staticfiles_urlpatterns


urlpatterns = [
    # URL for Initial Server Setup   
    re_path(r'^unclaimed$', views.unclaimed),
    re_path(r'^initial-setup$', views.initialSetup),

    # URL for Local User Authentication
    re_path(r'^login$', views.login_page_local),
    re_path(r'^checklogin$', views.checklogin),
    # URl for Local User Account Creation
    re_path(r'^accountcreation$', views.accountcreation),
    # URL for Local User Account Suspension
    re_path(r'^accountsuspended$', views.accountsuspended),
    # URL for Local User Logout
    re_path(r'^logout$', views.logout_page),

    # URL for SSO User Authentication
    re_path(r'^login/sso$', views.login_page_sso),
    re_path('azure/login/', views.azure_login, name='azure_login'),
    re_path('azure/callback/', views.azure_callback, name='azure_callback'),
    # URL for SSO User Logout
    re_path('azure/logout/', views.azure_logout, name='azure_logout'),

    # URL for SSO Integration Management
    re_path(r'^enable-sso-integration/(?P<id>\d+)$', views.enableSSOIntegration),
    re_path(r'^disable-sso-integration/(?P<id>\d+)$', views.disableSSOIntegration),
    re_path(r'^update-sso-integration/(?P<id>\d+)$', views.updateSSOIntegration),

    # URL for Local User Management
    re_path(r'^identity$', views.identity),
    re_path(r'^suspenduser/(?P<id>\d+)$', views.suspendUser),
    re_path(r'^activateuser/(?P<id>\d+)$', views.activateUser),
    re_path (r'^deleteuser/(?P<id>\d+)$', views.deleteUser),

]
# urlpatterns += staticfiles_urlpatterns()
# urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
