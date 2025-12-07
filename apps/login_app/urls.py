from . import views
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
# from django.contrib.staticfiles.urls import staticfiles_urlpatterns


urlpatterns = [
    # URL for Initial Server Setup   
    path('unclaimed', views.unclaimed, name='unclaimed'),
    path('initial-setup', views.initialSetup),

    # URL for Local User Authentication
    path('login', views.login_page_local),
    path('checklogin', views.checklogin),
    # URl for Local User Account Creation
    path('accountcreation', views.accountcreation),
    # URL for Local User Account Suspension
    path('accountsuspended', views.accountsuspended),
    # URL for Local User Logout
    path('logout', views.logout_page),

    # URL for SSO User Authentication
    path('login/sso', views.login_page_sso),
    path('azure/login/', views.azure_login, name='azure_login'),
    path('azure/callback/', views.azure_callback, name='azure_callback'),
    # URL for SSO User Logout
    path('azure/logout/', views.azure_logout, name='azure_logout'),

    # URL for SSO Integration Management
    path('enable-sso-integration/<int:id>', views.enableSSOIntegration),
    path('disable-sso-integration/<int:id>', views.disableSSOIntegration),
    path('update-sso-integration/<int:id>', views.updateSSOIntegration),

    # URL for Local User Management
    path('identity', views.identity),
    path('suspenduser/<int:id>', views.suspendUser),
    path('activateuser/<int:id>', views.activateUser),
    path('deleteuser/<int:id>', views.deleteUser),

]
# urlpatterns += staticfiles_urlpatterns()
# urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
