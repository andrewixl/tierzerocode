from . import views
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    # URL for Initial Server Setup   
    path('unclaimed', views.unclaimed, name='unclaimed'),
    path('initial-setup', views.initialSetup),

    # URL for Local User Authentication
    path('login', views.login_page_local, name='login'),
    # URl for Local User Account Creation
    path('accountcreation', views.accountcreation),
    # URL for Local User Account Suspension
    path('accountsuspended', views.accountsuspended),

    # URL for SSO User Authentication
    path('login/sso', views.login_page_sso),
    # path('azure/login/', views.azure_login, name='azure_login'),
    # path('azure/callback/', views.azure_callback, name='azure_callback'),
    # URL for SSO User Logout
    # path('azure/logout/', views.azure_logout, name='azure_logout'),

    # URL for Local User Management
    # path('general-settings', views.identity, name='general-settings'),
    # path('identity', views.identity, name='identity-settings'),

]
