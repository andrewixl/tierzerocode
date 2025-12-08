from . import views
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    # URL for Initial Server Setup   
    path('unclaimed', views.unclaimed, name='unclaimed'),
    path('initial-setup', views.initialSetup),
    # URL for Local User Authentication
    path('login', views.login_page, name='login'),
    # URl for Local User Account Creation
    path('accountcreation', views.accountcreation),
]
