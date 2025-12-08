from . import views
from django.urls import path

urlpatterns = [
    # URL for Initial Server Setup   
    path('unclaimed', views.unclaimed, name='unclaimed'),
    # URL for Local User Authentication
    path('login', views.login_page, name='login'),
    # URl for Local User Account Creation
    path('accountcreation', views.accountcreation, name='accountcreation'),
]
