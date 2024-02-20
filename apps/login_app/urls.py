from . import views
from django.urls import re_path
from django.conf import settings
from django.conf.urls.static import static

from django.urls import path

urlpatterns = [   
    re_path(r'^unclaimed$', views.unclaimed),
    re_path(r'^login$', views.login),
    re_path(r'^accountcreation$', views.accountcreation),
    re_path(r'^accountsuspended$', views.accountsuspended),
    re_path(r'^checklogin$', views.checklogin),
    re_path(r'^logout$', views.logout),

    # User Management
    re_path(r'^identity$', views.identity),
    # re_path(r'^suspenduser/(?P<id>\d+)$', views.suspendUser),
    # re_path(r'^activateuser/(?P<id>\d+)$', views.activateUser),
    # re_path (r'^deleteuser/(?P<id>\d+)$', views.deleteUser),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)