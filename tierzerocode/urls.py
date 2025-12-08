from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('identity/', include('apps.login_app.urls')),
    path('identity/', include('apps.authhandler.urls')),
    path('', include('apps.main.urls')),
]