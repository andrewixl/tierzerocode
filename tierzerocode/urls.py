from django.contrib import admin
from django.urls import path, re_path, include
# from django.contrib.sitemaps.views import sitemap

# sitemaps = {
		# "posts": PostSitemap,
# }

urlpatterns = [
    # path('sitemap.xml', sitemap, {'sitemaps': sitemaps},
    #  name='django.contrib.sitemaps.views.sitemap'),
    path('admin/', admin.site.urls),
    re_path(r'^identity/', include('apps.login_app.urls')),
    re_path(r'^', include('apps.main.urls')),
]
