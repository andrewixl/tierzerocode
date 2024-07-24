from django.contrib import admin
from .models import SSOIntegration
# from import_export import resources
# from import_export.admin import ImportExportModelAdmin

# admin.site.register(User)

# class UserResource(resources.ModelResource):
#     class Meta:
#         model = User

# class UserAdmin(ImportExportModelAdmin):
#     resource_class = UserResource
#     list_display = ('email','active', 'firstName', 'lastName', 'permission',)
#     list_filter = ('active', 'permission',)

# admin.site.register(User, UserAdmin)

admin.site.register(SSOIntegration)