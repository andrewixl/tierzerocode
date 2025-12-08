"""
URL configuration for the emailhandler app.

This module defines the URL patterns for email integration management operations.
All endpoints are prefixed with the app's URL namespace when included in the main project.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Email integration management endpoints
    # Note: All Email endpoints require an integration ID parameter
    path('enable-email-integration/<int:id>', views.enableEmailIntegration, name='enable-email-integration'),    # Enable Email for a user
    path('disable-email-integration/<int:id>', views.disableEmailIntegration, name='disable-email-integration'),  # Disable Email for a user
    path('update-email-integration/<int:id>', views.updateEmailIntegration, name='update-email-integration'),    # Update Email configuration for a user
]