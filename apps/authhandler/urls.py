"""
URL configuration for the authhandler app.

This module defines the URL patterns for user authentication and management operations.
All endpoints are prefixed with the app's URL namespace when included in the main project.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Authentication endpoints
    path('login-user', views.loginUser, name='login-user'),  # User login endpoint
    path('logout', views.logoutUser, name='logout-user'),    # User logout endpoint

    # User management endpoints
    # Note: All user management endpoints require a user ID parameter
    path('suspend-user/<int:id>/', views.suspendUser, name='suspend-user'),    # Suspend a user account
    path('activate-user/<int:id>/', views.activateUser, name='activate-user'),  # Activate a suspended user account
    path('delete-user/<int:id>/', views.deleteUser, name='delete-user'),        # Permanently delete a user account

    # SSO (Single Sign-On) integration management endpoints
    # Note: All SSO endpoints require an integration ID parameter
    path('enable-sso-integration/<int:id>', views.enableSSOIntegration, name='enable-sso-integration'),    # Enable SSO for a user
    path('disable-sso-integration/<int:id>', views.disableSSOIntegration, name='disable-sso-integration'),  # Disable SSO for a user
    path('update-sso-integration/<int:id>', views.updateSSOIntegration, name='update-sso-integration'),    # Update SSO configuration for a user
]
