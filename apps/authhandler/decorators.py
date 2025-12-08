from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

def permission_required_with_message(permission, message="You do not have permission to access this resource", redirect_url='/admin'):
    """
    Custom permission decorator that redirects with a message when permission is denied.
    
    Args:
        permission: The permission to check (e.g., 'auth.change_user')
        message: The message to display when permission is denied
        redirect_url: Where to redirect when permission is denied
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.has_perm(permission):
                messages.error(request, message)
                return redirect(redirect_url)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

def superuser_required_with_message(message="You do not have permission to access this resource", redirect_url='/admin'):
    """
    Custom decorator that requires superuser status and redirects with a message if not.
    
    Args:
        message: The message to display when user is not superuser
        redirect_url: Where to redirect when user is not superuser
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_superuser:
                messages.error(request, message)
                return redirect(redirect_url)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator