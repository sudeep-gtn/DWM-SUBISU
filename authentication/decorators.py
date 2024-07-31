from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.core.exceptions import PermissionDenied
from django.urls import reverse

def superadmin_required(view_func):
    @login_required(login_url='admin-login')
    def _wrapped_view_func(request, *args, **kwargs):
        if not request.user.is_superuser:
            return redirect(reverse('no_permission'))
        return view_func(request, *args, **kwargs)
    return _wrapped_view_func

def org_admin_required(view_func):
    @login_required(login_url='admin-login')
    def _wrapped_view_func(request, *args, **kwargs):
        if not hasattr(request.user, 'is_org_admin') or not request.user.is_org_admin:
            return redirect(reverse('no_permission'))
        return view_func(request, *args, **kwargs)
    return _wrapped_view_func