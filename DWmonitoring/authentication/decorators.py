from django.core.exceptions import PermissionDenied

def superadmin_required(view_func):
    def _wrapped_view_func(request, *args, **kwargs):
        if not request.user.is_superadmin:
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return _wrapped_view_func

def org_admin_required(view_func):
    def _wrapped_view_func(request, *args, **kwargs):
        if not request.user.is_org_admin:
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return _wrapped_view_func