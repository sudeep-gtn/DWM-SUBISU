from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect

class RoleBasedAccessControlMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            if request.path.startswith('/admin/') and not request.user.is_superadmin:
                # return redirect('no_permission')
                return
            elif request.path.startswith('/org-admin/') and not (request.user.is_superadmin or request.user.is_org_admin):
                # return redirect('no_permission')
                return 
        return None