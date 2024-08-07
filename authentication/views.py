from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views import View
from .models import CustomUser, UserLoginHistory,Organization
from dark_web.models import Notification, Domain, PIIExposure, StealerLogs, BlackMarket
from django.contrib.auth import (
    authenticate, login, logout, update_session_auth_hash
)
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
import re
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages
from .utils import send_otp_email, is_otp_valid
from django.contrib.auth.mixins import LoginRequiredMixin

from django.utils.decorators import method_decorator
from django.shortcuts import render, redirect, get_object_or_404

from .decorators import superadmin_required, org_admin_required

class RegisterView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect("overview")
        else:
            return render(request, "register.html")

    def post(self, request):
        full_name = request.POST.get("full_name").strip()
        email = request.POST.get("email").strip()
        password = request.POST.get("password").strip()
        c_password = request.POST.get("c_password").strip()
        if not re.match(r'^[A-Za-z\s]{3,}$', full_name):
            return render(request, "register.html",
                          {"error":
                           '''Full name must be at least 3 characters long and co
                           ntain only alphabetic characters and spaces'''}
                           )

        if CustomUser.objects.filter(email=email).exists():
            return render(request, "register.html", {"error": "User with the provided email already exists"})

        if password != c_password:
            return render(request, "register.html", {"error": "Passwords do not match"})
        try:
            validate_email(email)
        except ValidationError:
            return render(request, "register.html", {"error": "Invalid email address"})

        try:
            validate_password(password)
        except ValidationError as e:
            return render(request, "register.html", {"error": "".join(e.messages)})

        try:
            user = CustomUser.objects.create_user(
                email=email, full_name=full_name, password=password
            )

        except Exception as e:
            return render(request, "register.html", {"error": "Registration failed"})

        if user:
            request.session['registered_email'] = email
            
            send_otp_email(user)
            
            return redirect("verify-otp")
        else:
            return render(request, "register.html", {"error": "Registration failed"})

class LoginView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect("overview")
        else:
            return render(request, "login.html")

    def post(self, request):
        email = request.POST.get("email")
        password = request.POST.get("password")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return render(request, "login.html", {"error": "User with the provided email does not exist"})

        user = authenticate(request, email=email, password=password)
        if user is not None:
            request.session['login_email'] = email
            
            send_otp_email(user)
            
            return redirect("verify-login")
        else:
            return render(request, "login.html", {"error": "Invalid Password"})

class LogoutView(View, LoginRequiredMixin):
    login_url = "login"
    def get(self, request):
        logout(request)
        return redirect("login")

class HomeView(View):
    def get(self, request):
        return render(request, "home.html")

class VerifyOTP(View):
    def get(self, request):
        return render(request, 'verify-otp.html')

    def post(self, request):
        otp = request.POST.get("otp").strip()
        print("otp",otp)
        email = request.session.get("registered_email")
        if email:
            try:
                user = CustomUser.objects.get(email=email)
                if is_otp_valid(user, otp):
                    user.is_email_verified = True
                    user.save()

                    if request.user.is_authenticated:
                        return redirect('profile')
                    else :
                        return redirect("login")
                else:
                    return render(request, 'verify-otp.html', {"error": "Invalid OTP. Please try again."})
            except CustomUser.DoesNotExist:
                return HttpResponse("User does not exist")
        else:
            return HttpResponse("No registered email found in session")



class VerifyOTPForLogin(View):
    def get(self,request):
        return render(request, "verify-otp.html")
    
    def post(self, request):
        otp = request.POST.get("otp".strip())
        email = request.session.get("login_email")
        if email:
            try:
                user = CustomUser.objects.get(email=email)
                if is_otp_valid(user, otp):
                    user.is_email_verified = True
                    user.save()
                    login(request, user)
                    return redirect('overview') 
                else:
                    return render(request, 'verify-otp.html', {"error": "Invalid OTP. Please try again."})
            except CustomUser.DoesNotExist:
                return HttpResponse("User does not exist")
        else:
            return HttpResponse("No login email found in session")

class ProfileView(LoginRequiredMixin, View):
    login_url = "login"
    
    def get(self, request):
        user = request.user
        login_history = UserLoginHistory.objects.filter(user=user).order_by('-timestamp')
        context = {
            'login_history': login_history,
        }
        return render(request, "profile.html", context)


class SendOTPFromProfile(View):
    def post(self, request):
        user = request.user
        if user:
            request.session['registered_email'] = user.email
            send_otp_email(user)
            return redirect("verify-otp")
        else:
            return render('profile.html', {'error':"Something went wrong :( "})


class TermsAndConditionsView(View):
    def get(self, request):
        return render(request, "terms_and_conditions.html")
    

# @org_admin_required
# @superadmin_required
# @method_decorator(org_admin_required, name='dispatch')
class BrandProtectionView(LoginRequiredMixin, View):

    # print("blob.tags ==>", blob.tags )
    # print("blob.noun_phrases =>",blob.noun_phrases )
    def get(self, request):
        return render(request, "brand-protection.html")
    
class EditNameView(LoginRequiredMixin, View):
    login_url = "login"
    def get(self, request):
        return render(request, "profile.html")
    
    def post(self, request):
        user = request.user
        full_name = request.POST.get("full_name").strip()

        if not re.match(r'^[A-Za-z\s]{3,}$', full_name):
            messages.error(request, "Full name must be at least 3 characters long and contain only alphabetic characters and spaces")
            return redirect("profile")

        if full_name:
            user.full_name = full_name
            user.save()
            messages.success(request,"Name changed successfully")
            return redirect("profile")
        else:
            messages.error(request, "Something went wrong. Please try again.")
            return redirect("profile")


class ChangePasswordView(LoginRequiredMixin, View):
    login_url = "login"
    def get(self, request):
        return render(request, "profile.html")

    def post(self, request):
        user = request.user
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        c_new_password = request.POST.get("c_new_password")

        if not user.check_password(old_password):
            messages.error(request, "Old password is incorrect.")
            return redirect("profile")

        if new_password != c_new_password:
            messages.error(request, "New passwords do not match.")
            return render(request, "profile.html")
        
        try:
            validate_password(new_password)
        except ValidationError as e:
            messages.error(request, "".join(e.messages))
            return redirect("profile")

        user.set_password(new_password)
        user.save()

        update_session_auth_hash(request, user)
        messages.success(request, "Password changed successfully.")
        return redirect("profile")


class ContactPageView(View):

    def get(self, request):
        return render(request, "contact.html")
    


class NoPermissionView(View) :
    def get(self, request):
        return HttpResponse("403 Forbidden")
    



class AdminLogin(View):
    def get(self , request):
        return render(request, "admin-login.html")
    
    def post(self, request):
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()

        if not email or not password:
            return render(request, "admin-login.html", {"error": "Email and password are required."})

        try:
            validate_email(email)
        except ValidationError:
            return render(request, "admin-login.html", {"error": "Invalid email format."})

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return render(request, "admin-login.html", {"error": "User with the provided email does not exist",'post_data': request.POST})

        user = authenticate(request, email=email, password=password)

        print("email : ", email, 'password', password, "user:", user)
        if user is not None and user.is_superuser:
            login(request, user)
            return redirect('admin-dashboard')
        else:
            return render(request, "admin-login.html", {"error": "Invalid username or password!",'post_data': request.POST})




@method_decorator(superadmin_required, name='dispatch')
class AdminDashboard(View):
    def get(self, request):
        organizations = Organization.objects.all()
        organization_count = organizations.count()
        total_user_count = CustomUser.objects.all().count()

        notifications = Notification.objects.all().order_by('-timestamp')
        notifications_length = len(notifications)
        context = {
            "organizations" : organizations,
            "org_count" : organization_count,
            "total_user_count" : total_user_count ,
            "notifications" : notifications,
            "notification_count": notifications_length
        }
        return render(request, "admin-dashboard.html", context)
    
    

@method_decorator(superadmin_required, name='dispatch')
class AdminUsers(View):
    def get(self, request):
        superadmins = CustomUser.objects.filter(is_superadmin=True)
        organizations = Organization.objects.all()
        org_admins = CustomUser.objects.filter(is_org_admin=True)
        
        normal_users = CustomUser.objects.filter(is_superadmin=False, is_org_admin=False)

        context = {
            'superadmins': superadmins,
            'org_admins': org_admins,
            'normal_users': normal_users,
            "superadmin_counts":superadmins.count(),
            "org_admin_count" : org_admins.count(),
            "normal_user_counts":normal_users.count(),
            "organizations":organizations
        }

        return render(request, "admin-users.html", context)
    
    def post(self, request):
            user_id = request.POST.get('user_id')
            user = get_object_or_404(CustomUser, id=user_id)
            new_role = request.POST.get('role')


            if request.user.id == user.id:
                messages.error(request, "You cannot change your own role.")
            elif user.is_superadmin and CustomUser.objects.filter(is_superadmin=True).count() == 1:
                messages.error(request, "There must be at least one superuser.")
            else:
                if new_role in ['org_admin', 'superuser'] and not user.is_email_verified:
                    messages.error(request, "User's email must be verified to assign this role.")
                else:
                    if new_role == 'org_admin':
                        user.is_org_admin = True
                        user.is_superadmin = False
                    elif new_role == 'superuser':
                        user.is_superadmin = True
                        user.is_org_admin = False
                    else:
                        user.is_org_admin = False
                        user.is_superadmin = False

                    user.save()
                    messages.success(request, f"User role updated to {new_role.replace('_', ' ').title()}.")
            
            user.save()
            return redirect('admin-users') 


@method_decorator(superadmin_required, name='dispatch')
class AdminDomain(View):
    def get(self, request):
        domains = Domain.objects.all()
        domain_length = len(domains)
        all_domains = [domain.name for domain in domains]
        unique_domain = set(all_domains)
        unique_domain_length = len(unique_domain)

        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
    
        if start_date :
            domains = domains.filter(breach_date__gte=start_date)
        if end_date : 
            domains = domains.filter(breach_date__lte=end_date)
        context = {
            'domains': domains, 
            'domain_length': domain_length, 
            'unique_domain_length': unique_domain_length, 
            'unique_domains': unique_domain
        }
        return render(request,"admin-domain.html", context=context)
    def post(self, request):
        if not request.user.is_superuser:
            return HttpResponse("403 Forbidden!", status=403)
        domain_id = request.POST.get('domain_id', '').strip()
        domain_name = request.POST.get('domain_name', '').strip()
        domain_ip = request.POST.get('domain_ip', '').strip()
        breach_date = request.POST.get('breach_date', '').strip()
        source_ip = request.POST.get('source_ip', '').strip()
        source_domain = request.POST.get('source_domain', '').strip()

        errors = []

        # Validation
        if not domain_name:
            errors.append("Domain name is required.")
        elif len(domain_name) > 255:
            errors.append("Domain name must be at most 255 characters long.")

        if not domain_ip:
            errors.append("Domain IP is required.")
        elif not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain_ip):
            errors.append("Invalid domain IP format.")

        if not breach_date:
            errors.append("Breach date is required.")
        # Add additional date format validation if needed

        if not source_ip:
            errors.append("Source IP is required.")
        elif not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', source_ip):
            errors.append("Invalid source IP format.")

        if not source_domain:
            errors.append("Source domain is required.")
        elif len(source_domain) > 255:
            errors.append("Source domain must be at most 255 characters long.")

        if errors:
            return render(request, 'domain.html', {'errors': errors,'post_data': request.POST})


        if domain_id:
            # Update existing domain record
            try:
                domain = Domain.objects.get(id=domain_id)
                domain.name = domain_name
                domain.domain_ip = domain_ip
                domain.breach_date = breach_date
                domain.source_ip = source_ip
                domain.source_domain = source_domain
                domain.save()
            except Domain.DoesNotExist:
                return HttpResponse("Domain not found", status=404)
        else:
            # Create new domain record
            new_domain_record = Domain(
                name=domain_name,
                domain_ip=domain_ip,
                source_domain=source_domain,
                source_ip=source_ip,
                breach_date=breach_date
            )
            new_domain_record.save()

        return redirect('admin-domain')
    
    
@method_decorator(superadmin_required, name='dispatch')
class AdminPII(View):
    def get(self, request):
        return render(request,"admin-pii.html")
    
@method_decorator(superadmin_required, name='dispatch')
class AdminBlackMarket(View):
    def get(self, request):
        return render(request,"admin-black-market.html" )

@method_decorator(superadmin_required, name='dispatch')
class AdminStealerLogs(View):
    def get(self, request):
        return render(request, "admin-stealer-logs.html")