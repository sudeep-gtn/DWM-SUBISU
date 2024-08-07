from django.urls import path
from .views import (
    RegisterView, LoginView,
    HomeView, LogoutView,
    ProfileView,
    TermsAndConditionsView,
    BrandProtectionView, EditNameView,
    ChangePasswordView, ContactPageView,
    VerifyOTP, SendOTPFromProfile, NoPermissionView, AdminLogin,AdminDashboard,AdminUsers,VerifyOTPForLogin,
    AdminDomain, AdminBlackMarket, AdminPII , AdminStealerLogs
    )

urlpatterns = [
    path('', HomeView.as_view(), name="home"),
    path('login', LoginView.as_view(), name="login"),
    path('register', RegisterView.as_view(), name="register"),
    path('logout', LogoutView.as_view(), name="logout"),
    path('profile', ProfileView.as_view(), name="profile"),
    path('terms-and-conditions', TermsAndConditionsView.as_view(), name='''terms-
         and-conditions'''),
    path('brand-protection', BrandProtectionView.as_view(), name="brand-protection"),
    path('edit-name', EditNameView.as_view(), name="edit-name"),
    path('change-password', ChangePasswordView.as_view(), name="change-password"),
    path('contact', ContactPageView.as_view(), name="contact"),
    path('verify-otp', VerifyOTP.as_view(), name="verify-otp"),
    path("verify-login", VerifyOTPForLogin.as_view(), name="verify-login"),
    path('send-otp-now', SendOTPFromProfile.as_view(), name="send-otp-now"),
    path('no_permission', NoPermissionView.as_view(), name="no_permission"),



    path("admin-login", AdminLogin.as_view(), name="admin-login"),
    path("admin-site/dashboard",AdminDashboard.as_view(), name="admin-dashboard"),
    path("admin-site/users", AdminUsers.as_view(), name="admin-users"),

    path("admin-site/compromised/domain",AdminDomain.as_view(),name="admin-domain" ),
    path("admin-site/compromised/pii",AdminPII.as_view(),name="admin-pii" ),
    path("admin-site/compromised/black-market",AdminBlackMarket.as_view(),name="admin-black-market" ),
    path("admin-site/compromised/stealer-logs",AdminStealerLogs.as_view(),name="admin-stealer-logs" ),



    ]
