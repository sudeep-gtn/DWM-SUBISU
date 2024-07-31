from html import escape
from django.shortcuts import redirect, render
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from .models import Card, Domain, BlackMarket, Notification, StealerLogs, PIIExposure, Ticket,Comment, calculate_organization_health
import json
import requests
from collections import defaultdict
from cybernews.cybernews import CyberNews
from dateutil import parser
from django.http import HttpResponse, HttpResponseBadRequest
from django.templatetags.static import static
from django.utils.dateparse import parse_date
from django.db.models import Count

from django.template.loader import render_to_string
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DetailView
from django.core.mail import send_mail
from django.conf import settings
from django.core.validators import validate_email, validate_ipv4_address
import io
from datetime import datetime
import os
import re

from django.core.exceptions import ValidationError
from django.utils.html import escape

class DashboardView(LoginRequiredMixin, View):
    login_url = "login"

    def get(self, request):
        domains_count = Domain.objects.count()
        cards_count = Card.objects.count()
        pii_exposures_count = PIIExposure.objects.count()
        stealer_logs_count = StealerLogs.objects.count()

        health_score = calculate_organization_health()

        context = {
            'domains_count': domains_count,
            'cards_count': cards_count,
            'pii_exposures_count': pii_exposures_count,
            'stealer_logs_count': stealer_logs_count,
            'health_score': health_score
        }

        return render(request, "dashboard.html", context)

class DomainView(LoginRequiredMixin, View):
    login_url = "login"
    
    def get(self, request):
        # Domain.objects.create(
        #     name='example.com',
        #     domain_ip='192.168.1.1',
        #     source_ip='10.0.0.1',
        #     source_domain='example-source.com',
        #     breach_date='2024-03-10'
        # )

        # Domain.objects.create(
        #     name='testsite.org',
        #     domain_ip='172.16.0.1',
        #     source_ip='192.168.0.1',
        #     source_domain='testsite-source.org',
        #     breach_date='2023-11-05'
        # )

        # Domain.objects.create(
        #     name='mywebsite.net',
        #     domain_ip='203.0.113.1',
        #     source_ip='198.51.100.1',
        #     source_domain='mywebsite-source.net',
        #     breach_date='2024-02-20'
        # )

        # Domain.objects.create(
        #     name='anothersite.io',
        #     domain_ip='198.51.100.2',
        #     source_ip='203.0.113.2',
        #     source_domain='anothersite-source.io',
        #     breach_date='2024-01-15'
        # )

        # Domain.objects.create(
        #     name='sampledomain.edu',
        #     domain_ip='203.0.113.3',
        #     source_ip='198.51.100.3',
        #     source_domain='sampledomain-source.edu',
        #     breach_date='2024-05-18'
        # )

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
        print("start date : ", start_date , "end date : ", end_date)
        
        leak_sources = {}
        for domain_obj in domains:
            name = domain_obj.name
            source_domain = domain_obj.source_domain
            if name not in leak_sources:
                leak_sources[name] = []

            domain_exists = next((item for item in leak_sources[name] if item["domain"] == source_domain), None)
            if domain_exists:
                domain_exists["count"] += 1
            else:
                leak_sources[name].append({"count": 1, "domain": source_domain})
        
        leak_sources_json = json.dumps(leak_sources)

        return render(request, "domain.html", {'domains': domains, 'domain_length': domain_length, 'unique_domain_length': unique_domain_length, 'unique_domains': unique_domain, 'leak_sources_json': leak_sources_json})

    def post(self, request):
        if not request.user.is_superuser:
            return HttpResponse("403 Forbidden!", status=403)

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


        # Create and save the new domain record
        new_domain_record = Domain(
            name=domain_name,
            domain_ip=domain_ip,
            source_domain=source_domain,
            source_ip=source_ip,
            breach_date=breach_date
        )
        new_domain_record.save()

        return redirect('domain')
        
        
    
class CardsView(LoginRequiredMixin, View):
    login_url = "login"
    
    def get(self, request):

        # Card.objects.create(
        #     card_bin_number=123456,
        #     card_type='Visa',
        #     expiry_date='2025-12-31',
        #     cvv=123,
        #     card_holder_name='John Doe',
        #     issuing_bank='Bank of America',
        #     breach_date='2024-01-15',
        #     breach_source='Data Breach XYZ',
        #     last_used_date='2024-05-20',
        #     breach_source_domain='xyzbreach.com'
        # )

        # Card.objects.create(
        #     card_bin_number=654321,
        #     card_type='MasterCard',
        #     expiry_date='2023-07-31',
        #     cvv=321,
        #     card_holder_name='Jane Smith',
        #     issuing_bank='Chase Bank',
        #     breach_date='2023-02-10',
        #     breach_source='Data Breach ABC',
        #     last_used_date='2023-06-15',
        #     breach_source_domain='abcbreach.net'
        # )

        # Card.objects.create(
        #     card_bin_number=111111,
        #     card_type='American Express',
        #     expiry_date='2024-09-30',
        #     cvv=456,
        #     card_holder_name='Alice Johnson',
        #     issuing_bank='Wells Fargo',
        #     breach_date='2024-04-22',
        #     breach_source='Data Breach 123',
        #     last_used_date='2024-05-01',
        #     breach_source_domain='123breach.com'
        # )

        # Card.objects.create(
        #     card_bin_number=222222,
        #     card_type='Discover',
        #     expiry_date='2026-03-31',
        #     cvv=789,
        #     card_holder_name='Bob Brown',
        #     issuing_bank='Citi Bank',
        #     breach_date='2024-06-15',
        #     breach_source='Data Breach 456',
        #     last_used_date='2024-06-20',
        #     breach_source_domain='456breach.com'
        # )

        # Card.objects.create(
        #     card_bin_number=333333,
        #     card_type='Visa',
        #     expiry_date='2023-11-30',
        #     cvv=101,
        #     card_holder_name='Carol White',
        #     issuing_bank='HSBC',
        #     breach_date='2023-12-01',
        #     breach_source='Data Breach 789',
        #     last_used_date='2023-12-10',
        #     breach_source_domain='789breach.com'
        # )

        cards = Card.objects.all()
        card_length = len(cards)
        card_bin_numbers = [card.card_bin_number for card in cards]
        unique_card_bin_numbers = set(card_bin_numbers)
        unique_card_length = len(unique_card_bin_numbers)
        
        reversed_leak_sources = {}
        for card in cards:
            bin_number = card.card_bin_number
            domain = card.breach_source_domain
            if domain not in reversed_leak_sources:
                reversed_leak_sources[domain] = []
            bin_exists = next((item for item in reversed_leak_sources[domain] if item["bin_number"] == bin_number), None)
            if bin_exists:
                bin_exists["count"] += 1
            else:
                reversed_leak_sources[domain].append({"count": 1, "bin_number": bin_number})
        
        reversed_leak_sources_json = json.dumps(reversed_leak_sources)

        return render(request, "cards.html", {
            'cards': cards,
            'card_length': card_length,
            'unique_card_length': unique_card_length,
            'unique_card_bin_numbers': unique_card_bin_numbers,
            'reversed_leak_sources_json': reversed_leak_sources_json
        })

class EmailView(LoginRequiredMixin, View):
    login_url = "login"
    def get(self,request):
        return render(request, "email.html")
    
class OrganizationDetailsView(LoginRequiredMixin, View):
    login_url = "login"
    def get(self, request):
        return render(request, "organization-details.html")

class NotificationsAlertView(LoginRequiredMixin, View):
    login_url = "login"
    
    def get(self, request):    
        notifications = Notification.objects.all().order_by('-timestamp')
        notifications_length = len(notifications)
        return render(request, 'notificationsAlert.html', {'notifications': notifications, 'notifications_length': notifications_length})
 

class BlackMarketView(LoginRequiredMixin, View):
    login_url = "login"
    def get(self, request):

        # BlackMarket.objects.create(
        #     source='DarkWeb Market A',
        #     stealer_log_preview='Preview of stolen data...',
        #     related_assets='Credit cards, PII',
        #     price=199.99,
        #     status='Available',
        #     obtain_progress='10% completed',
        #     discovery_date='2024-04-22',
        #     incident='Incident 1234'
        # )

        # BlackMarket.objects.create(
        #     source='DarkWeb Market B',
        #     stealer_log_preview='Preview of different stolen data...',
        #     related_assets='Bank account details, SSNs',
        #     price=299.99,
        #     status='Sold',
        #     obtain_progress='100% completed',
        #     discovery_date='2023-10-10',
        #     incident='Incident 5678'
        # )

        # BlackMarket.objects.create(
        #     source='Black Market C',
        #     stealer_log_preview='Preview of more stolen data...',
        #     related_assets='Passwords, Usernames',
        #     price=399.99,
        #     status='Unavailable',
        #     obtain_progress='50% completed',
        #     discovery_date='2024-03-15',
        #     incident='Incident 9101'
        # )

        # BlackMarket.objects.create(
        #     source='DarkWeb Market D',
        #     stealer_log_preview='Another preview of stolen data...',
        #     related_assets='Credit reports, Addresses',
        #     price=149.99,
        #     status='Available',
        #     obtain_progress='70% completed',
        #     discovery_date='2024-02-28',
        #     incident='Incident 1121'
        # )

        # BlackMarket.objects.create(
        #     source='DarkWeb Market E',
        #     stealer_log_preview='Preview of various stolen data...',
        #     related_assets='Emails, Phone numbers',
        #     price=99.99,
        #     status='Sold',
        #     obtain_progress='90% completed',
        #     discovery_date='2024-01-10',
        #     incident='Incident 3141'
        # )
        
        

        black_market_data = BlackMarket.objects.all()
        
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
    
        if start_date :
            black_market_data = black_market_data.filter(discovery_date__gte=start_date)
        if end_date : 
            black_market_data = black_market_data.filter(discovery_date__lte=end_date)
        print("start date : ", start_date , "end date : ", end_date)
        
        return render(request, "black_market.html",{'black_market_datas': black_market_data})
    
    def post(self, request):
        if not request.user.is_superuser:
            return HttpResponse("403 Forbidden", status=403)
        bm_source = escape(request.POST.get("source")).strip()
        stealer_log_preview = escape(request.POST.get("log_preview")).strip()
        bm_related_assets = escape(request.POST.get('related_assets')).strip()
        bm_price = escape(request.POST.get('price')).strip()
        bm_status = escape(request.POST.get("status")).strip()
        bm_obtain_progress = escape(request.POST.get("obtain_progress")).strip()
        bm_discovery_date = escape(request.POST.get("discovery_date")).strip()
        bm_incident = escape(request.POST.get("incident")).strip()

        # Custom validation
        errors = []
        try:
            if not bm_source:
                errors.append("Source is required.")
            if not stealer_log_preview:
                errors.append("Log preview is required.")
            if not bm_related_assets:
                errors.append("Related assets are required.")
            if not bm_price or not bm_price.isnumeric():
                errors.append("Price is required and must be numeric.")
            if not bm_status:
                errors.append("Status is required.")
            if not bm_obtain_progress or not bm_obtain_progress.isnumeric():
                errors.append("Obtain progress is required and must be numeric.")
            else:
                bm_obtain_progress = int(bm_obtain_progress)
                if not 1 <= bm_obtain_progress <= 100:
                    errors.append("Obtain progress must be between 1 and 100.")
            if not bm_discovery_date:
                errors.append("Discovery date is required.")
            if not bm_incident:
                errors.append("Incident is required.")
        except ValidationError as e:
            errors.append(e.message)

        if errors:
            # Handle the errors appropriately, e.g., render them in the template
            return render(request, 'black_market.html', {'errors': errors,'post_data': request.POST})

        new_blackmarket_record = BlackMarket(
            source=bm_source,
            stealer_log_preview=stealer_log_preview,
            related_assets=bm_related_assets,
            price=bm_price,
            status=bm_status,
            obtain_progress=bm_obtain_progress,
            discovery_date=bm_discovery_date,
            incident=bm_incident,
        )
        new_blackmarket_record.save()
        return redirect('black-market')
    
class StealerLogsView(LoginRequiredMixin, View):
    login_url = "login"
    def get(self, request):
        # StealerLogs.objects.create(
        #     date_detected='2024-01-05',
        #     data_type='Credit Card Information',
        #     source='Malware XYZ',
        #     details='Details of the stolen data...'
        # )

        # StealerLogs.objects.create(
        #     date_detected='2023-08-12',
        #     data_type='Personal Identifiable Information',
        #     source='Spyware ABC',
        #     details='Details of the stolen PII...'
        # )

        # StealerLogs.objects.create(
        #     date_detected='2024-02-18',
        #     data_type='Bank Account Information',
        #     source='Malware DEF',
        #     details='Details of the stolen bank account information...'
        # )

        # StealerLogs.objects.create(
        #     date_detected='2023-09-25',
        #     data_type='Social Security Numbers',
        #     source='Spyware GHI',
        #     details='Details of the stolen SSNs...'
        # )

        # StealerLogs.objects.create(
        #     date_detected='2024-03-10',
        #     data_type='Email Addresses',
        #     source='Malware JKL',
        #     details='Details of the stolen email addresses...'
        # )

        stealer_logs = StealerLogs.objects.all()
        total_stealer_log_counts = stealer_logs.count()
        
        
        year = int(request.GET.get('year', datetime.now().year))
        print("year => ",year)

        # Query to count logs per month for the selected year
        logs_per_month = (
            StealerLogs.objects.filter(date_detected__year=year)
            .values('date_detected__month')
            .annotate(count=Count('log_id'))
            .order_by('date_detected__month')
        )

        print("logs per month :", logs_per_month)
        # Prepare data for rendering
        months = list(range(1, 13))
        counts = [0] * 12
        for log in logs_per_month:
            month = log['date_detected__month']
            counts[month - 1] = log['count']

        
        years = range(2023, datetime.now().year + 1)
        counts_json = json.dumps(counts)
        context = {
            'months': months,
            'selected_year': year,
            'years': years,
            'selected_year': year 
        }
        print("counts:", counts)
        
        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")
    
        if start_date :
            stealer_logs = stealer_logs.filter(date_detected__gte=start_date)
        if end_date : 
            stealer_logs = stealer_logs.filter(date_detected__lte=end_date)
        return render(request, "stealer-logs.html",{'counts_json': counts_json,'stealer_logs': stealer_logs,'context':context, 'stealer_log_counts':total_stealer_log_counts})

    def post(self, request):
        if not request.user.is_superadmin:
            return HttpResponse("403 Forbidden. Access strictly denied.", status=403)
        errors = []
        post_data = {}

        post_data['date_detected'] = request.POST.get('date_detected', '').strip()
        post_data['data_type'] = request.POST.get('data_type', '').strip()
        post_data['source'] = request.POST.get('source', '').strip()
        post_data['details'] = request.POST.get('details', '').strip()

        # Validation
        if not post_data['date_detected']:
            errors.append("Date detected is required.")
        if not post_data['data_type']:
            errors.append("Data type is required.")
        elif len(post_data['data_type']) > 100:
            errors.append("Data type must be at most 100 characters long.")
        if not post_data['source']:
            errors.append("Source is required.")
        elif len(post_data['source']) > 100:
            errors.append("Source must be at most 100 characters long.")
        if not post_data['details']:
            errors.append("Details are required.")
        elif len(post_data['details']) > 500:
            errors.append("Details must be at most 500 characters long.")

        if errors:
            return render(request, 'stealer-logs.html', {'post_data': post_data, 'errors': errors})

        new_stealer_log = StealerLogs(
            date_detected=post_data['date_detected'],
            data_type=post_data['data_type'],
            source=post_data['source'],
            details=post_data['details']
        )
        new_stealer_log.save()
        return redirect('stealer-logs')
        
class PiiExposureView(LoginRequiredMixin, View):
    login_url = "login"

    def get(self, request):

        # PIIExposure.objects.create(
        #     name='John Doe',
        #     breach_date='2024-02-28',
        #     breach_ip='203.0.113.1',
        #     source_domain='breach-source.com',
        #     threat_type='Data Leak',
        #     type_of_data='Email, Phone Number',
        #     source='Breach Report XYZ',
        #     personal_email='john.doe@example.com',
        #     phone='+1234567890'
        # )

        # PIIExposure.objects.create(
        #     name='Jane Smith',
        #     breach_date='2023-09-15',
        #     breach_ip='198.51.100.2',
        #     source_domain='another-breach-source.net',
        #     threat_type='Unauthorized Access',
        #     type_of_data='SSN, Address',
        #     source='Breach Report ABC',
        #     personal_email='jane.smith@example.com',
        #     phone='+0987654321'
        # )

        # PIIExposure.objects.create(
        #     name='Alice Johnson',
        #     breach_date='2024-01-05',
        #     breach_ip='192.0.2.1',
        #     source_domain='third-breach-source.com',
        #     threat_type='Credential Theft',
        #     type_of_data='Username, Password',
        #     source='Breach Report 123',
        #     personal_email='alice.johnson@example.com',
        #     phone='+1123456789'
        # )

        # PIIExposure.objects.create(
        #     name='Bob Brown',
        #     breach_date='2023-08-25',
        #     breach_ip='198.51.100.3',
        #     source_domain='fourth-breach-source.net',
        #     threat_type='Phishing Attack',
        #     type_of_data='Bank Account, Routing Number',
        #     source='Breach Report 456',
        #     personal_email='bob.brown@example.com',
        #     phone='+2212345678'
        # )

        # PIIExposure.objects.create(
        #     name='Carol White',
        #     breach_date='2023-12-30',
        #     breach_ip='203.0.113.2',
        #     source_domain='fifth-breach-source.org',
        #     threat_type='Ransomware',
        #     type_of_data='PII, Financial Data',
        #     source='Breach Report 789',
        #     personal_email='carol.white@example.com',
        #     phone='+3321234567'
        # )


        pii_exposures = PIIExposure.objects.all()

        pii_exposures_length = pii_exposures.count()

        pii_exposures_emails = [pii_exposure.personal_email for pii_exposure in pii_exposures]
        unique_pii_exposures_emails = set(pii_exposures_emails)
        unique_pii_exposures_length = len(unique_pii_exposures_emails)

        leak_sources = {}
        for pii_exposure in pii_exposures:
            email = pii_exposure.personal_email
            domain = pii_exposure.source_domain
            if email not in leak_sources:
                leak_sources[email] = []

            domain_exists = next((item for item in leak_sources[email] if item["domain"] == domain), None)
            if domain_exists:
                domain_exists["count"] += 1
            else:
                leak_sources[email].append({"count": 1, "domain": domain})
        
        leak_sources_json = json.dumps(leak_sources)

        start_date = request.GET.get("start_date")
        end_date = request.GET.get("end_date")

        if start_date :
            pii_exposures = pii_exposures.filter(breach_date__gte=start_date)
        if end_date : 
            pii_exposures = pii_exposures.filter(breach_date__lte=end_date)


        return render(request, "pii-exposure.html", {
            'pii_exposures': pii_exposures,
            'pii_exposures_length': pii_exposures_length,
            'unique_pii_exposures_length': unique_pii_exposures_length,
            'unique_pii_exposures_emails': unique_pii_exposures_emails,
            'leak_sources_json': leak_sources_json
        })
        
    def post(self, request):
        if request.user.is_superuser:
            errors = []
            post_data = {}
            post_data['name'] = request.POST.get('name').strip()
            post_data['email'] = request.POST.get('email').strip()
            post_data['phone_number'] = request.POST.get('phone_number').strip()
            post_data['breach_date'] = request.POST.get('breach_date').strip()
            post_data['source_domain'] = request.POST.get('source_domain').strip()
            post_data['source_ip'] = request.POST.get('source_ip').strip()
            post_data['data_type'] = request.POST.get('data_type').strip()
            post_data['threat_type'] = request.POST.get('threat_type').strip()
            post_data['leak_source'] = request.POST.get('leak_source').strip()

            try:
                validate_email(post_data['email'])
            except ValidationError:
                errors.append("Invalid email format.")

            if not post_data['phone_number'].isdigit():
                errors.append("Phone number must contain only digits.")

            try:
                validate_ipv4_address(post_data['source_ip'])
            except ValidationError:
                errors.append("Invalid IP address format.")

            if errors:
                return render(request, 'pii-exposure.html', {'post_data': post_data, 'errors': errors})


            new_blackmarket_record = BlackMarket(
                name=post_data['name'],
                email=post_data['email'],
                phone_number=post_data['phone_number'],
                breach_date=post_data['breach_date'],
                source_domain=post_data['source_domain'],
                source_ip=post_data['source_ip'],
                data_type=post_data['data_type'],
                threat_type=post_data['threat_type'],
                leak_source=post_data['leak_source']
            )
            new_blackmarket_record.save()

            return redirect('pii-exposure')
        
        else :
            return HttpResponse("403 Permission strictly denied ! ")


class Overview(LoginRequiredMixin, View):
    login_url = "login"
    def get(self, request):
        health_score = calculate_organization_health()
        context = {
            'health_score': health_score
        }
        return render(request, "overview.html", context)
        




'''
<------------- threat intelligenece ---------->
'''
class ThreatIntelligence(LoginRequiredMixin, View):
    login_url = "login"

    def get(self, request):
        news = CyberNews()
        malware_news = news.get_news('malware')
        
        news_data = malware_news
        for news_item in news_data:
            try:
                news_item['newsDate'] = parser.parse(news_item['newsDate']).date()
            except ValueError:
                print("The date is not in correct date format")
                news_item['newsDate'] = None
        
        news_data = [item for item in news_data if item['newsDate'] is not None]
        news_data_sorted = sorted(news_data, key=lambda x: x['newsDate'], reverse=True)
        
        return render(request, "threatIntelligence.html", {'news_data_sorted': news_data_sorted}) 
    


class FetchThreatIntelligenceData(LoginRequiredMixin, View):
    login_url = "login"

    def get(self, request):
        url = 'https://api.any.run/v1/feeds/stix.json?IP=true&Domain=true&URL=true'
        token = 'WX2JCzLFjmaRXaQHFhLfbfn5EHdwxCmbBpY8tQ78'

        headers = {
            'Accept': '*/*',
            'Authorization': f'API-Key {token}',
            'Content-Type': 'application/json'
        }

        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return JsonResponse({'error': 'Error fetching the API', 'details': response.text}, status=response.status_code)

        context = response.json()

        types = defaultdict(int)
        for obj in context["data"]["objects"]:
            types[obj["type"]] += 1
        
        context["types"] = sorted(types.keys())
        return JsonResponse(context)
class ThreatActor(LoginRequiredMixin, View):
    login_url = "login"
    
    def get(self, request):
        # url = "https://api.feedly.com/v3/entities/nlp%2Ff%2Fentity%2Fgz%3Ata%3A68391641-859f-4a9a-9a1e-3e5cf71ec376"

        # headers = {
        #     "accept": "application/json",
        #     "Authorization": "Bearer 68391641-859f-4a9a-9a1e-3e5cf71ec376"
        # }
        # response = requests.get(url, headers=headers)
     
        # if response.status_code != 200:
        #     context = {'error': 'Error fetching the API', 'details': response.text}
        # else:
        #     context = {'data': response.json()}

        return render(request, "threatActorProfile.html")

class IncidentResponse(LoginRequiredMixin, View):
    login_url = "login"

    def get(self, request):
        user = request.user
        if user.is_superadmin or user.is_org_admin:
            open_tickets = Ticket.objects.filter(resolved=False).order_by('-created_at')
            closed_tickets = Ticket.objects.filter(resolved=True).order_by('-created_at')
        else:
            open_tickets = Ticket.objects.filter(user=user, resolved=False).order_by('-created_at')
            closed_tickets = Ticket.objects.filter(user=user, resolved=True).order_by('-created_at')
        
        ticket_count = open_tickets.count() + closed_tickets.count()
        print("ticket count " , ticket_count)
        # Display up to 3 open tickets and up to 6 closed tickets
        open_tickets = open_tickets[:3]
        closed_tickets = closed_tickets[:6]
        
        # Combine the open and closed tickets
        tickets = list(open_tickets) + list(closed_tickets)

        return render(request, 'incidentResponse.html', {'tickets': tickets, 'ticket_count': ticket_count})
    def post(self, request):
        ticket_title = request.POST.get('ticket_title')
        ticket_description = request.POST.get('ticket_description')
        image_file = request.FILES.get('image')
        
        new_ticket = Ticket(
            ticket_title=ticket_title,
            ticket_description=ticket_description,
            image=image_file,
            user = request.user
            )
        new_ticket.save()
        admin_email = settings.ADMIN_EMAIL
        subject = f'New Ticket Created: {ticket_title}'
        message = f'A new ticket has been created by { request.user.full_name}.\n\nTitle: {ticket_title}\n\nDescription: {ticket_description}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [admin_email]
        if not request.user.is_superuser and not request.user.is_org_admin: 
            send_mail(subject, message, from_email, recipient_list)
        return redirect('incident-response')
    
class AnalyticsAndReports(LoginRequiredMixin, View):
    login_url = "login"

    def get(self, request):
        breach_dates = ['2023-01-15', '2023-02-10', '2023-03-05', '2023-04-25', '2023-05-12', '2023-06-08']
        breach_counts = [1, 2, 1, 1, 1, 2]
        context = {
            'breach_dates': breach_dates,
            'breach_counts': breach_counts,
        }        
        return render( request,'analyticsAndReports.html', {'context':context})

class LiveThreatMap(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, "liveThreatMap.html")
    


class GenerateReportView(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'report_template.html')


    def link_callback(uri, rel):
        """
        Convert HTML URIs to absolute system paths so xhtml2pdf can access those resources.
        """
        # Use Django's staticfiles finders to locate the file
        sUrl = settings.STATIC_URL                # Typically /static/
        sRoot = settings.STATIC_ROOT          # Typically /home/userX/project_static/
        mUrl = settings.MEDIA_URL             # Typically /media/
        mRoot = settings.MEDIA_ROOT       # Typically /home/userX/project_static/media/
        bRoot = settings.BASE_DIR              # Project's base directory
        if uri.startswith(mUrl):
            path = os.path.join(mRoot, uri.replace(mUrl, ""))
        elif uri.startswith(sUrl):
            path = os.path.join(sRoot, uri.replace(sUrl, ""))
        else:
            return os.path.join(bRoot, '../', uri)

        # make sure that file exists
        if not os.path.isfile(path):
            raise Exception(
                'media URI must start with %s or %s' % (sUrl, mUrl)
            )
        return path

    def post(self, request, *args, **kwargs):
        filters = request.POST.getlist('filters')
        date_from = request.POST.get('date_from')
        date_to = request.POST.get('date_to') 

        date_from = datetime.strptime(date_from, '%Y-%m-%d') if date_from else None
        date_to = datetime.strptime(date_to, '%Y-%m-%d') if date_to else None

        print('filters: ', filters)
        print("date from ", date_from, "date to ", date_to)
        
        domains = []
        cards = []
        pii = []
        stealer_logs = []
        black_market = []
        tickets = []


        # Fetch data from the database
        if 'domain-leaks' in filters:
            domains = Domain.objects.all()
            if date_from and date_to:
                domains = domains.filter(breach_date__range=(date_from, date_to))
        if 'card-leaks' in filters:
            cards = Card.objects.all()
            if date_from and date_to:
                cards = cards.filter(breach_date__range=(date_from, date_to))
        if 'pii-leaks' in filters:
            pii = PIIExposure.objects.all()
            if date_from and date_to:
                pii = pii.filter(breach_date__range=(date_from, date_to))
            
        if 'stealer_logs' in filters:
            stealer_logs = StealerLogs.objects.all()
            if date_from and date_to:
                stealer_logs = stealer_logs.filter(date_detected__range=(date_from, date_to))
            
        if 'black_market' in filters:
            black_market = BlackMarket.objects.all()
            if date_from and date_to:
                black_market = black_market.filter(discovery_date__range=(date_from, date_to))
        if 'tickets' in filters : 
            tickets = Ticket.objects.all()
            if date_from and date_to : 
                tickets = tickets.filter(discovery_date__range=(date_from, date_to))

        # print("domain with filter: ", domains)
        # print("cards with filter: ", cards)
        # print("pii with filter: ", pii)
        print("Tickets : " ,tickets)
        context = {
            'domains': domains,
            'cards': cards,
            'pii': pii,
            'stealer_log':stealer_logs,
            'black_market': black_market , 
            'tickets' : tickets
        }
        
    #     html_string = html_string.replace(
    #     '{% static \'images/logo-green1.png\' %}', escape(static('images/logo-green1.png'))
    # )
        # pdf = HTML(string=html_string).write_pdf()

        # response = HttpResponse(pdf, content_type='application/pdf')
        # response['Content-Disposition'] = 'attachment; filename="report.pdf"'

        html_string = render_to_string('report_template.html', context)
        result = io.BytesIO()
        pdf = pisa.pisaDocument(io.BytesIO(html_string.encode("UTF-8")), result, link_callback=GenerateReportView.link_callback)
        if not pdf.err:
            return HttpResponse(result.getvalue(), content_type='application/pdf')
        return HttpResponse('We had some errors <pre>' + escape(html_string) + '</pre>')   
        # return response

        '''
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'attachment; filename="dwm-report.pdf"'
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)

        elements = []

        # Add logo
        logo_path = 'static/images/logo-green1.png'
        # logo_path = os.path.join(settings.STATIC_URL, 'images/logo.png')
        logo = Image(logo_path, width=100, height=50)
        logo.hAlign = 'RIGHT'
        elements.append(logo)

        # Title and subtitle
        styles = getSampleStyleSheet()
        title = Paragraph("DWM Report", styles['Title'])
        elements.append(title)
        subtitle = Paragraph(f"Filters: {', '.join(filters)}<br/>Date Range: {date_from} to {date_to}", styles['Normal'])
        subtitle.height = '50'
        elements.append(subtitle)

        def add_table(title, data, columns):
            elements.append(Spacer(1, 12))
            table_title = Paragraph(title, styles['Heading2'])
            data_counts = Paragraph(f"Total findings : {len(data)}")
            elements.append(table_title)

            elements.append(data_counts)
            table_data = [columns]
            for item in data:
                table_data.append([getattr(item, col) for col in columns])
            table = Table(table_data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                # ('WORDWRAP', (0, 0), (-1, -1), 'CJK'),
            ]))
            elements.append(table)

        # Add tables for each entity
        if domains:
            add_table("Domains", domains, ['name', 'domain_ip', 'source_ip', 'source_domain', 'posted_date', 'breach_date']) 
        if cards:
            add_table("Cards", cards, ['card_bin_number', 'card_type', 'expiry_date', 'cvv', 'card_holder_name', 'issuing_bank', 'breach_date', 'posted_date', 'breach_source', 'last_used_date', 'breach_source_domain'])

        if pii:
            add_table("PII Leaks", pii, ['name', 'breach_date', 'breach_ip', 'source_domain', 'threat_type', 'type_of_data', 'source', 'personal_email', 'phone'])

        if stealer_logs:
            add_table("Stealer Logs", stealer_logs, ['log_id', 'date_detected', 'data_type', 'source', 'details'])

        if black_market:
            add_table("Black Market", black_market, ['source', 'stealer_log_preview', 'related_assets', 'price', 'status', 'obtain_progress', 'discovery_date', 'incident'])

        doc.build(elements)
        pdf = buffer.getvalue()
        buffer.close()
        response.write(pdf)
        '''
        # Convert the rendered HTML to PDF
       
    
    # def generate_pdf(self, html_string):
    #     result = io.BytesIO()
    #     pdf = pisa.CreatePDF(io.StringIO(html_string), dest=result)
    #     if pdf.err:
    #         return None
    #     return result.getvalue()


class PreviewReportView(View):
    def get(self, request, *args, **kwargs):
        filters = request.GET.getlist('filters')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')

        date_from = datetime.strptime(date_from, '%Y-%m-%d') if date_from else None
        date_to = datetime.strptime(date_to, '%Y-%m-%d') if date_to else None

        print('filters: ', filters)
        print("date from ", date_from, "date to ", date_to)
        
        domains = []
        cards = []
        pii = []
        black_market = []
        stealer_log = []
        tickets = []
        # Fetch data from the database
        if 'domain-leaks' in filters:
            domains = Domain.objects.all()
            if date_from and date_to:
                domains = domains.filter(breach_date__range=(date_from, date_to))
        if 'card-leaks' in filters:
            cards = Card.objects.all()
            if date_from and date_to:
                cards = cards.filter(breach_date__range=(date_from, date_to))
        if 'pii-leaks' in filters:
            pii = PIIExposure.objects.all()
            if date_from and date_to:
                pii = pii.filter(breach_date__range=(date_from, date_to))


        if 'stealer_log' in filters:
            stealer_log = StealerLogs.objects.all()
            # if date_from and date_to:
            #     stealer_log = stealer_log.filter(date_detected__range=(date_from, date_to))
            
        if 'black_market' in filters:
            black_market = BlackMarket.objects.all()
            # if date_from and date_to:
            #     black_market = black_market.filter(discovery_date__range=(date_from, date_to))
            
        if 'tickets' in filters : 
            tickets = Ticket.objects.all()
            if date_from and date_to : 
                tickets = tickets.filter(created_at__range=(date_from, date_to))

        print("domain with filter: ", domains)
        print("cards with filter: ", cards)
        print("pii with filter: ", pii)
        print("balck ", black_market )
        print("Stealer:", stealer_log)
        context = {
            'domains': domains,
            'cards': cards,
            'pii': pii,
            'black_market':black_market,
            'stealer_log':stealer_log,
            'tickets':tickets
        }

        # Render the template for preview
        return render(request, 'report_template.html', context)
    
    
class TicketsView(View):
    
    def post(self, request, *args, **kwargs):
        ticket_id = kwargs.get('ticket_id')
        try:
            ticket = Ticket.objects.get(ticket_id=ticket_id)
        except Ticket.DoesNotExist:
            return HttpResponseBadRequest("Invalid Ticket ID")
        
        ticket.resolved = True
        ticket.resolved_date = datetime.now()

        ticket.save()
        return redirect('incident-response')


# class TicketDetailView(View):
#     model = Ticket
#     template_name = 'ticket_details.html'
#     context_object_name = 'ticket'

#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['comments'] = Comment.objects.filter(ticket=self.get_object()).order_by('-created_at')
#         # context['form'] = CommentForm()
#         return context

# details about a specfic ticket, includes comments 
class TicketDetailView(DetailView):
    model = Ticket
    template_name = 'ticket_details.html'
    context_object_name = 'ticket'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['comments'] = Comment.objects.filter(ticket=self.get_object()).order_by('created_at')

        # print("Context : ", context)
        return context
class AllTickets(LoginRequiredMixin, View):
    login_url = 'login'
    
    def get(self, request):
        user = request.user
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if user.is_superadmin or user.is_org_admin:
            open_tickets = Ticket.objects.filter(resolved=False).order_by('-created_at')
            closed_tickets = Ticket.objects.filter(resolved=True).order_by('-created_at')
        else:
            open_tickets = Ticket.objects.filter(user=user, resolved=False).order_by('-created_at')
            closed_tickets = Ticket.objects.filter(user=user, resolved=True).order_by('-created_at')
        
        if start_date:
            start_date_parsed = parse_date(start_date)
            open_tickets = open_tickets.filter(created_at__gte=start_date_parsed)
            closed_tickets = closed_tickets.filter(created_at__gte=start_date_parsed)
        
        if end_date:
            end_date_parsed = parse_date(end_date)
            open_tickets = open_tickets.filter(created_at__lte=end_date_parsed)
            closed_tickets = closed_tickets.filter(created_at__lte=end_date_parsed)

        ticket_count = open_tickets.count() + closed_tickets.count()
        tickets = list(open_tickets) + list(closed_tickets)
        open_tickets = list(open_tickets)
        closed_tickets = list(closed_tickets)
        
        return render(request, 'allTickets.html', {'tickets': tickets, 'ticket_count': ticket_count, 'open_tickets':open_tickets, 'closed_tickets':closed_tickets})




# class AddCommentView(LoginRequiredMixin, View):
#     def post(self, request, pk):
#         ticket = get_object_or_404(Ticket, pk=pk)
#         comment_text = request.POST.get('comment')
        
#         if comment_text:
#             new_comment = Comment.objects.create(ticket=ticket, author=request.user, text=comment_text)
#             data = {
#                 'author': new_comment.author.email,
#                 'text': new_comment.text,
#                 'created_at': new_comment.created_at.strftime('%Y-%m-%d %H:%M:%S'),
#             }
#             print("Data :  ", data)
#             return JsonResponse({'comment': data})
#         else:
#             return JsonResponse({'error': 'Comment text is required'}, status=400)


class AddCommentView(LoginRequiredMixin, View):
    def post(self, request, pk):
        ticket = get_object_or_404(Ticket, pk=pk)
        comment_text = request.POST.get('comment')
        if comment_text:
            Comment.objects.create(ticket=ticket, author=request.user, text=comment_text)
        return redirect('ticket_details', pk=pk)


class SupportAndAssistance(LoginRequiredMixin,View):
    login_url = 'login'
    def get(self, request):
        return render(request,'support-and-assistance.html')
    
class TermsAndConditions(View):
    def get(self, request):
        return render(request, 'terms_and_conditions.html')