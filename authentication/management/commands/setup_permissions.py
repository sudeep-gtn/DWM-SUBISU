from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission


class Command(BaseCommand):
    help = 'Set up initial groups and permissions'

    def handle(self, *args, **kwargs):
        superadmin_group, created = Group.objects.get_or_create(name='Superadmin')
        org_admin_group, created = Group.objects.get_or_create(name='Org Admin')
        end_user_group, created = Group.objects.get_or_create(name='End User')

        # Example of assigning permissions (customize this based on your needs)
        # Can use Permission model to assign specific permissions
        # Example:
        # permission = Permission.objects.get(codename='some_permission')
        # superadmin_group.permissions.add(permission)
        
        self.stdout.write(self.style.SUCCESS('Successfully created groups and assigned permissions'))