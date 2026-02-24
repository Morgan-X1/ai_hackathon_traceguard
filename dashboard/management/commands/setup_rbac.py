"""
Django management command to set up RBAC roles and groups.
Usage: python manage.py setup_rbac
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from dashboard.models import Transaction, AuditTrail, UserProfile


class Command(BaseCommand):
    help = 'Set up Role-Based Access Control groups and permissions for TraceGuard AI'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Setting up RBAC groups and permissions...'))
        
        # Get content types
        transaction_ct = ContentType.objects.get_for_model(Transaction)
        audit_ct = ContentType.objects.get_for_model(AuditTrail)
        profile_ct = ContentType.objects.get_for_model(UserProfile)
        
        # Create or get groups
        analyst_group, created = Group.objects.get_or_create(name='Analyst')
        if created:
            self.stdout.write(self.style.SUCCESS('✓ Created Analyst group'))
        else:
            self.stdout.write('  Analyst group already exists')
        
        compliance_group, created = Group.objects.get_or_create(name='Compliance_Officer')
        if created:
            self.stdout.write(self.style.SUCCESS('✓ Created Compliance_Officer group'))
        else:
            self.stdout.write('  Compliance_Officer group already exists')
        
        admin_group, created = Group.objects.get_or_create(name='Admin')
        if created:
            self.stdout.write(self.style.SUCCESS('✓ Created Admin group'))
        else:
            self.stdout.write('  Admin group already exists')
        
        # Clear existing permissions
        analyst_group.permissions.clear()
        compliance_group.permissions.clear()
        admin_group.permissions.clear()
        
        # Define permissions for each role
        self.stdout.write('\nConfiguring permissions...')
        
        # ANALYST PERMISSIONS (Read-only, masked data)
        analyst_permissions = [
            Permission.objects.get(codename='view_transaction', content_type=transaction_ct),
            Permission.objects.get(codename='view_audittrail', content_type=audit_ct),
        ]
        analyst_group.permissions.set(analyst_permissions)
        self.stdout.write(self.style.SUCCESS(f'✓ Analyst: {len(analyst_permissions)} permissions'))
        
        # COMPLIANCE OFFICER PERMISSIONS (Can demask high-risk transactions, export data)
        compliance_permissions = [
            Permission.objects.get(codename='view_transaction', content_type=transaction_ct),
            Permission.objects.get(codename='change_transaction', content_type=transaction_ct),
            Permission.objects.get(codename='view_audittrail', content_type=audit_ct),
            Permission.objects.get(codename='add_audittrail', content_type=audit_ct),
            Permission.objects.get(codename='view_userprofile', content_type=profile_ct),
        ]
        compliance_group.permissions.set(compliance_permissions)
        self.stdout.write(self.style.SUCCESS(f'✓ Compliance Officer: {len(compliance_permissions)} permissions'))
        
        # ADMIN PERMISSIONS (Full access)
        admin_permissions = Permission.objects.filter(
            content_type__in=[transaction_ct, audit_ct, profile_ct]
        )
        admin_group.permissions.set(admin_permissions)
        self.stdout.write(self.style.SUCCESS(f'✓ Admin: {len(admin_permissions)} permissions'))
        
        # Summary
        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('RBAC Setup Complete!'))
        self.stdout.write('='*60)
        self.stdout.write('\nRole Summary:')
        self.stdout.write('  • ANALYST: View transactions (masked), view audit logs')
        self.stdout.write('  • COMPLIANCE_OFFICER: View/demask high-risk transactions, export data')
        self.stdout.write('  • ADMIN: Full access to all resources')
        self.stdout.write('\nNext Steps:')
        self.stdout.write('  1. Run migrations: python manage.py makemigrations && python manage.py migrate')
        self.stdout.write('  2. Create users: python manage.py create_test_users')
        self.stdout.write('  3. Assign users to groups via Django admin or shell')
        self.stdout.write('')
