"""
Django management command to create test users for RBAC testing.
Usage: python manage.py create_test_users
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group
from dashboard.models import UserProfile


class Command(BaseCommand):
    help = 'Create test users for each RBAC role'

    def add_arguments(self, parser):
        parser.add_argument(
            '--password',
            type=str,
            default='TraceGuard2026!',
            help='Password for all test users (default: TraceGuard2026!)',
        )

    def handle(self, *args, **options):
        password = options['password']
        
        self.stdout.write(self.style.SUCCESS('Creating test users for RBAC...'))
        
        # Get groups
        try:
            analyst_group = Group.objects.get(name='Analyst')
            compliance_group = Group.objects.get(name='Compliance_Officer')
            admin_group = Group.objects.get(name='Admin')
        except Group.DoesNotExist:
            self.stdout.write(self.style.ERROR(
                'Error: Groups not found. Run "python manage.py setup_rbac" first.'
            ))
            return
        
        # Create test users
        users_data = [
            {
                'username': 'analyst1',
                'email': 'analyst1@traceguard.local',
                'first_name': 'Alice',
                'last_name': 'Analyst',
                'group': analyst_group,
                'role': 'ANALYST',
                'employee_id': 'EMP001',
                'department': 'Fraud Detection',
                'can_demask': False,
            },
            {
                'username': 'analyst2',
                'email': 'analyst2@traceguard.local',
                'first_name': 'Bob',
                'last_name': 'Analyst',
                'group': analyst_group,
                'role': 'ANALYST',
                'employee_id': 'EMP002',
                'department': 'Fraud Detection',
                'can_demask': False,
            },
            {
                'username': 'compliance1',
                'email': 'compliance1@traceguard.local',
                'first_name': 'Charlie',
                'last_name': 'Compliance',
                'group': compliance_group,
                'role': 'COMPLIANCE_OFFICER',
                'employee_id': 'EMP101',
                'department': 'Compliance',
                'can_demask': True,
                'demask_threshold': 0.8,
            },
            {
                'username': 'compliance2',
                'email': 'compliance2@traceguard.local',
                'first_name': 'Diana',
                'last_name': 'Compliance',
                'group': compliance_group,
                'role': 'COMPLIANCE_OFFICER',
                'employee_id': 'EMP102',
                'department': 'Compliance',
                'can_demask': True,
                'demask_threshold': 0.7,
            },
            {
                'username': 'admin1',
                'email': 'admin1@traceguard.local',
                'first_name': 'Eve',
                'last_name': 'Administrator',
                'group': admin_group,
                'role': 'ADMIN',
                'employee_id': 'EMP201',
                'department': 'IT Security',
                'can_demask': True,
                'demask_threshold': 0.0,
            },
        ]
        
        created_users = []
        
        for user_data in users_data:
            username = user_data['username']
            
            # Check if user already exists
            if User.objects.filter(username=username).exists():
                self.stdout.write(f'  User {username} already exists, skipping...')
                continue
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=user_data['email'],
                password=password,
                first_name=user_data['first_name'],
                last_name=user_data['last_name']
            )
            
            # Add to group
            user.groups.add(user_data['group'])
            
            # Create profile
            UserProfile.objects.create(
                user=user,
                role=user_data['role'],
                employee_id=user_data['employee_id'],
                department=user_data['department'],
                can_demask=user_data['can_demask'],
                demask_threshold=user_data.get('demask_threshold', 0.8)
            )
            
            created_users.append(username)
            self.stdout.write(self.style.SUCCESS(f'✓ Created user: {username} ({user_data["role"]})'))
        
        # Summary
        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS(f'Created {len(created_users)} test users!'))
        self.stdout.write('='*60)
        self.stdout.write('\nLogin Credentials:')
        self.stdout.write(f'  Password (all users): {password}')
        self.stdout.write('\nUsers:')
        for user_data in users_data:
            self.stdout.write(f'  • {user_data["username"]:15} - {user_data["role"]:20} - {user_data["department"]}')
        
        self.stdout.write('\nTesting:')
        self.stdout.write('  1. Log in as analyst1 → see masked data')
        self.stdout.write('  2. Log in as compliance1 → demask high-risk transactions (risk > 0.8)')
        self.stdout.write('  3. Log in as admin1 → full access, no masking')
        self.stdout.write('  4. Check AuditTrail model for all access logs')
        self.stdout.write('')
