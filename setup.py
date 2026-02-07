"""
Quick setup script for TraceGuard AI
Run this after installing dependencies
"""
import os
import sys
import django

# Add the project directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'traceguard.settings')

# Setup Django
django.setup()

print("=" * 60)
print("TraceGuard AI - Setup Script")
print("=" * 60)

# Check if model file exists
from django.conf import settings
if os.path.exists(settings.MODEL_PATH):
    print("✓ Model file found: traceguard_milestone2_final.json")
else:
    print("✗ Model file NOT found!")
    print(f"  Expected at: {settings.MODEL_PATH}")

# Run migrations
print("\n" + "=" * 60)
print("Running database migrations...")
print("=" * 60)
os.system('python manage.py migrate')

print("\n" + "=" * 60)
print("Setup Complete!")
print("=" * 60)
print("\nTo start the development server, run:")
print("  python manage.py runserver")
print("\nThen visit: http://127.0.0.1:8000/dashboard/")
print("=" * 60)
