from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class Transaction(models.Model):
    """
    Transaction model for storing analyzed transactions.
    Fields are masked based on user role and risk score.
    """
    # Transaction identifiers
    transaction_id = models.CharField(max_length=100, unique=True)
    
    # Sensitive fields (subject to masking)
    account_number = models.CharField(max_length=50)
    customer_name = models.CharField(max_length=200)
    sender_account = models.CharField(max_length=50)
    receiver_account = models.CharField(max_length=50)
    
    # Transaction details
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    currency = models.CharField(max_length=3, default='USD')
    transaction_type = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    
    # Risk assessment
    risk_score = models.FloatField()
    xgb_score = models.FloatField()
    gnn_score = models.FloatField()
    network_factor = models.FloatField(default=1.0)
    risk_category = models.CharField(max_length=20)
    reasoning = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['risk_score']),
            models.Index(fields=['transaction_id']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"Transaction {self.transaction_id} - Risk: {self.risk_score:.1f}"


class AuditTrail(models.Model):
    """
    Audit trail for tracking all data access and masking actions.
    Required for CBK compliance and regulatory reporting.
    """
    ACTION_CHOICES = [
        ('VIEW', 'View Transaction'),
        ('DEMASK', 'De-mask Sensitive Data'),
        ('EXPORT', 'Export Data'),
        ('BATCH_UPLOAD', 'Batch Upload'),
        ('SINGLE_ANALYZE', 'Single Transaction Analysis'),
        ('PERMISSION_DENIED', 'Permission Denied'),
    ]
    
    # Who performed the action
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    username = models.CharField(max_length=150)  # Backup in case user is deleted
    user_role = models.CharField(max_length=50)
    
    # What action was performed
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    description = models.TextField()
    
    # What data was accessed
    transaction_id = models.CharField(max_length=100, blank=True)
    risk_score = models.FloatField(null=True, blank=True)
    data_masked = models.BooleanField(default=True)
    
    # When and where
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    
    # Result
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
            models.Index(fields=['transaction_id']),
        ]
    
    def __str__(self):
        return f"{self.username} - {self.action} at {self.timestamp}"


class UserProfile(models.Model):
    """
    Extended user profile for storing RBAC-related information.
    """
    ROLE_CHOICES = [
        ('ANALYST', 'Analyst'),
        ('COMPLIANCE_OFFICER', 'Compliance Officer'),
        ('ADMIN', 'Admin'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='ANALYST')
    department = models.CharField(max_length=100, blank=True)
    employee_id = models.CharField(max_length=50, unique=True, blank=True, null=True)
    
    # Permission tracking
    can_demask = models.BooleanField(default=False)
    demask_threshold = models.FloatField(default=0.8, help_text="Minimum risk score to demask data")
    
    # Activity tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_activity = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['user__username']
    
    def __str__(self):
        return f"{self.user.username} - {self.role}"
    
    def get_role_display_name(self):
        """Returns human-readable role name"""
        return dict(self.ROLE_CHOICES).get(self.role, self.role)


class ForensicReportLog(models.Model):
    """
    Verification Log for FRC Forensic Report Generation
    
    Tracks which Compliance Officer generated each report for:
    - Ethical Leadership criterion
    - Audit trail compliance
    - Accountability and sovereignty
    """
    # Case identification
    case_id = models.CharField(max_length=100, unique=True, db_index=True)
    report_type = models.CharField(max_length=50, default='NATIONAL_SECURITY_DOSSIER')
    
    # Officer accountability
    generated_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='forensic_reports')
    officer_name = models.CharField(max_length=200)
    officer_role = models.CharField(max_length=50)
    officer_employee_id = models.CharField(max_length=50, blank=True)
    
    # Report metadata
    evidence_timestamp = models.DateTimeField()
    generation_timestamp = models.DateTimeField(auto_now_add=True)
    
    # Case details
    total_transactions_analyzed = models.IntegerField()
    total_volume_usd = models.DecimalField(max_digits=20, decimal_places=2)
    critical_risk_count = models.IntegerField()
    typologies_detected = models.JSONField(default=list)
    
    # AI model used
    model_used = models.CharField(max_length=50, default='gemma3:4b')
    entity_anonymization_applied = models.BooleanField(default=True)
    
    # Risk narrative
    risk_narrative = models.TextField()
    network_summary = models.JSONField()
    
    # Export tracking
    pdf_generated = models.BooleanField(default=False)
    pdf_generation_timestamp = models.DateTimeField(null=True, blank=True)
    pdf_file_hash = models.CharField(max_length=64, blank=True)  # SHA-256 for integrity
    
    # Audit and compliance
    verification_status = models.CharField(
        max_length=20,
        choices=[
            ('DRAFT', 'Draft'),
            ('VERIFIED', 'Verified by Officer'),
            ('SUBMITTED', 'Submitted to FRC'),
            ('ARCHIVED', 'Archived')
        ],
        default='DRAFT'
    )
    cbk_reporting_required = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-generation_timestamp']
        indexes = [
            models.Index(fields=['case_id']),
            models.Index(fields=['generated_by', 'generation_timestamp']),
            models.Index(fields=['verification_status']),
        ]
    
    def __str__(self):
        return f"{self.case_id} - Generated by {self.officer_name} on {self.generation_timestamp.date()}"
