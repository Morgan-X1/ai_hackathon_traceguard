from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from .models import Transaction, AuditTrail, UserProfile


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile"""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fields = ('role', 'department', 'employee_id', 'can_demask', 'demask_threshold', 
              'last_login_ip', 'last_activity')
    readonly_fields = ('last_login_ip', 'last_activity', 'created_at', 'updated_at')


class UserAdmin(BaseUserAdmin):
    """Extended User admin with profile"""
    inlines = (UserProfileInline,)
    list_display = ('username', 'email', 'first_name', 'last_name', 'get_role', 'is_staff')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    
    def get_role(self, obj):
        try:
            return obj.profile.get_role_display_name()
        except UserProfile.DoesNotExist:
            return 'No Profile'
    get_role.short_description = 'Role'


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    """Admin interface for Transaction model"""
    list_display = ('transaction_id', 'customer_name', 'amount', 'currency', 
                    'risk_score', 'risk_category', 'timestamp', 'created_at')
    list_filter = ('risk_category', 'currency', 'transaction_type', 'timestamp')
    search_fields = ('transaction_id', 'customer_name', 'account_number', 
                     'sender_account', 'receiver_account')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Transaction Info', {
            'fields': ('transaction_id', 'timestamp', 'transaction_type', 'amount', 'currency')
        }),
        ('Parties', {
            'fields': ('customer_name', 'account_number', 'sender_account', 'receiver_account'),
            'description': 'Sensitive fields - access is logged'
        }),
        ('Risk Assessment', {
            'fields': ('risk_score', 'xgb_score', 'gnn_score', 'network_factor', 
                      'risk_category', 'reasoning')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def has_change_permission(self, request, obj=None):
        """Only Compliance Officers and Admins can modify transactions"""
        if request.user.is_superuser:
            return True
        if request.user.groups.filter(name__in=['Compliance_Officer', 'Admin']).exists():
            return True
        return False


@admin.register(AuditTrail)
class AuditTrailAdmin(admin.ModelAdmin):
    """Admin interface for AuditTrail model"""
    list_display = ('timestamp', 'username', 'user_role', 'action', 'transaction_id', 
                    'risk_score', 'data_masked', 'success', 'ip_address')
    list_filter = ('action', 'user_role', 'data_masked', 'success', 'timestamp')
    search_fields = ('username', 'transaction_id', 'description', 'ip_address')
    readonly_fields = ('user', 'username', 'user_role', 'action', 'description', 
                      'transaction_id', 'risk_score', 'data_masked', 'timestamp', 
                      'ip_address', 'user_agent', 'success', 'error_message')
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('User Info', {
            'fields': ('user', 'username', 'user_role', 'ip_address')
        }),
        ('Action Details', {
            'fields': ('action', 'description', 'timestamp', 'success', 'error_message')
        }),
        ('Transaction Info', {
            'fields': ('transaction_id', 'risk_score', 'data_masked')
        }),
        ('Technical', {
            'fields': ('user_agent',),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        """Audit trails are created automatically"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Audit trails are immutable"""
        return False
    
    def has_delete_permission(self, request, obj=None):
        """Only superusers can delete audit trails"""
        return request.user.is_superuser


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """Admin interface for UserProfile model"""
    list_display = ('user', 'role', 'department', 'employee_id', 'can_demask', 
                    'demask_threshold', 'last_activity')
    list_filter = ('role', 'can_demask', 'department')
    search_fields = ('user__username', 'user__email', 'employee_id', 'department')
    readonly_fields = ('created_at', 'updated_at', 'last_login_ip', 'last_activity')
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Role & Permissions', {
            'fields': ('role', 'department', 'employee_id', 'can_demask', 'demask_threshold')
        }),
        ('Activity', {
            'fields': ('last_login_ip', 'last_activity')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


# Re-register UserAdmin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)

