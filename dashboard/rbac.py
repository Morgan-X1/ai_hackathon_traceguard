"""
TraceGuard AI - Role-Based Access Control (RBAC) System
Implements data masking, dynamic permissions, and audit logging for CBK compliance.
"""
from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.contrib import messages
from .models import AuditTrail, UserProfile
import re


def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_role(user):
    """Get user role from profile or group"""
    if not user.is_authenticated:
        return None
    
    # Try to get from UserProfile
    try:
        profile = user.profile
        return profile.role
    except (UserProfile.DoesNotExist, AttributeError):
        pass
    
    # Fallback to groups
    if user.groups.filter(name='Admin').exists():
        return 'ADMIN'
    elif user.groups.filter(name='Compliance_Officer').exists():
        return 'COMPLIANCE_OFFICER'
    elif user.groups.filter(name='Analyst').exists():
        return 'ANALYST'
    
    return 'ANALYST'  # Default role


def can_demask_data(user, risk_score):
    """
    Check if user has permission to demask sensitive data.
    Only Compliance Officers can demask, and only for high-risk transactions.
    """
    if not user.is_authenticated:
        return False
    
    role = get_user_role(user)
    
    # Admins can always demask
    if role == 'ADMIN' or user.is_superuser:
        return True
    
    # Compliance Officers can demask if risk score is above threshold
    if role == 'COMPLIANCE_OFFICER':
        try:
            profile = user.profile
            threshold = profile.demask_threshold
        except (UserProfile.DoesNotExist, AttributeError):
            threshold = 0.8  # Default threshold
        
        return risk_score >= threshold
    
    # Analysts cannot demask
    return False


def mask_sensitive_field(value, mask_type='account'):
    """
    Mask sensitive data based on field type.
    
    Args:
        value: The sensitive value to mask
        mask_type: Type of masking ('account', 'name', 'full')
    
    Returns:
        Masked string
    """
    if not value:
        return value
    
    value_str = str(value)
    
    if mask_type == 'account':
        # Show last 4 characters: XXXX-1234
        if len(value_str) <= 4:
            return 'XXXX'
        return 'XXXX-' + value_str[-4:]
    
    elif mask_type == 'name':
        # Show first letter and last letter: J*** D**
        parts = value_str.split()
        masked_parts = []
        for part in parts:
            if len(part) <= 2:
                masked_parts.append(part[0] + '*')
            else:
                masked_parts.append(part[0] + '*' * (len(part) - 1))
        return ' '.join(masked_parts)
    
    elif mask_type == 'full':
        # Completely mask: ********
        return '*' * min(len(value_str), 8)
    
    return value_str


def mask_transaction_data(transaction_dict, user, log_access=True):
    """
    Mask sensitive fields in transaction dictionary based on user role.
    
    Args:
        transaction_dict: Dictionary containing transaction data
        user: Django User object
        log_access: Whether to log this masking action
    
    Returns:
        Dictionary with masked data and metadata
    """
    if not user.is_authenticated:
        # Completely mask for unauthenticated users
        return {**transaction_dict, '_masked': True, '_demask_allowed': False}
    
    role = get_user_role(user)
    risk_score = transaction_dict.get('risk_score', 0)
    can_demask = can_demask_data(user, risk_score)
    
    # Create a copy to avoid modifying original
    masked_data = transaction_dict.copy()
    
    # Fields that should be masked for Analysts
    sensitive_fields = ['account_number', 'customer_name', 'sender_account', 'receiver_account']
    
    if role == 'ANALYST' or (role == 'COMPLIANCE_OFFICER' and not can_demask):
        # Apply masking
        for field in sensitive_fields:
            if field in masked_data:
                if 'name' in field.lower():
                    masked_data[field] = mask_sensitive_field(masked_data[field], 'name')
                else:
                    masked_data[field] = mask_sensitive_field(masked_data[field], 'account')
        
        masked_data['_masked'] = True
        masked_data['_demask_allowed'] = can_demask
    else:
        # Admin or Compliance Officer with sufficient risk score
        masked_data['_masked'] = False
        masked_data['_demask_allowed'] = False  # Already demasked
    
    # Log access if requested
    if log_access and hasattr(user, 'profile'):
        try:
            AuditTrail.objects.create(
                user=user,
                username=user.username,
                user_role=role,
                action='VIEW' if masked_data['_masked'] else 'DEMASK',
                description=f"Accessed transaction data (masked={masked_data['_masked']})",
                transaction_id=transaction_dict.get('transaction_id', ''),
                risk_score=risk_score,
                data_masked=masked_data['_masked'],
                success=True
            )
        except Exception as e:
            # Don't fail transaction processing if audit logging fails
            pass
    
    return masked_data


def log_audit_trail(user, action, description, transaction_id='', risk_score=None, 
                   data_masked=True, success=True, error_message='', request=None):
    """
    Create an audit trail entry.
    
    Args:
        user: Django User object
        action: Action type (VIEW, DEMASK, EXPORT, etc.)
        description: Human-readable description
        transaction_id: ID of transaction being accessed
        risk_score: Risk score of transaction
        data_masked: Whether data was masked
        success: Whether action succeeded
        error_message: Error message if action failed
        request: HTTP request object (for IP and user agent)
    """
    role = get_user_role(user) if user and user.is_authenticated else 'ANONYMOUS'
    username = user.username if user and user.is_authenticated else 'anonymous'
    
    ip_address = None
    user_agent = ''
    
    if request:
        ip_address = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:500]
    
    AuditTrail.objects.create(
        user=user if user and user.is_authenticated else None,
        username=username,
        user_role=role,
        action=action,
        description=description,
        transaction_id=transaction_id,
        risk_score=risk_score,
        data_masked=data_masked,
        ip_address=ip_address,
        user_agent=user_agent,
        success=success,
        error_message=error_message
    )


def role_required(*allowed_roles):
    """
    Decorator to restrict view access to specific roles.
    
    Usage:
        @role_required('ADMIN', 'COMPLIANCE_OFFICER')
        def my_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            user_role = get_user_role(request.user)
            
            if user_role not in allowed_roles and not request.user.is_superuser:
                # Log permission denied
                log_audit_trail(
                    user=request.user,
                    action='PERMISSION_DENIED',
                    description=f"Attempted to access {view_func.__name__} without permission",
                    success=False,
                    error_message=f"User role {user_role} not in {allowed_roles}",
                    request=request
                )
                
                messages.error(request, 'You do not have permission to access this resource.')
                raise PermissionDenied("Insufficient permissions")
            
            return view_func(request, *args, **kwargs)
        
        return _wrapped_view
    return decorator


def audit_view(action_type, description_template=None):
    """
    Decorator to automatically log view access.
    
    Usage:
        @audit_view('BATCH_UPLOAD', 'User uploaded batch file')
        def batch_upload(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Execute the view
            try:
                result = view_func(request, *args, **kwargs)
                
                # Log successful access
                if request.user.is_authenticated:
                    description = description_template or f"Accessed {view_func.__name__}"
                    log_audit_trail(
                        user=request.user,
                        action=action_type,
                        description=description,
                        success=True,
                        request=request
                    )
                
                return result
            
            except Exception as e:
                # Log failed access
                if request.user.is_authenticated:
                    log_audit_trail(
                        user=request.user,
                        action=action_type,
                        description=f"Failed to access {view_func.__name__}",
                        success=False,
                        error_message=str(e),
                        request=request
                    )
                raise
        
        return _wrapped_view
    return decorator


class DataMaskingMixin:
    """
    Mixin for class-based views to handle data masking.
    
    Usage:
        class TransactionDetailView(DataMaskingMixin, DetailView):
            model = Transaction
    """
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Apply masking to object if it exists
        if 'object' in context and hasattr(context['object'], '__dict__'):
            obj_dict = {
                field.name: getattr(context['object'], field.name)
                for field in context['object']._meta.fields
            }
            
            masked_data = mask_transaction_data(obj_dict, self.request.user, log_access=True)
            context['masked_data'] = masked_data
            context['can_demask'] = masked_data.get('_demask_allowed', False)
        
        # Add user role to context
        context['user_role'] = get_user_role(self.request.user)
        
        return context
    
    def dispatch(self, request, *args, **kwargs):
        # Log view access
        if request.user.is_authenticated:
            log_audit_trail(
                user=request.user,
                action='VIEW',
                description=f"Accessed {self.__class__.__name__}",
                request=request
            )
        
        return super().dispatch(request, *args, **kwargs)
