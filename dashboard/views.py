"""
TraceGuard AI - Dashboard Views
Handles transaction form submission and risk prediction
Includes RBAC, data masking, and audit logging for CBK compliance
"""
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.utils.dateparse import parse_datetime
import logging
import json
import os
import numpy as np

from .forms import TransactionForm
from .utils import predict_risk, validate_transaction_data, get_risk_color
from .batch_processor import (
    analyze_csv_file, analyze_json_file, process_transaction_list,
    get_high_risk_transactions, get_elevated_risk_transactions, 
    get_structuring_transactions, generate_summary_report
)
from .rbac import (
    role_required, audit_view, log_audit_trail, mask_transaction_data,
    get_user_role, can_demask_data
)
from .services.forensic_service import generate_forensic_report, check_ollama_availability
from .services.gemma_analyst import generate_forensic_insight, verify_ollama_gemma
from .models import ForensicReportLog, AnalysisRecord
from django.http import HttpResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import hashlib


def convert_numpy_types(obj):
    """Convert NumPy types to Python native types for JSON serialization"""
    if isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, np.floating):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {key: convert_numpy_types(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(item) for item in obj]
    return obj

logger = logging.getLogger(__name__)


def index(request):
    """Landing page - redirect to dashboard"""
    return redirect('dashboard')


@require_http_methods(["GET", "POST"])
@login_required
@audit_view('SINGLE_ANALYZE', 'User analyzed single transaction')
def dashboard(request):
    """
    Main dashboard view with transaction form and risk prediction.
    Requires authentication. All access is logged for CBK compliance.
    """
    # Add user role to context
    user_role = get_user_role(request.user)
    
    context = {
        'form': TransactionForm(),
        'prediction': None,
        'show_results': False,
        'user_role': user_role,
        'user_can_demask': False,
    }
    
    if request.method == 'POST':
        form = TransactionForm(request.POST)
        
        if form.is_valid():
            try:
                # Extract form data
                transaction_data = {
                    'Amount': float(form.cleaned_data['Amount']),
                    'Sender_ID': int(form.cleaned_data['Sender_ID']),
                    'Receiver_ID': int(form.cleaned_data['Receiver_ID']),
                    'Tx_Type': int(form.cleaned_data['Tx_Type']),
                    'Location': int(form.cleaned_data['Location']),
                    'Device_ID': int(form.cleaned_data['Device_ID']),
                    'IP_Prefix': int(form.cleaned_data['IP_Prefix']),
                    'Is_High_Risk_Country': int(form.cleaned_data['Is_High_Risk_Country']),
                    'Is_Proxy': int(form.cleaned_data['Is_Proxy']),
                    'Transaction_Frequency': int(form.cleaned_data['Transaction_Frequency']),
                    'Avg_Transaction_Amount': float(form.cleaned_data['Avg_Transaction_Amount']),
                    'Is_Round_Amount': int(form.cleaned_data['Is_Round_Amount']),
                    'Is_Structuring_Risk': int(form.cleaned_data['Is_Structuring_Risk']),
                    'Time_Since_Last_Tx': int(form.cleaned_data['Time_Since_Last_Tx']),
                    'Sender_Receiver_Relationship': int(form.cleaned_data['Sender_Receiver_Relationship']),
                    'Account_Age_Days': int(form.cleaned_data['Account_Age_Days']),
                }
                
                # Validate transaction data
                is_valid, error_msg = validate_transaction_data(transaction_data)
                if not is_valid:
                    messages.error(request, f"Validation error: {error_msg}")
                    context['form'] = form
                    return render(request, 'dashboard/dashboard.html', context)
                
                # Perform risk prediction
                prediction_result = predict_risk(transaction_data)
                
                # Add color coding
                prediction_result['risk_color'] = get_risk_color(prediction_result['risk_score'])
                
                # Apply data masking based on user role
                # Create mock transaction dict with sensitive fields
                masked_transaction = {
                    'transaction_id': f"TXN-{prediction_result.get('risk_score', 0):.0f}",
                    'account_number': f"{transaction_data['Sender_ID']}{transaction_data['Receiver_ID']}",
                    'customer_name': 'John Doe',  # Mock name
                    'sender_account': str(transaction_data['Sender_ID']),
                    'receiver_account': str(transaction_data['Receiver_ID']),
                    'risk_score': prediction_result['risk_score'],
                }
                
                masked_data = mask_transaction_data(masked_transaction, request.user, log_access=True)
                prediction_result['masked_sender'] = masked_data.get('sender_account', transaction_data['Sender_ID'])
                prediction_result['masked_receiver'] = masked_data.get('receiver_account', transaction_data['Receiver_ID'])
                prediction_result['data_masked'] = masked_data.get('_masked', True)
                prediction_result['can_demask'] = masked_data.get('_demask_allowed', False)
                
                # Log the analysis
                log_audit_trail(
                    user=request.user,
                    action='SINGLE_ANALYZE',
                    description=f"Analyzed transaction: Amount ${transaction_data['Amount']:.2f}, Risk {prediction_result['risk_score']:.1f}",
                    risk_score=prediction_result['risk_score'],
                    data_masked=prediction_result['data_masked'],
                    success=True,
                    request=request
                )
                
                # Check for warnings
                warnings = form.get_warnings()
                if warnings:
                    for field, warning in warnings.items():
                        messages.warning(request, warning)
                
                # Add success message
                risk_level = prediction_result['risk_level']
                messages.success(
                    request, 
                    f"Risk analysis complete: {risk_level} risk detected "
                    f"(Score: {prediction_result['risk_score']}/100)"
                )
                
                context['prediction'] = prediction_result
                context['show_results'] = True
                context['form'] = form  # Keep form filled for review
                
                logger.info(
                    f"Prediction completed - Risk Score: {prediction_result['risk_score']}, "
                    f"Amount: ${transaction_data['Amount']}, "
                    f"Structuring Risk: {prediction_result['is_structuring_risk']}"
                )
                
            except Exception as e:
                logger.error(f"Error during prediction: {str(e)}", exc_info=True)
                messages.error(
                    request, 
                    f"An error occurred during risk analysis: {str(e)}"
                )
                context['form'] = form
        else:
            # Form validation failed
            messages.error(request, "Please correct the errors below.")
            context['form'] = form
    
    return render(request, 'dashboard/dashboard.html', context)


@require_http_methods(["POST"])
def predict_api(request):
    """
    API endpoint for risk prediction (JSON response).
    Useful for AJAX calls or external integrations.
    """
    try:
        import json
        
        # Parse JSON data from request body
        data = json.loads(request.body)
        
        # Validate transaction data
        is_valid, error_msg = validate_transaction_data(data)
        if not is_valid:
            return JsonResponse({
                'success': False,
                'error': error_msg
            }, status=400)
        
        # Perform prediction
        prediction_result = predict_risk(data)
        
        # Add color coding
        prediction_result['risk_color'] = get_risk_color(prediction_result['risk_score'])
        
        return JsonResponse({
            'success': True,
            'prediction': prediction_result
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        logger.error(f"API prediction error: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


def about(request):
    """About page with project information"""
    context = {
        'project_name': 'TraceGuard AI',
        'version': '1.0.0',
        'description': 'Anti-Money Laundering Risk Assessment Dashboard',
        'features': [
            'Real-time transaction risk scoring',
            'XGBoost-powered ML prediction engine',
            'Structuring detection (near $10,000 transactions)',
            'Multi-factor risk analysis (16 features)',
            'Visual risk gauge and color-coded alerts',
            'Batch transaction processing (CSV/JSON)',
        ]
    }
    return render(request, 'dashboard/about.html', context)


@require_http_methods(["GET", "POST"])
@login_required
@audit_view('BATCH_UPLOAD', 'User uploaded batch transaction file')
def batch_analysis(request):
    """
    Batch analysis view - upload and analyze multiple transactions.
    Handles partial data - only requires Amount, Sender, Receiver at minimum.
    Requires authentication. All access is logged for CBK compliance.
    """
    # Add user role to context
    user_role = get_user_role(request.user)
    
    context = {
        'results': None,
        'summary': None,
        'critical_risk': None,
        'elevated_risk': None,
        'structuring': None,
        'user_role': user_role,
    }
    
    if request.method == 'POST':
        try:
            # Check if file was uploaded
            if 'transaction_file' in request.FILES:
                uploaded_file = request.FILES['transaction_file']
                file_extension = os.path.splitext(uploaded_file.name)[1].lower()
                
                # Save temporarily
                file_path = default_storage.save(f'temp/{uploaded_file.name}', uploaded_file)
                full_path = os.path.join(default_storage.location if hasattr(default_storage, 'location') else '', file_path)
                
                # Process based on file type
                if file_extension == '.csv':
                    analysis_results = analyze_csv_file(full_path)
                elif file_extension == '.json':
                    analysis_results = analyze_json_file(full_path)
                else:
                    messages.error(request, "Unsupported file format. Please upload CSV or JSON.")
                    return render(request, 'dashboard/batch_analysis.html', context)
                
                # Clean up temp file
                if os.path.exists(full_path):
                    os.remove(full_path)
                
                # Extract results and graph data (handle both dict and list formats)
                if isinstance(analysis_results, dict):
                    results = analysis_results.get('results', [])
                    graph_data = analysis_results.get('graph_data', None)
                else:
                    # Backward compatibility - old format was just list
                    results = analysis_results
                    graph_data = None
                
                # Convert NumPy types in graph_data for JSON serialization
                context['graph_data_json'] = None
                context['graph_data'] = None
                
                if graph_data is not None:
                    if not isinstance(graph_data, dict):
                        print(f"WARNING: graph_data is not a dict, it's {type(graph_data)}")
                    else:
                        try:
                            graph_data = convert_numpy_types(graph_data)
                            # Verify it's still a dict after conversion
                            if isinstance(graph_data, dict) and 'visualization' in graph_data:
                                context['graph_data_json'] = json.dumps(graph_data['visualization'])
                                context['graph_data'] = graph_data
                            else:
                                print(f"WARNING: graph_data missing 'visualization' key or wrong type after conversion")
                        except Exception as e:
                            print(f"ERROR converting graph_data: {str(e)}")
                            import traceback
                            traceback.print_exc()
                
                # Generate reports
                summary = generate_summary_report(results)
                critical_risk = get_high_risk_transactions(results, threshold=40.0)
                elevated_risk = get_elevated_risk_transactions(results)
                structuring = get_structuring_transactions(results)
                
                # Apply data masking to all results
                masked_results = []
                for result in results:
                    masked_result = mask_transaction_data(result, request.user, log_access=False)
                    masked_results.append(masked_result)
                
                # Store masked results in session for AI forensic analysis
                request.session['masked_results'] = masked_results
                request.session['raw_results'] = results  # Store unmasked for AI (will be anonymized)
                request.session.modified = True
                
                # Log batch analysis
                log_audit_trail(
                    user=request.user,
                    action='BATCH_UPLOAD',
                    description=f"Batch analyzed {len(results)} transactions from file: {uploaded_file.name}",
                    risk_score=summary.get('avg_risk', 0),
                    data_masked=True,
                    success=True,
                    request=request
                )
                
                context['results'] = masked_results
                context['summary'] = summary
                context['critical_risk'] = critical_risk
                context['elevated_risk'] = elevated_risk
                context['structuring'] = structuring
                
                messages.success(
                    request,
                    f"Analyzed {summary['successful_analysis']} transactions. "
                    f"Found {len(critical_risk)} 🚨 CRITICAL, {len(elevated_risk)} ⚠️ ELEVATED, "
                    f"and {len(structuring)} structuring attempts."
                )
                
            # Check if JSON was pasted
            elif 'transaction_json' in request.POST:
                json_data = request.POST.get('transaction_json')
                
                try:
                    data = json.loads(json_data)
                    
                    # Handle different JSON structures
                    if isinstance(data, list):
                        transactions = data
                    elif isinstance(data, dict) and 'transactions' in data:
                        transactions = data['transactions']
                    else:
                        messages.error(request, "JSON must be an array or object with 'transactions' key")
                        return render(request, 'dashboard/batch_analysis.html', context)
                    
                    # Process transactions and get graph data
                    analysis_results = process_transaction_list(transactions)
                    
                    # Extract results and graph data (handle both dict and list formats)
                    if isinstance(analysis_results, dict):
                        results = analysis_results.get('results', [])
                        graph_data = analysis_results.get('graph_data', None)
                    else:
                        # Backward compatibility - old format was just list
                        results = analysis_results
                        graph_data = None
                    
                    # Convert NumPy types in graph_data for JSON serialization
                    context['graph_data_json'] = None
                    context['graph_data'] = None
                    
                    if graph_data is not None:
                        if not isinstance(graph_data, dict):
                            print(f"WARNING: graph_data is not a dict, it's {type(graph_data)}")
                        else:
                            try:
                                graph_data = convert_numpy_types(graph_data)
                                # Verify it's still a dict after conversion
                                if isinstance(graph_data, dict) and 'visualization' in graph_data:
                                    context['graph_data_json'] = json.dumps(graph_data['visualization'])
                                    context['graph_data'] = graph_data
                                    # Store in session for network visualization page
                                    request.session['graph_data'] = graph_data
                                    request.session['graph_data_json'] = json.dumps(graph_data['visualization'])
                                    request.session.modified = True  # Ensure session is saved
                                    print(f"SUCCESS: Stored graph data in session. Nodes: {len(graph_data['visualization'].get('nodes', []))}, Edges: {len(graph_data['visualization'].get('edges', []))}")
                                else:
                                    print(f"WARNING: graph_data missing 'visualization' key or wrong type after conversion")
                            except Exception as e:
                                print(f"ERROR converting graph_data: {str(e)}")
                                import traceback
                                traceback.print_exc()
                    else:
                        print("WARNING: graph_data is None - network visualization will not be available")
                    
                    # Generate reports
                    summary = generate_summary_report(results)
                    critical_risk = get_high_risk_transactions(results, threshold=40.0)
                    elevated_risk = get_elevated_risk_transactions(results)
                    structuring = get_structuring_transactions(results)
                    
                    # Apply data masking to all results
                    masked_results = []
                    for result in results:
                        masked_result = mask_transaction_data(result, request.user, log_access=False)
                        masked_results.append(masked_result)
                    
                    # Store masked results in session for AI forensic analysis
                    request.session['masked_results'] = masked_results
                    request.session['raw_results'] = results  # Store unmasked for AI (will be anonymized)
                    request.session.modified = True
                    
                    # Log batch analysis
                    log_audit_trail(
                        user=request.user,
                        action='BATCH_UPLOAD',
                        description=f"Batch analyzed {len(results)} transactions from JSON paste",
                        risk_score=summary.get('avg_risk', 0),
                        data_masked=True,
                        success=True,
                        request=request
                    )
                    
                    context['results'] = masked_results
                    context['summary'] = summary
                    context['critical_risk'] = critical_risk
                    context['elevated_risk'] = elevated_risk
                    context['structuring'] = structuring
                    context['graph_data'] = graph_data  # For conditional display
                    
                    messages.success(
                        request,
                        f"Analyzed {summary['successful_analysis']} transactions. "
                        f"Found {len(critical_risk)} 🚨 CRITICAL, {len(elevated_risk)} ⚠️ ELEVATED, "
                        f"and {len(structuring)} structuring attempts."
                    )
                    
                except json.JSONDecodeError as e:
                    messages.error(request, f"Invalid JSON: {str(e)}")
            else:
                messages.error(request, "Please upload a file or paste JSON data.")
                
        except Exception as e:
            logger.error(f"Batch analysis error: {str(e)}", exc_info=True)
            messages.error(request, f"Error processing transactions: {str(e)}")
    
    return render(request, 'dashboard/batch_analysis.html', context)


@login_required
@audit_view('NETWORK_VIEW', 'User viewed network visualization')
def network_visualization(request):
    """
    Dedicated network visualization page showing GNN analysis.
    Displays interactive transaction network graph with suspicious pattern detection.
    """
    user_role = get_user_role(request.user)
    
    # Get graph data from session (stored during batch analysis)
    graph_data = request.session.get('graph_data', None)
    graph_data_json = request.session.get('graph_data_json', None)
    
    # Debug output
    print(f"Network Visualization - Session keys: {list(request.session.keys())}")
    print(f"Graph data exists: {graph_data is not None}")
    print(f"Graph data JSON exists: {graph_data_json is not None}")
    if graph_data:
        print(f"Graph data type: {type(graph_data)}")
        print(f"Graph data keys: {graph_data.keys() if isinstance(graph_data, dict) else 'Not a dict'}")
    
    context = {
        'graph_data': graph_data,
        'graph_data_json': graph_data_json,
        'user_role': user_role,
    }
    
    return render(request, 'dashboard/network_visualization.html', context)


@require_http_methods(["POST"])
@login_required
@role_required('COMPLIANCE_OFFICER', 'ADMIN')
def demask_transaction(request):
    """
    API endpoint for Compliance Officers to demask sensitive transaction data.
    Only allowed for transactions with risk_score >= threshold (default 0.8).
    Every demask action is logged to AuditTrail.
    """
    try:
        data = json.loads(request.body)
        transaction_id = data.get('transaction_id')
        risk_score = float(data.get('risk_score', 0))
        
        # Check permission
        if not can_demask_data(request.user, risk_score):
            log_audit_trail(
                user=request.user,
                action='PERMISSION_DENIED',
                description=f"Attempted to demask transaction {transaction_id} with risk score {risk_score}",
                transaction_id=transaction_id,
                risk_score=risk_score,
                success=False,
                error_message=f"Risk score {risk_score} below threshold",
                request=request
            )
            return JsonResponse({
                'success': False,
                'error': f'Insufficient risk score. Minimum: {request.user.profile.demask_threshold}'
            }, status=403)
        
        # In a real system, fetch actual data from database
        # For now, return mock demasked data
        demasked_data = {
            'account_number': data.get('account_number', 'ACCT-12345678'),
            'customer_name': data.get('customer_name', 'John Michael Doe'),
            'sender_account': data.get('sender_account', 'SEND-87654321'),
            'receiver_account': data.get('receiver_account', 'RECV-11223344'),
        }
        
        # Log successful demask
        log_audit_trail(
            user=request.user,
            action='DEMASK',
            description=f"Demasked transaction {transaction_id} (Risk: {risk_score:.1f})",
            transaction_id=transaction_id,
            risk_score=risk_score,
            data_masked=False,
            success=True,
            request=request
        )
        
        return JsonResponse({
            'success': True,
            'data': demasked_data,
            'demasked_by': request.user.username,
            'demasked_at': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Demask error: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
@login_required
@role_required('COMPLIANCE_OFFICER', 'ADMIN')
def audit_log(request):
    """
    View audit trail logs.
    Only accessible by Compliance Officers and Admins.
    """
    from .models import AuditTrail
    from django.core.paginator import Paginator
    
    # Get filters
    action_filter = request.GET.get('action', '')
    user_filter = request.GET.get('user', '')
    
    # Query audit trail
    logs = AuditTrail.objects.all()
    
    if action_filter:
        logs = logs.filter(action=action_filter)
    if user_filter:
        logs = logs.filter(username__icontains=user_filter)
    
    # Paginate
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    # Get distinct actions for filter dropdown
    actions = AuditTrail.objects.values_list('action', flat=True).distinct()
    
    context = {
        'page_obj': page_obj,
        'actions': actions,
        'action_filter': action_filter,
        'user_filter': user_filter,
        'user_role': get_user_role(request.user),
    }
    
    return render(request, 'dashboard/audit_log.html', context)


@require_http_methods(["POST"])
@login_required
@role_required('COMPLIANCE_OFFICER', 'ADMIN')
@audit_view('AI_FORENSIC_REPORT', 'Generated AI forensic analysis report')
def generate_ai_forensic_report(request):
    """
    Generate AI-powered forensic analysis report using Ollama llama3.2
    Accessible only to Compliance Officers and Admins
    Anonymizes PII before sending to AI model
    """
    try:
        # Check Ollama availability first
        availability = check_ollama_availability()
        if not availability.get('available'):
            return JsonResponse({
                'success': False,
                'error': 'Ollama service not available',
                'message': availability.get('message', 'Please ensure Ollama is running (ollama serve) and llama3.2 is installed (ollama pull llama3.2)')
            }, status=503)
        
        if not availability.get('has_compatible_model'):
            return JsonResponse({
                'success': False,
                'error': 'No models found',
                'message': f'No Ollama models installed. Available models: {availability.get("models", [])}. Install a model with: ollama pull gemma3:4b'
            }, status=503)
        
        # Get transaction data from session (from batch analysis)
        graph_data = request.session.get('graph_data', None)
        
        # Parse request body for transaction data
        try:
            body = json.loads(request.body)
            transaction_data = body.get('transactions', [])
        except json.JSONDecodeError:
            transaction_data = []
        
        # If no transactions provided, try to get from session
        if not transaction_data:
            # Use raw_results (unmasked) - will be anonymized by forensic_service
            raw_results = request.session.get('raw_results', [])
            if raw_results:
                transaction_data = raw_results
            else:
                # Fallback to masked_results if raw not available
                masked_results = request.session.get('masked_results', [])
                transaction_data = masked_results
        
        if not transaction_data:
            # Debug: Check what's in session
            session_keys = list(request.session.keys())
            logger.warning(f"No transaction data found. Session keys: {session_keys}")
            return JsonResponse({
                'success': False,
                'error': 'No transaction data',
                'message': f'No transactions available for analysis. Please run batch analysis first. Session keys: {session_keys}'
            }, status=400)
        
        # Generate forensic report using AI
        logger.info(f"Generating AI forensic report for {len(transaction_data)} transactions by user {request.user.username}")
        
        # Determine which model to use from available models
        available_models = availability.get('models', [])
        selected_model = None
        if 'gemma3:4b' in available_models:
            selected_model = 'gemma3:4b'
        elif 'llama3.2' in available_models:
            selected_model = 'llama3.2'
        elif len(available_models) > 0:
            selected_model = available_models[0]
        else:
            selected_model = 'gemma3:4b'  # fallback
        
        logger.info(f"Using model: {selected_model}")
        
        report_result = generate_forensic_report(
            transaction_data=transaction_data,
            graph_data=graph_data,
            model=selected_model
        )
        
        if not report_result.get('success'):
            return JsonResponse({
                'success': False,
                'error': report_result.get('error', 'Unknown error'),
                'message': report_result.get('message', 'Failed to generate report')
            }, status=500)
        
        # Log successful report generation to audit trail
        log_audit_trail(
            user=request.user,
            action='AI_FORENSIC_REPORT',
            details=f"Generated AI report for {report_result.get('metadata', {}).get('total_transactions', 0)} transactions"
        )
        
        # Return successful response with report
        return JsonResponse({
            'success': True,
            'report': report_result.get('report', ''),
            'metadata': report_result.get('metadata', {}),
            'context_summary': report_result.get('context_summary', {}),
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error generating AI forensic report: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Server error',
            'message': f'An error occurred while generating the report: {str(e)}'
        }, status=500)


@require_http_methods(["GET", "POST"])
def test_gemma_endpoint(request):
    """Simple test endpoint to verify routing works"""
    return JsonResponse({
        'success': True,
        'message': 'Test endpoint working',
        'method': request.method
    })


@require_http_methods(["POST"])
def gemma_deep_analysis(request):
    """
    Gemma Reasoning Engine - National Security Forensic Dossier Generation
    
    Transforms GraphSAGE/Isolation Forest outputs into FRC-style investigative narratives.
    Accessible only to Compliance Officers and Admins.
    """
    # Temporary: Remove decorators for testing
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)
    
    try:
        # Verify Gemma availability
        gemma_status = verify_ollama_gemma()
        if not gemma_status.get('available'):
            return JsonResponse({
                'success': False,
                'error': 'Gemma service not available',
                'message': gemma_status.get('message', 'Ollama service not running')
            }, status=503)
        
        if not gemma_status.get('gemma_installed'):
            return JsonResponse({
                'success': False,
                'error': 'Gemma model not found',
                'message': f'No Gemma model installed. Available models: {gemma_status.get("all_models", [])}. Install with: ollama pull gemma3:4b'
            }, status=503)
        
        # Get transaction and network data from session
        raw_results = request.session.get('raw_results', [])
        graph_data = request.session.get('graph_data', None)
        
        if not raw_results:
            return JsonResponse({
                'success': False,
                'error': 'No anomaly data',
                'message': 'No suspicious transactions available. Run batch analysis first.'
            }, status=400)
        
        # Debug: Log the structure of raw_results
        logger.info(f"Raw results count: {len(raw_results)}")
        if raw_results:
            logger.info(f"Sample transaction keys: {raw_results[0].keys() if raw_results else 'None'}")
        
        # Prepare anomaly data structure
        anomaly_data = {
            'transactions': raw_results,
            'network': graph_data if graph_data else {'nodes': [], 'edges': []},
            'case_metadata': {
                'analyst': request.user.get_full_name() or request.user.username,
                'timestamp': timezone.now().isoformat()
            }
        }
        
        # Select Gemma model
        gemma_model = gemma_status['gemma_models'][0] if gemma_status['gemma_models'] else 'gemma3:4b'
        
        logger.info(f"Generating FRC forensic dossier using {gemma_model} for user {request.user.username}")
        
        # Generate forensic insight using Gemma
        insight_result = generate_forensic_insight(
            anomaly_data=anomaly_data,
            model=gemma_model
        )
        
        if not insight_result.get('success'):
            return JsonResponse({
                'success': False,
                'error': insight_result.get('error', 'Analysis failed'),
                'message': insight_result.get('message', 'Failed to generate forensic insight')
            }, status=500)
        
        # Create Verification Log (Ethical Leadership & Accountability)
        try:
            user_profile = request.user.profile
            officer_role = user_profile.role
            employee_id = user_profile.employee_id or 'N/A'
        except:
            officer_role = 'COMPLIANCE_OFFICER'
            employee_id = 'N/A'
        
        # Parse ISO timestamp to timezone-aware datetime
        evidence_ts = parse_datetime(insight_result['evidence_timestamp'])
        if evidence_ts and not timezone.is_aware(evidence_ts):
            evidence_ts = timezone.make_aware(evidence_ts)
        
        forensic_log = ForensicReportLog.objects.create(
            case_id=insight_result['case_id'],
            generated_by=request.user,
            officer_name=request.user.get_full_name() or request.user.username,
            officer_role=officer_role,
            officer_employee_id=employee_id,
            evidence_timestamp=evidence_ts,
            total_transactions_analyzed=insight_result['network_summary']['total_transactions'],
            total_volume_usd=insight_result['network_summary']['total_volume_usd'],
            critical_risk_count=insight_result['network_summary']['critical_risk_count'],
            typologies_detected=insight_result['typologies_detected'],
            model_used=insight_result['model_used'],
            entity_anonymization_applied=True,
            risk_narrative=insight_result['risk_narrative'],
            network_summary=insight_result['network_summary'],
            verification_status='VERIFIED',
            cbk_reporting_required=insight_result['network_summary']['critical_risk_count'] > 5
        )
        
        logger.info(f"Created forensic report log: {forensic_log.case_id}")
        
        # Create Analysis Record for accountability and case history
        # Extract primary target account from network data
        target_accounts = []
        if graph_data and graph_data.get('nodes'):
            # Get accounts with highest risk scores
            nodes_sorted = sorted(
                graph_data['nodes'],
                key=lambda x: x.get('risk', 0),
                reverse=True
            )
            target_accounts = [node['id'] for node in nodes_sorted[:5]]  # Top 5 risky accounts
        
        # Create analysis records for each target account
        for idx, account_id in enumerate(target_accounts):
            AnalysisRecord.objects.create(
                officer=request.user,
                target_account=account_id,
                gemma_summary=insight_result['risk_narrative'],
                risk_score=insight_result['network_summary']['critical_risk_count'] * 10,  # Normalize to 0-100
                case_reference=insight_result['case_id'],
                transaction_count=insight_result['network_summary']['total_transactions'],
                total_amount_usd=insight_result['network_summary']['total_volume_usd'],
                typologies_identified=insight_result['typologies_detected'],
                network_connections=insight_result['network_summary'].get('total_entities', 0),
                investigation_status='ONGOING'
            )
        
        logger.info(f"Created {len(target_accounts)} analysis records for case {forensic_log.case_id}")
        
        # Log to audit trail
        log_audit_trail(
            user=request.user,
            action='GEMMA_DEEP_ANALYSIS',
            description=f"Generated FRC dossier {insight_result['case_id']} - {len(insight_result['typologies_detected'])} typologies detected",
            request=request
        )
        
        # Return forensic dossier
        return JsonResponse({
            'success': True,
            'case_id': insight_result['case_id'],
            'evidence_timestamp': insight_result['evidence_timestamp'],
            'risk_narrative': insight_result['risk_narrative'],
            'network_summary': insight_result['network_summary'],
            'typologies_detected': insight_result['typologies_detected'],
            'officer_name': forensic_log.officer_name,
            'verification_status': forensic_log.verification_status,
            'cbk_reporting_required': forensic_log.cbk_reporting_required,
            'model_used': insight_result['model_used']
        })
        
    except Exception as e:
        logger.error(f"Gemma deep analysis failed: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'error': 'Server error',
            'message': f'Error during Gemma analysis: {str(e)}'
        }, status=500)


@login_required
@role_required('COMPLIANCE_OFFICER', 'ADMIN')
def export_forensic_pdf(request, case_id):
    """
    Export FRC Forensic Dossier as PDF
    
    Generates downloadable PDF with:
    - Risk Narrative (Gemma-generated)
    - Network Summary (quantitative evidence)
    - Evidence Timestamp & Case ID
    - Officer verification
    """
    try:
        # Retrieve forensic report log
        forensic_log = ForensicReportLog.objects.get(case_id=case_id)
        
        # Create PDF response
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="FRC_Dossier_{case_id}.pdf"'
        
        # Create PDF document
        doc = SimpleDocTemplate(response, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=12,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=10,
            spaceBefore=15,
            fontName='Helvetica-Bold'
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['BodyText'],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=8,
            leading=14
        )
        
        # Title
        story.append(Paragraph("KENYA FINANCIAL REPORTING CENTRE", title_style))
        story.append(Paragraph("NATIONAL SECURITY FORENSIC DOSSIER", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Classification Banner
        classification_table = Table(
            [[Paragraph("<b>CONFIDENTIAL - CBK COMPLIANCE USE ONLY</b>", styles['Normal'])]],
            colWidths=[6.5*inch]
        )
        classification_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#d32f2f')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(classification_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Case Information
        case_info_data = [
            ['<b>Case ID:</b>', forensic_log.case_id],
            ['<b>Evidence Timestamp:</b>', forensic_log.evidence_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['<b>Report Generated:</b>', forensic_log.generation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['<b>Generated By:</b>', f"{forensic_log.officer_name} ({forensic_log.officer_role})"],
            ['<b>Employee ID:</b>', forensic_log.officer_employee_id],
            ['<b>Verification Status:</b>', forensic_log.verification_status],
            ['<b>CBK Reporting Required:</b>', 'YES' if forensic_log.cbk_reporting_required else 'NO'],
        ]
        
        case_info_table = Table(case_info_data, colWidths=[2*inch, 4.5*inch])
        case_info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(case_info_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Network Summary
        story.append(Paragraph("NETWORK SUMMARY", header_style))
        network_summary = forensic_log.network_summary
        summary_data = [
            ['<b>Metric</b>', '<b>Value</b>'],
            ['Total Entities Analyzed', str(network_summary.get('total_entities', 0))],
            ['Total Transactions', str(network_summary.get('total_transactions', 0))],
            ['Total Volume (USD)', f"${network_summary.get('total_volume_usd', 0):,.2f}"],
            ['Critical Risk Alerts', str(network_summary.get('critical_risk_count', 0))],
            ['Smurfing Patterns Detected', str(network_summary.get('smurfing_patterns', 0))],
            ['Layering Patterns Detected', str(network_summary.get('layering_patterns', 0))],
            ['Structuring Attempts', str(network_summary.get('structuring_attempts', 0))],
        ]
        
        summary_table = Table(summary_data, colWidths=[3.5*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.2*inch))
        
        # Typologies Detected
        story.append(Paragraph("TYPOLOGIES IDENTIFIED", header_style))
        if forensic_log.typologies_detected:
            typology_text = "<br/>".join([f"• {typology}" for typology in forensic_log.typologies_detected])
            story.append(Paragraph(typology_text, body_style))
        else:
            story.append(Paragraph("No specific typologies detected.", body_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Risk Narrative
        story.append(Paragraph("FORENSIC RISK NARRATIVE", header_style))
        story.append(Paragraph("<i>Generated by Gemma AI Reasoning Engine (Sovereignty-Compliant Analysis)</i>", styles['Italic']))
        story.append(Spacer(1, 0.1*inch))
        
        # Split narrative into paragraphs
        narrative_paragraphs = forensic_log.risk_narrative.split('\n\n')
        for para in narrative_paragraphs:
            if para.strip():
                story.append(Paragraph(para.strip(), body_style))
        
        story.append(PageBreak())
        
        # Legal Disclaimer
        story.append(Paragraph("LEGAL DISCLAIMER & VERIFICATION", header_style))
        disclaimer_text = f"""
This forensic dossier was generated using AI-assisted analysis (Gemma Reasoning Engine) 
in compliance with Kenya's Anti-Money Laundering and Counter-Terrorism Financing regulations.

<b>Privacy Safeguards:</b> All personally identifiable information (PII) was anonymized before 
AI processing. No real names, account numbers, or phone numbers were exposed to the language model, 
ensuring data sovereignty and public trust.

<b>Officer Accountability:</b> This report was generated and verified by {forensic_log.officer_name} 
({forensic_log.officer_role}, Employee ID: {forensic_log.officer_employee_id}) on 
{forensic_log.generation_timestamp.strftime('%Y-%m-%d at %H:%M:%S UTC')}.

<b>Evidence Integrity:</b> This document hash: {hashlib.sha256(forensic_log.risk_narrative.encode()).hexdigest()[:16].upper()}

<b>Regulatory Authority:</b> Kenya Financial Reporting Centre (FRC) | Central Bank of Kenya (CBK)

<b>Distribution:</b> CONFIDENTIAL - Authorized personnel only. Unauthorized disclosure may result 
in legal action under Kenya's Banking Act.
        """
        story.append(Paragraph(disclaimer_text, body_style))
        
        # Build PDF
        doc.build(story)
        
        # Update forensic log
        forensic_log.pdf_generated = True
        forensic_log.pdf_generation_timestamp = timezone.now()
        forensic_log.pdf_file_hash = hashlib.sha256(response.content).hexdigest()
        forensic_log.save()
        
        # Log to audit trail
        log_audit_trail(
            user=request.user,
            action='PDF_EXPORT',
            description=f"Exported FRC dossier {case_id} as PDF",
            request=request
        )
        
        logger.info(f"Exported PDF for case {case_id} by {request.user.username}")
        
        return response
        
    except ForensicReportLog.DoesNotExist:
        return HttpResponse("Case ID not found", status=404)
    except Exception as e:
        logger.error(f"PDF export failed: {str(e)}", exc_info=True)
        return HttpResponse(f"Error generating PDF: {str(e)}", status=500)


@login_required
@role_required('COMPLIANCE_OFFICER', 'ADMIN')
def generate_investigation_report(request):
    """
    Generate a professional PDF investigation report for suspected accounts.
    
    Takes a list of suspected_account_ids and generates a comprehensive FRC-compliant
    PDF report with officer details, account analysis, and risk assessments.
    """
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'POST method required'}, status=405)
    
    try:
        # Parse request data
        data = json.loads(request.body)
        suspected_account_ids = data.get('suspected_account_ids', [])
        
        if not suspected_account_ids:
            return JsonResponse({'success': False, 'error': 'No account IDs provided'}, status=400)
        
        # Get analysis records for these accounts (created by current officer)
        analysis_records = AnalysisRecord.objects.filter(
            officer=request.user,
            target_account__in=suspected_account_ids
        ).order_by('-risk_score')
        
        if not analysis_records.exists():
            return JsonResponse({
                'success': False,
                'error': 'No analysis records found for the specified accounts'
            }, status=404)
        
        # Generate PDF
        response = HttpResponse(content_type='application/pdf')
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename = f'TraceGuard_Investigation_Report_{timestamp}.pdf'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Create PDF document
        doc = SimpleDocTemplate(response, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        
        # Container for PDF elements
        story = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#8B0000'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2C3E50'),
            spaceAfter=12,
            fontName='Helvetica-Bold'
        )
        
        body_style = ParagraphStyle(
            'CustomBody',
            parent=styles['BodyText'],
            fontSize=11,
            leading=14,
            spaceAfter=12
        )
        
        # Header Section
        story.append(Paragraph("TraceGuard AI", title_style))
        story.append(Paragraph("Confidential Forensic Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Classification Banner
        classification_table = Table(
            [['CONFIDENTIAL - FOR FRC COMPLIANCE AUDIT ONLY']],
            colWidths=[6.5*inch]
        )
        classification_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.red),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(classification_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Officer Details Section
        story.append(Paragraph("Investigating Officer Details", header_style))
        
        officer_name = request.user.get_full_name() or request.user.username
        officer_role = get_user_role(request.user)
        
        try:
            from .models import UserProfile
            user_profile = UserProfile.objects.get(user=request.user)
            employee_id = user_profile.employee_id or 'N/A'
        except:
            employee_id = 'N/A'
        
        officer_data = [
            ['Investigating Officer:', officer_name],
            ['Role:', officer_role],
            ['Employee ID:', employee_id],
            ['Report Generated:', timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Number of Accounts:', str(analysis_records.count())]
        ]
        
        officer_table = Table(officer_data, colWidths=[2*inch, 4.5*inch])
        officer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E8E8E8')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        story.append(officer_table)
        story.append(Spacer(1, 0.4*inch))
        
        # Suspected Accounts Analysis Section
        story.append(Paragraph("Suspected Accounts Analysis", header_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Build accounts table
        account_table_data = [[
            'Account ID',
            'Risk Score',
            'Status',
            'Typologies',
            'Key Risk Factors'
        ]]
        
        for record in analysis_records:
            # Truncate summary for table display
            risk_factors = record.gemma_summary[:150] + '...' if len(record.gemma_summary) > 150 else record.gemma_summary
            typologies = ', '.join(record.typologies_identified[:3]) if record.typologies_identified else 'N/A'
            
            account_table_data.append([
                record.target_account,
                f"{record.risk_score:.1f}",
                record.investigation_status,
                typologies,
                risk_factors
            ])
        
        account_table = Table(account_table_data, colWidths=[1.2*inch, 0.8*inch, 1*inch, 1.5*inch, 2*inch])
        account_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495E')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TOPPADDING', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(account_table)
        story.append(Spacer(1, 0.4*inch))
        
        # Detailed Analysis for Each Account
        story.append(PageBreak())
        story.append(Paragraph("Detailed Account Analysis", header_style))
        story.append(Spacer(1, 0.2*inch))
        
        for idx, record in enumerate(analysis_records, 1):
            # Account header
            account_header = f"Account {idx}: {record.target_account}"
            story.append(Paragraph(account_header, ParagraphStyle(
                'AccountHeader',
                parent=styles['Heading3'],
                fontSize=14,
                textColor=colors.HexColor('#8B0000'),
                spaceAfter=10,
                fontName='Helvetica-Bold'
            )))
            
            # Account metrics
            metrics_data = [
                ['Risk Score:', f"{record.risk_score:.2f}"],
                ['Transaction Count:', str(record.transaction_count)],
                ['Total Amount (USD):', f"${record.total_amount_usd:,.2f}"],
                ['Network Connections:', str(record.network_connections)],
                ['Investigation Status:', record.investigation_status],
                ['Analysis Date:', record.created_at.strftime('%Y-%m-%d %H:%M:%S')]
            ]
            
            metrics_table = Table(metrics_data, colWidths=[2*inch, 4.5*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#F0F0F0')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(metrics_table)
            story.append(Spacer(1, 0.2*inch))
            
            # Typologies detected
            if record.typologies_identified:
                story.append(Paragraph("<b>Typologies Identified:</b>", body_style))
                for typology in record.typologies_identified:
                    story.append(Paragraph(f"• {typology}", body_style))
                story.append(Spacer(1, 0.1*inch))
            
            # Gemma AI Analysis
            story.append(Paragraph("<b>AI Forensic Analysis:</b>", body_style))
            story.append(Paragraph(record.gemma_summary, body_style))
            
            if idx < analysis_records.count():
                story.append(Spacer(1, 0.3*inch))
                story.append(Paragraph("—" * 60, body_style))
                story.append(Spacer(1, 0.3*inch))
        
        # Footer Section
        story.append(PageBreak())
        story.append(Paragraph("Report Summary & Recommendations", header_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Calculate summary statistics
        total_risk = sum(r.risk_score for r in analysis_records)
        avg_risk = total_risk / analysis_records.count()
        high_risk_count = analysis_records.filter(risk_score__gte=75).count()
        
        summary_text = f"""
        This investigation report covers {analysis_records.count()} suspected accounts identified through 
        TraceGuard AI's machine learning analysis. The average risk score across all accounts is {avg_risk:.2f}, 
        with {high_risk_count} accounts classified as high-risk (score ≥ 75).
        <br/><br/>
        <b>Recommended Actions:</b><br/>
        • Escalate high-risk accounts to the Financial Reporting Centre (FRC) for further investigation<br/>
        • Request enhanced due diligence documentation for accounts with complex network patterns<br/>
        • Monitor ongoing transactions for accounts under investigation<br/>
        • Coordinate with law enforcement if criminal activity is suspected<br/>
        <br/>
        <b>Legal Disclaimer:</b><br/>
        This report is generated for compliance purposes under the Kenya Financial Reporting Centre Act 
        and the Proceeds of Crime and Anti-Money Laundering Act. All information contained herein is 
        confidential and intended solely for authorized personnel. Unauthorized disclosure may result 
        in legal consequences.
        <br/><br/>
        <b>Document Integrity:</b><br/>
        Generated by TraceGuard AI • Report ID: {timestamp} • Officer: {officer_name}
        """
        
        story.append(Paragraph(summary_text, body_style))
        
        # Build PDF
        doc.build(story)
        
        # Update analysis records
        for record in analysis_records:
            record.report_generated = True
            record.report_generated_at = timezone.now()
            record.report_download_count += 1
            record.save()
        
        # Log to audit trail
        log_audit_trail(
            user=request.user,
            action='INVESTIGATION_REPORT_GENERATED',
            description=f"Generated investigation report for {len(suspected_account_ids)} accounts",
            request=request
        )
        
        logger.info(f"Generated investigation report for {len(suspected_account_ids)} accounts by {request.user.username}")
        
        return response
        
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Investigation report generation failed: {str(e)}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


@login_required
def get_recent_investigations(request):
    """
    API endpoint to get the last 5 analysis records for the current officer.
    
    Used for the "Recent Investigations" sidebar section to allow officers
    to quickly access their case history.
    """
    try:
        recent_records = AnalysisRecord.objects.filter(
            officer=request.user
        ).order_by('-created_at')[:5]
        
        records_data = []
        for record in recent_records:
            records_data.append({
                'id': record.id,
                'target_account': record.target_account,
                'risk_score': float(record.risk_score),
                'investigation_status': record.investigation_status,
                'created_at': record.created_at.strftime('%Y-%m-%d %H:%M'),
                'typologies': record.typologies_identified,
                'transaction_count': record.transaction_count,
                'report_generated': record.report_generated,
                'case_reference': record.case_reference or 'N/A'
            })
        
        return JsonResponse({
            'success': True,
            'records': records_data,
            'officer_name': request.user.get_full_name() or request.user.username
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch recent investigations: {str(e)}", exc_info=True)
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
