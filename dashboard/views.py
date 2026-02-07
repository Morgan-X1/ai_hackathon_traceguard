"""
TraceGuard AI - Dashboard Views
Handles transaction form submission and risk prediction
"""
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
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
def dashboard(request):
    """
    Main dashboard view with transaction form and risk prediction.
    """
    context = {
        'form': TransactionForm(),
        'prediction': None,
        'show_results': False,
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
def batch_analysis(request):
    """
    Batch analysis view - upload and analyze multiple transactions.
    Handles partial data - only requires Amount, Sender, Receiver at minimum.
    """
    context = {
        'results': None,
        'summary': None,
        'critical_risk': None,
        'elevated_risk': None,
        'structuring': None,
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
                
                context['results'] = results
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
                    
                    context['results'] = results
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
