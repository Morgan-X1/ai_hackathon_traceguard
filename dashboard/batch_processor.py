"""
TraceGuard AI - Batch Transaction Processing
Automatically analyze multiple transactions from CSV/JSON files
Uses both XGBoost and GNN models for ensemble predictions
"""
import csv
import json
import pandas as pd
import xgboost as xgb
import numpy as np
from typing import List, Dict
from django.conf import settings
from .utils import ModelLoader
from .gnn_model import predict_ensemble, calculate_network_factors
from .graph_utils import TransactionGraph
from .feature_engineering import (
    prepare_transactions_for_model,
    calculate_risk_index,
    categorize_risk_level,
    FEATURE_ORDER
)


def get_flag_reason(xgb_score_base, gnn_score, is_structuring_risk, network_factor, amount):
    """
    Generate human-readable explanation for why a transaction was flagged.
    
    Args:
        xgb_score_base: Base XGBoost score (0-100)
        gnn_score: GNN score (0-100)
        is_structuring_risk: Boolean flag for structuring
        network_factor: Network multiplier (1.0+)
        amount: Transaction amount
        
    Returns:
        String explaining the flagging reason
    """
    reasons = []
    
    # Check structuring first (highest priority)
    if is_structuring_risk:
        reasons.append("🎯 Potential Structuring: Near $10k limit")
    
    # Check GNN score for relational risk
    if gnn_score > 60:
        if amount < 1000:  # Low amount but high GNN
            reasons.append("🔗 Relational Risk: Linked to suspicious account network")
        else:
            reasons.append("🔗 Network Pattern: Part of high-risk transaction network")
    
    # Check for high fusion risk (both high)
    if xgb_score_base > 60 and gnn_score > 60:
        reasons.append("⚠️ High Fusion Risk: Suspicious amount and network history")
    
    # Check network factor boosting
    if network_factor >= 3.0:
        reasons.append("⚡ Velocity Alert: Rapid transactions detected (<1 hour)")
    elif network_factor >= 2.5:
        reasons.append("👥 Mule Pattern: Multiple senders to same receiver")
    elif network_factor > 1.0:
        reasons.append("📊 Network Boost: Connected to suspicious patterns")
    
    # Check for high XGB but normal GNN
    if xgb_score_base > 60 and gnn_score <= 60:
        reasons.append("💰 Transaction Risk: Amount/pattern flags detected")
    
    # If no specific reasons, provide general assessment
    if not reasons:
        if xgb_score_base > 40 or gnn_score > 40:
            reasons.append("⚠️ Elevated Risk: Multiple moderate risk indicators")
        else:
            reasons.append("✅ Low Risk: Standard transaction profile")
    
    # Return the most relevant reason (first one)
    return reasons[0]

def process_transaction_list(transactions: List[Dict]) -> List[Dict]:
    """
    Process a list of transactions and return risk assessments for each.
    Handles partial data - fills missing features automatically.
    
    Args:
        transactions: List of transaction dictionaries (partial data OK)
        
    Returns:
        List of dictionaries containing transaction data and risk assessment
    """
    results = []
    
    try:
        # Debug: Print what we received
        print(f"DEBUG: Processing {len(transactions)} transactions")
        print(f"DEBUG: First transaction: {transactions[0] if transactions else 'EMPTY'}")
        
        # Step 1: Prepare all transactions with feature engineering
        df_complete = prepare_transactions_for_model(transactions)
        print(f"DEBUG: DataFrame shape after preparation: {df_complete.shape}")
        print(f"DEBUG: DataFrame columns: {df_complete.columns.tolist()}")
        
        # Step 2: Load XGBoost model
        model_loader = ModelLoader()
        model = model_loader.get_model()
        
        # Step 3: Create DMatrix for prediction
        dmatrix = xgb.DMatrix(df_complete.values, feature_names=FEATURE_ORDER)
        
        # Step 4: Get predictions for all transactions at once
        predictions = model.predict(dmatrix)
        
        # Step 4.5: Get GNN predictions and ensemble with graph data
        ensemble_preds, gnn_preds, xgb_preds, graph_data = predict_ensemble(df_complete, predictions)
        
        # Step 4.6: Calculate network factors for structuring accounts, mules, and velocity
        network_factors = calculate_network_factors(df_complete, graph_data, transactions)
        
        print(f"DEBUG: XGBoost predictions: {xgb_preds[:3]}")
        print(f"DEBUG: GNN predictions: {gnn_preds[:3]}")
        print(f"DEBUG: Ensemble predictions: {ensemble_preds[:3]}")
        print(f"DEBUG: Network factors calculated: {len(network_factors)} accounts")
        print(f"DEBUG: Graph data type: {type(graph_data)}")
        print(f"DEBUG: Graph data available: {graph_data is not None and isinstance(graph_data, dict)}")
        
        # Step 5: Process each result with network factors
        for idx, (_, row) in enumerate(df_complete.iterrows()):
            try:
                # Get original transaction for account IDs
                original_transaction = transactions[idx] if idx < len(transactions) else {}
                
                # Extract account IDs
                sender_id = original_transaction.get('Account', original_transaction.get('Sender', f'ACCT_{idx}_S'))
                receiver_id = original_transaction.get('Account.1', original_transaction.get('Receiver', f'ACCT_{idx}_R'))
                
                # Use ensemble prediction
                raw_prediction = float(ensemble_preds[idx])
                xgb_score_base = calculate_risk_index(float(xgb_preds[idx]))
                gnn_score = calculate_risk_index(float(gnn_preds[idx]))
                
                # Apply network factor if account has structuring pattern
                sender_factor = network_factors.get(sender_id, 1.0)
                receiver_factor = network_factors.get(receiver_id, 1.0)
                max_network_factor = max(sender_factor, receiver_factor)
                
                # FUSION SCORE: Apply network multiplier to XGBoost score
                # This boosts the score for accounts with suspicious network patterns
                xgb_score = min(xgb_score_base * max_network_factor, 100.0)  # Cap at 100
                
                # Final risk index: weighted combination with network-boosted XGBoost
                risk_index = min(xgb_score, 100.0)  # Use network-boosted score as primary
                
                # Force CRITICAL if network factor is high
                if max_network_factor >= 2.5:
                    risk_index = max(risk_index, 75.0)  # Ensure CRITICAL threshold
                
                # Override risk category for high network factors
                if max_network_factor > 1.0:
                    # Force CRITICAL for transactions with network boost
                    risk_category = '🚨 CRITICAL'
                    risk_class = 'critical'
                    risk_index = max(risk_index, 65.0)  # Ensure elevated minimum
                else:
                    # Normal categorization
                    risk_category, risk_class = categorize_risk_level(risk_index)
                
                print(f"DEBUG: Transaction {idx+1} - Base XGB: {xgb_score_base}, Network: {max_network_factor}x, Final: {xgb_score}, Risk: {risk_index}")
                
                print(f"DEBUG: Category: {risk_category}, Class: {risk_class}")
                
                # Generate explainability reason
                flag_reason = get_flag_reason(
                    xgb_score_base=xgb_score_base,
                    gnn_score=gnn_score,
                    is_structuring_risk=(row['Is_Structuring_Risk'] == 1),
                    network_factor=max_network_factor,
                    amount=row.get('Amount Received', row.get('Amount Paid', 0))
                )
                
                # Enhanced transaction with all features
                complete_transaction = row.to_dict()
                complete_transaction['Sender'] = sender_id
                complete_transaction['Receiver'] = receiver_id
                complete_transaction['network_factor'] = max_network_factor
                complete_transaction['sender_centrality'] = graph_data.get('account_risks', {}).get(
                    abs(hash(str(sender_id))) % 100000, 0
                ) if graph_data else 0
                complete_transaction['receiver_centrality'] = graph_data.get('account_risks', {}).get(
                    abs(hash(str(receiver_id))) % 100000, 0
                ) if graph_data else 0
                
                results.append({
                    'transaction_id': idx + 1,
                    'status': 'success',
                    'original_data': original_transaction,
                    'transaction': complete_transaction,  # Template expects 'transaction'
                    'risk_assessment': {
                        'risk_score': risk_index,
                        'risk_level': risk_category,
                        'risk_class': risk_class,
                        'raw_prediction': raw_prediction,
                        'xgb_score': xgb_score,
                        'xgb_score_base': xgb_score_base,
                        'gnn_score': gnn_score,
                        'network_factor': max_network_factor,
                        'model_type': 'Ensemble (XGBoost + GNN + Network Factor)',
                        'is_structuring_risk': complete_transaction['Is_Structuring_Risk'] == 1,
                        'is_round_amount': complete_transaction['Is_Round_Amount'] == 1,
                        'amount': complete_transaction.get('Amount Received', complete_transaction.get('Amount Paid', 0)),
                        'sender': sender_id,
                        'receiver': receiver_id,
                        'sender_centrality': complete_transaction['sender_centrality'],
                        'receiver_centrality': complete_transaction['receiver_centrality'],
                        'reasoning': flag_reason,  # Add reasoning
                    }
                })
                
            except Exception as e:
                import traceback
                error_details = traceback.format_exc()
                print(f"DEBUG ERROR in transaction {idx+1}: {str(e)}")
                print(f"DEBUG TRACEBACK: {error_details}")
                original = transactions[idx] if idx < len(transactions) else {}
                results.append({
                    'transaction_id': idx + 1,
                    'status': 'error',
                    'error': f"Error processing transaction: {str(e)}",
                    'original_data': original,
                    'transaction': original  # Template expects this key
                })
    
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"DEBUG BATCH ERROR: {str(e)}")
        print(f"DEBUG BATCH TRACEBACK: {error_details}")
        # If batch processing fails, process individually
        for idx, transaction in enumerate(transactions):
            results.append({
                'transaction_id': idx + 1,
                'status': 'error',
                'error': f"Batch processing error: {str(e)}",
                'original_data': transaction,
                'transaction': transaction  # Template expects this key
            })
        graph_data = None
    
    # Return results with graph data for visualization
    return {
        'results': results,
        'graph_data': graph_data if 'graph_data' in locals() else None
    }


def analyze_csv_file(file_path: str) -> List[Dict]:
    """
    Read transactions from CSV file and analyze them.
    Handles partial data - any columns are OK.
    
    Args:
        file_path: Path to CSV file
        
    Returns:
        List of risk assessment results
    """
    # Read CSV into DataFrame
    df = pd.read_csv(file_path)
    
    # Convert DataFrame to list of dictionaries
    transactions = df.to_dict('records')
    
    return process_transaction_list(transactions)


def analyze_json_file(file_path: str) -> List[Dict]:
    """
    Read transactions from JSON file and analyze them.
    
    JSON should be array of transaction objects or object with 'transactions' key.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        List of risk assessment results
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Handle different JSON structures
    if isinstance(data, list):
        transactions = data
    elif isinstance(data, dict) and 'transactions' in data:
        transactions = data['transactions']
    else:
        raise ValueError("JSON must be array or object with 'transactions' key")
    
    return process_transaction_list(transactions)


def get_high_risk_transactions(results: List[Dict], threshold: float = 40.0) -> List[Dict]:
    """
    Filter transactions by risk threshold.
    
    Args:
        results: List of transaction results
        threshold: Risk score threshold (default 40.0 for CRITICAL)
        
    Returns:
        List of high-risk transactions
    """
    high_risk = []
    
    for result in results:
        if result['status'] == 'success':
            risk_score = result['risk_assessment']['risk_score']
            if risk_score >= threshold:
                high_risk.append(result)
    
    return high_risk


def get_elevated_risk_transactions(results: List[Dict]) -> List[Dict]:
    """
    Filter transactions with elevated risk (15-40).
    
    Args:
        results: List of transaction results
        
    Returns:
        List of elevated-risk transactions
    """
    elevated = []
    
    for result in results:
        if result['status'] == 'success':
            risk_score = result['risk_assessment']['risk_score']
            if 15 <= risk_score < 40:
                elevated.append(result)
    
    return elevated


def get_structuring_transactions(results: List[Dict]) -> List[Dict]:
    """
    Filter transactions with structuring risk.
    
    Args:
        results: List of transaction results
        
    Returns:
        List of transactions with structuring risk
    """
    structuring = []
    
    for result in results:
        if result['status'] == 'success':
            if result['risk_assessment']['is_structuring_risk']:
                structuring.append(result)
    
    return structuring


def generate_summary_report(results: List[Dict]) -> Dict:
    """
    Generate summary statistics from batch analysis.
    
    Args:
        results: List of transaction results
        
    Returns:
        Dictionary with summary statistics
    """
    total = len(results)
    successful = sum(1 for r in results if r['status'] == 'success')
    errors = total - successful
    
    if successful == 0:
        return {
            'total_transactions': total,
            'successful_analysis': 0,
            'errors': errors,
            'error_rate': 100.0 if total > 0 else 0,
        }
    
    risk_scores = [r['risk_assessment']['risk_score'] 
                   for r in results if r['status'] == 'success']
    
    # Updated risk categories
    low_risk = sum(1 for r in results 
                   if r['status'] == 'success' and r['risk_assessment']['risk_class'] == 'low')
    elevated_risk = sum(1 for r in results 
                        if r['status'] == 'success' and r['risk_assessment']['risk_class'] == 'elevated')
    critical_risk = sum(1 for r in results 
                        if r['status'] == 'success' and r['risk_assessment']['risk_class'] == 'critical')
    
    structuring_count = sum(1 for r in results 
                           if r['status'] == 'success' and r['risk_assessment']['is_structuring_risk'])
    
    round_amount_count = sum(1 for r in results 
                            if r['status'] == 'success' and r['risk_assessment']['is_round_amount'])
    
    # Count accounts with network factor boost
    network_boosted = sum(1 for r in results 
                         if r['status'] == 'success' and r['risk_assessment'].get('network_factor', 1.0) > 1.0)
    
    return {
        'total_transactions': total,
        'successful_analysis': successful,
        'errors': errors,
        'error_rate': (errors / total * 100) if total > 0 else 0,
        'risk_distribution': {
            'low': low_risk,
            'elevated': elevated_risk,
            'critical': critical_risk,
        },
        'risk_percentages': {
            'low': (low_risk / successful * 100) if successful > 0 else 0,
            'elevated': (elevated_risk / successful * 100) if successful > 0 else 0,
            'critical': (critical_risk / successful * 100) if successful > 0 else 0,
        },
        'risk_scores': {
            'average': sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            'minimum': min(risk_scores) if risk_scores else 0,
            'maximum': max(risk_scores) if risk_scores else 0,
        },
        'structuring_detected': structuring_count,
        'structuring_percentage': (structuring_count / successful * 100) if successful > 0 else 0,
        'round_amounts': round_amount_count,
        'network_boosted': network_boosted,
    }
