"""
TraceGuard AI - Feature Engineering and Mapping
Handles incomplete transaction data and fills missing features
"""
import pandas as pd
import numpy as np
from typing import Dict, List


# Default values for YOUR model's features
FEATURE_DEFAULTS = {
    'Amount Received': 1000.0,
    'Amount Paid': 1000.0,
    'Amount_USD': 1000.0,
    'Is_Structuring_Risk': 0,
    'Is_Round_Amount': 0,
    'Account_Activity_Count': 5,  # Average activity
    'Relative_Amount': 0.5,  # Mid-range relative amount
    'Is_New_Counterparty': 0,  # Existing counterparty (safer)
    'Activity_Intensity': 0.3,  # Low-medium activity
    'PF_ACH': 0,
    'PF_Bitcoin': 0,
    'PF_Cash': 0,
    'PF_Cheque': 0,
    'PF_Credit Card': 0,
    'PF_Reinvestment': 0,
    'PF_Wire': 1,  # Default to wire transfer
}

# Expected feature order for YOUR ACTUAL model
FEATURE_ORDER = [
    'Amount Received',
    'Amount Paid', 
    'Amount_USD',
    'Is_Structuring_Risk',
    'Is_Round_Amount',
    'Account_Activity_Count',
    'Relative_Amount',
    'Is_New_Counterparty',
    'Activity_Intensity',
    'PF_ACH',
    'PF_Bitcoin',
    'PF_Cash',
    'PF_Cheque',
    'PF_Credit Card',
    'PF_Reinvestment',
    'PF_Wire',
]

# Column name mappings for YOUR bank data format
COLUMN_MAPPINGS = {
    'amount r': 'Amount Received',
    'amount received': 'Amount Received',
    'amountr': 'Amount Received',
    'receiving': 'Amount Received',
    'amount p': 'Amount Paid',
    'amount paid': 'Amount Paid',
    'amountp': 'Amount Paid',
    'payment c': 'Amount_USD',  # Payment Currency -> Amount in USD
    'paymentc': 'Amount_USD',
    'amount': 'Amount_USD',
    'amount_usd': 'Amount_USD',
    'payment f': 'payment_format',  # Will be one-hot encoded
    'paymentf': 'payment_format',
    'payment format': 'payment_format',
}

# Payment type mappings (for bank data)
PAYMENT_TYPE_MAPPINGS = {
    'reinvestment': 0,
    'wire transfer': 0,
    'wire': 0,
    'ach': 1,
    'check': 2,
    'cash': 3,
    'card': 4,
    'transfer': 0,
    'payment': 0,
}


def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize column names to standard format.
    
    Args:
        df: Input DataFrame with user column names
        
    Returns:
        DataFrame with standardized column names
    """
    df_normalized = df.copy()
    
    print(f"DEBUG normalize: Input columns: {df_normalized.columns.tolist()}")
    
    # Convert to lowercase and strip whitespace
    df_normalized.columns = df_normalized.columns.str.lower().str.strip()
    
    print(f"DEBUG normalize: After lowercase: {df_normalized.columns.tolist()}")
    
    # Map alternative column names
    rename_dict = {}
    for col in df_normalized.columns:
        if col in COLUMN_MAPPINGS:
            rename_dict[col] = COLUMN_MAPPINGS[col]
        elif col.replace('_', '').replace(' ', '') in COLUMN_MAPPINGS:
            rename_dict[col] = COLUMN_MAPPINGS[col.replace('_', '').replace(' ', '')]
    
    print(f"DEBUG normalize: Rename dict: {rename_dict}")
    
    df_normalized.rename(columns=rename_dict, inplace=True)
    
    print(f"DEBUG normalize: After rename: {df_normalized.columns.tolist()}")
    
    # Remove old code that handled Sender_ID/Receiver_ID conversion
    # (not needed for this model)
    
    return df_normalized


def calculate_rule_based_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate rule-based and derived features for YOUR model.
    
    Args:
        df: DataFrame with transaction data
        
    Returns:
        DataFrame with calculated features
    """
    df_enhanced = df.copy()
    
    # Ensure Amount columns exist and are numeric
    for col in ['Amount Received', 'Amount Paid']:
        if col in df_enhanced.columns:
            if isinstance(df_enhanced[col], pd.DataFrame):
                amount_series = df_enhanced[col].iloc[:, 0]
                df_enhanced = df_enhanced.loc[:, ~df_enhanced.columns.duplicated()]
                df_enhanced[col] = amount_series
            df_enhanced[col] = pd.to_numeric(df_enhanced[col], errors='coerce').fillna(1000.0)
    
    # Use Amount Received as primary amount
    if 'Amount Received' in df_enhanced.columns:
        amount_col = df_enhanced['Amount Received']
    elif 'Amount Paid' in df_enhanced.columns:
        amount_col = df_enhanced['Amount Paid']
    else:
        amount_col = pd.Series([1000.0] * len(df_enhanced))
    
    # Set Amount_USD (same as primary amount if not specified)
    if 'Amount_USD' not in df_enhanced.columns:
        df_enhanced['Amount_USD'] = amount_col
    
    # Rule 1: Structuring Risk Detection (amounts near $10K)
    df_enhanced['Is_Structuring_Risk'] = (
        (amount_col >= 9000) & (amount_col <= 9999)
    ).astype(int)
    
    # Rule 2: Round Amount Detection (multiples of 100)
    df_enhanced['Is_Round_Amount'] = (
        amount_col % 100 == 0
    ).astype(int)
    
    # Rule 3: One-hot encode Payment Format
    if 'payment_format' in df_enhanced.columns:
        # Initialize all PF_ columns to 0
        for pf in ['PF_ACH', 'PF_Bitcoin', 'PF_Cash', 'PF_Cheque', 'PF_Credit Card', 'PF_Reinvestment', 'PF_Wire']:
            df_enhanced[pf] = 0
        
        # Set the appropriate column to 1 based on payment format
        payment_map = {
            'ach': 'PF_ACH',
            'bitcoin': 'PF_Bitcoin',
            'cash': 'PF_Cash',
            'cheque': 'PF_Cheque',
            'check': 'PF_Cheque',
            'credit card': 'PF_Credit Card',
            'card': 'PF_Credit Card',
            'reinvestment': 'PF_Reinvestment',
            'wire': 'PF_Wire',
            'wire transfer': 'PF_Wire',
        }
        
        for idx, pf_value in df_enhanced['payment_format'].items():
            pf_lower = str(pf_value).lower().strip()
            if pf_lower in payment_map:
                df_enhanced.loc[idx, payment_map[pf_lower]] = 1
        
        # Remove the temporary payment_format column
        df_enhanced.drop('payment_format', axis=1, inplace=True)
    
    return df_enhanced


def fill_missing_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fill missing features with logical defaults.
    
    Args:
        df: DataFrame with partial transaction data
        
    Returns:
        DataFrame with all 16 required features
    """
    df_complete = df.copy()
    
    # Add missing columns with defaults
    for feature in FEATURE_ORDER:
        if feature not in df_complete.columns:
            df_complete[feature] = FEATURE_DEFAULTS[feature]
    
    # Fill NaN values with defaults
    for feature in FEATURE_ORDER:
        if df_complete[feature].isna().any():
            df_complete[feature].fillna(FEATURE_DEFAULTS[feature], inplace=True)
    
    # Ensure correct data types
    numeric_features = ['Amount Received', 'Amount Paid', 'Amount_USD', 'Relative_Amount', 'Activity_Intensity']
    integer_features = [f for f in FEATURE_ORDER if f not in numeric_features]
    
    for feature in numeric_features:
        df_complete[feature] = pd.to_numeric(df_complete[feature], errors='coerce').fillna(FEATURE_DEFAULTS.get(feature, 0))
    
    for feature in integer_features:
        df_complete[feature] = pd.to_numeric(df_complete[feature], errors='coerce').fillna(FEATURE_DEFAULTS.get(feature, 0)).astype(int)
    
    # Reorder columns to match model expectations
    df_complete = df_complete[FEATURE_ORDER]
    
    return df_complete


def prepare_transactions_for_model(data: List[Dict]) -> pd.DataFrame:
    """
    Complete pipeline: normalize, calculate rules, fill missing features.
    
    Args:
        data: List of transaction dictionaries (partial data OK)
        
    Returns:
        DataFrame ready for XGBoost model with all 16 features
    """
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Step 1: Normalize column names
    df = normalize_column_names(df)
    
    # Step 2: Calculate rule-based features
    df = calculate_rule_based_features(df)
    
    # Step 3: Fill missing features with defaults
    df = fill_missing_features(df)
    
    return df


def categorize_risk_level(risk_score: float) -> tuple[str, str]:
    """
    Categorize risk score into levels with emoji indicators.
    
    Args:
        risk_score: Risk score from 0-100
        
    Returns:
        Tuple of (category, emoji)
    """
    if risk_score > 40:
        return '🚨 CRITICAL', 'critical'
    elif risk_score >= 15:
        return '⚠️ ELEVATED', 'elevated'
    else:
        return '✅ LOW', 'low'


def calculate_risk_index(model_output: float) -> float:
    """
    Convert model output to 0-100 Risk Index.
    
    Args:
        model_output: Raw model prediction (can be negative, typically -2 to +2 for XGBoost)
        
    Returns:
        Risk index scaled to 0-100
    """
    # Debug the input
    print(f"DEBUG calculate_risk_index: Input = {model_output}")
    
    # XGBoost outputs raw scores (logits), need to convert to probability
    # Using sigmoid function: 1 / (1 + e^(-x))
    import math
    try:
        probability = 1 / (1 + math.exp(-model_output))
    except OverflowError:
        # Handle extreme values
        probability = 1.0 if model_output > 0 else 0.0
    
    # Scale to 0-100
    risk_index = min(probability * 100, 100.0)
    
    print(f"DEBUG calculate_risk_index: Probability = {probability}, Risk Index = {risk_index}")
    
    return round(risk_index, 2)
