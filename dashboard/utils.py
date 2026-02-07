"""
TraceGuard AI - Model Utilities
Handles XGBoost model loading and risk prediction
"""
import json
import numpy as np
import xgboost as xgb
from django.conf import settings
from typing import Dict, Union
import logging

logger = logging.getLogger(__name__)

# Expected feature order for the model (16 features)
FEATURE_NAMES = [
    'Amount',
    'Sender_ID',
    'Receiver_ID',
    'Tx_Type',
    'Location',
    'Device_ID',
    'IP_Prefix',
    'Is_High_Risk_Country',
    'Is_Proxy',
    'Transaction_Frequency',
    'Avg_Transaction_Amount',
    'Is_Round_Amount',
    'Is_Structuring_Risk',
    'Time_Since_Last_Tx',
    'Sender_Receiver_Relationship',
    'Account_Age_Days'
]


class ModelLoader:
    """Singleton class to load and cache the XGBoost model"""
    _instance = None
    _model = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelLoader, cls).__new__(cls)
        return cls._instance
    
    def load_model(self):
        """Load the XGBoost model from JSON file"""
        if self._model is None:
            try:
                model_path = settings.MODEL_PATH
                logger.info(f"Loading model from {model_path}")
                
                # Load XGBoost model from JSON
                self._model = xgb.Booster()
                self._model.load_model(str(model_path))
                
                logger.info("Model loaded successfully")
            except Exception as e:
                logger.error(f"Error loading model: {str(e)}")
                raise
        return self._model
    
    def get_model(self):
        """Get the loaded model"""
        if self._model is None:
            return self.load_model()
        return self._model


def align_features(data: Dict[str, Union[float, int]]) -> np.ndarray:
    """
    Align input data dictionary to the correct feature order expected by the model.
    
    Args:
        data: Dictionary containing transaction features
        
    Returns:
        numpy array with features in correct order
    """
    feature_vector = []
    
    for feature_name in FEATURE_NAMES:
        if feature_name not in data:
            raise ValueError(f"Missing required feature: {feature_name}")
        feature_vector.append(float(data[feature_name]))
    
    return np.array(feature_vector).reshape(1, -1)


def predict_risk(data: Dict[str, Union[float, int]]) -> Dict[str, Union[float, str]]:
    """
    Predict risk score for a transaction.
    
    Args:
        data: Dictionary containing 16 transaction features
        
    Returns:
        Dictionary containing:
            - risk_score: Normalized risk score from 0 to 100
            - risk_level: Risk category (Low, Medium, High)
            - raw_prediction: Raw model output
            - is_structuring_risk: Boolean flag for structuring risk
    """
    try:
        # Load model
        model_loader = ModelLoader()
        model = model_loader.get_model()
        
        # Align features to correct order
        feature_vector = align_features(data)
        
        # Convert to DMatrix for XGBoost prediction
        dmatrix = xgb.DMatrix(feature_vector, feature_names=FEATURE_NAMES)
        
        # Get prediction
        raw_prediction = model.predict(dmatrix)[0]
        
        # Normalize to 0-100 scale
        # Assuming model outputs probability or score between 0 and 1
        if raw_prediction <= 1.0:
            risk_score = float(raw_prediction * 100)
        else:
            # If model outputs raw scores, normalize them
            risk_score = min(float(raw_prediction * 10), 100.0)
        
        # Ensure risk_score is between 0 and 100
        risk_score = max(0.0, min(100.0, risk_score))
        
        # Determine risk level
        if risk_score < 10:
            risk_level = 'Low'
        elif risk_score < 40:
            risk_level = 'Medium'
        else:
            risk_level = 'High'
        
        # Check for structuring risk (transactions near $10,000)
        amount = float(data.get('Amount', 0))
        is_structuring_risk = data.get('Is_Structuring_Risk', 0) == 1 or (9000 <= amount <= 10500)
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'raw_prediction': float(raw_prediction),
            'is_structuring_risk': is_structuring_risk,
            'amount': amount,
            'features': data
        }
        
    except Exception as e:
        logger.error(f"Error during prediction: {str(e)}")
        raise


def get_risk_color(risk_score: float) -> str:
    """
    Get color code based on risk score.
    
    Args:
        risk_score: Risk score from 0 to 100
        
    Returns:
        Color code (green, amber, red)
    """
    if risk_score < 10:
        return 'green'
    elif risk_score < 40:
        return 'amber'
    else:
        return 'red'


def validate_transaction_data(data: Dict) -> tuple[bool, str]:
    """
    Validate transaction data before prediction.
    
    Args:
        data: Transaction data dictionary
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Check if all required features are present
    missing_features = [f for f in FEATURE_NAMES if f not in data]
    if missing_features:
        return False, f"Missing required features: {', '.join(missing_features)}"
    
    # Validate Amount
    try:
        amount = float(data['Amount'])
        if amount < 0:
            return False, "Amount must be positive"
    except (ValueError, TypeError):
        return False, "Invalid amount value"
    
    # Validate binary fields
    binary_fields = ['Is_High_Risk_Country', 'Is_Proxy', 'Is_Round_Amount', 'Is_Structuring_Risk']
    for field in binary_fields:
        if field in data and data[field] not in [0, 1, '0', '1', True, False]:
            return False, f"{field} must be 0 or 1"
    
    return True, ""
