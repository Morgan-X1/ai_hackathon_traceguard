"""
TraceGuard AI - Graph Neural Network Model
Analyzes transaction networks and account relationships using GraphSAGE
"""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, global_mean_pool
from torch_geometric.data import Data, Batch
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple
from .graph_utils import TransactionGraph


class GraphSAGEModel(nn.Module):
    """
    GraphSAGE for account-level risk scoring.
    Learns from neighborhood aggregation to detect money laundering networks.
    """
    def __init__(self, num_node_features=8, hidden_channels=32):
        super(GraphSAGEModel, self).__init__()
        # GraphSAGE layers
        self.conv1 = SAGEConv(num_node_features, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, hidden_channels)
        self.conv3 = SAGEConv(hidden_channels, 16)
        
        # Account-level prediction head
        self.fc1 = nn.Linear(16, 8)
        self.fc2 = nn.Linear(8, 1)
        self.dropout = nn.Dropout(0.3)
        
    def forward(self, x, edge_index):
        # GraphSAGE layers with neighborhood aggregation
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = self.dropout(x)
        
        x = self.conv3(x, edge_index)
        x = F.relu(x)
        
        # Per-node prediction (account risk scores)
        x = self.fc1(x)
        x = F.relu(x)
        x = self.dropout(x)
        
        x = self.fc2(x)
        return torch.sigmoid(x)  # Output probability [0, 1] per account


class GNNModelLoader:
    """Singleton class to load and manage GraphSAGE model"""
    _instance = None
    _model = None
    _graph_builder = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GNNModelLoader, cls).__new__(cls)
        return cls._instance
    
    def get_model(self):
        """Load GraphSAGE model (lazy loading)"""
        if self._model is None:
            self._model = GraphSAGEModel(num_node_features=8, hidden_channels=32)
            self._model.eval()  # Set to evaluation mode
            print("GraphSAGE model initialized")
        return self._model
    
    def get_graph_builder(self):
        """Get graph builder instance"""
        if self._graph_builder is None:
            self._graph_builder = TransactionGraph()
        return self._graph_builder


def predict_account_risks(transactions_df: pd.DataFrame) -> Tuple[Dict[int, float], TransactionGraph]:
    """
    Predict risk scores for all accounts in the transaction network.
    
    Args:
        transactions_df: DataFrame with transaction features
        
    Returns:
        Tuple of (account_risk_dict, graph_builder)
    """
    try:
        model_loader = GNNModelLoader()
        model = model_loader.get_model()
        graph_builder = TransactionGraph()
        
        # Ensure we have a DataFrame, not a dict or string
        if not isinstance(transactions_df, pd.DataFrame):
            print(f"ERROR: Expected DataFrame, got {type(transactions_df)}")
            return {}, graph_builder
        
        print(f"DEBUG GNN: Building graph from {len(transactions_df)} transactions")
        print(f"DEBUG GNN: DataFrame columns: {transactions_df.columns.tolist()}")
        
        # Build transaction graph
        graph = graph_builder.build_from_transactions(transactions_df)
        
        print(f"DEBUG GNN: Graph built with {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
        
        # Convert to PyTorch Geometric format
        pyg_data, node_mapping = graph_builder.to_pyg_data()
        
        # Run GNN prediction
        with torch.no_grad():
            account_risks = model(pyg_data.x, pyg_data.edge_index)
        
        # Map back to account IDs
        account_risk_dict = {}
        reverse_mapping = {idx: node for node, idx in node_mapping.items()}
        
        for idx, risk in enumerate(account_risks.squeeze().cpu().numpy()):
            account_id = reverse_mapping[idx]
            account_risk_dict[account_id] = float(risk)
        
        # Store risks in graph builder
        graph_builder.account_risk_scores = account_risk_dict
        
        print(f"DEBUG GNN: Generated {len(account_risk_dict)} account risk scores")
        
        return account_risk_dict, graph_builder
        
    except Exception as e:
        import traceback
        print(f"ERROR in predict_account_risks: {str(e)}")
        print(traceback.format_exc())
        # Return empty results on error
        return {}, TransactionGraph()


def calculate_relational_risk(transactions_df: pd.DataFrame, account_risks: Dict[int, float]) -> np.ndarray:
    """
    Calculate relational risk score for each transaction based on account network positions.
    
    Args:
        transactions_df: DataFrame with transactions
        account_risks: Dictionary of account ID -> risk score
        
    Returns:
        Array of relational risk scores per transaction
    """
    relational_risks = []
    
    for idx, row in transactions_df.iterrows():
        # Get sender/receiver from original data or hash (handle pandas Series properly)
        if 'Account' in row.index:
            sender_val = row['Account']
        else:
            sender_val = f'sender_{idx}'
        
        if 'Account.1' in row.index:
            receiver_val = row['Account.1']
        else:
            receiver_val = f'receiver_{idx}'
        
        sender_id = abs(hash(str(sender_val))) % 100000
        receiver_id = abs(hash(str(receiver_val))) % 100000
        
        # Get account risks (default to 0.5 if not found)
        sender_risk = account_risks.get(sender_id, 0.5)
        receiver_risk = account_risks.get(receiver_id, 0.5)
        
        # Combined relational risk (max of sender/receiver)
        relational_risk = max(sender_risk, receiver_risk)
        
        relational_risks.append(relational_risk)
    
    return np.array(relational_risks)


def predict_ensemble(transactions_df: pd.DataFrame, xgb_predictions: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, Dict]:
    """
    Ensemble prediction combining XGBoost (transaction-level) and GNN (account-level).
    
    Args:
        transactions_df: DataFrame with transaction features
        xgb_predictions: XGBoost model predictions (raw probabilities)
        
    Returns:
        Tuple of (ensemble_predictions, gnn_predictions, xgb_predictions, graph_data)
    """
    try:
        # Get account-level risks from GNN
        account_risks, graph_builder = predict_account_risks(transactions_df)
        
        # Calculate relational risk for each transaction
        gnn_predictions = calculate_relational_risk(transactions_df, account_risks)
        
        # Ensemble: weighted combination
        # 60% XGBoost (transaction features) + 40% GNN (network position)
        ensemble_predictions = 0.6 * xgb_predictions + 0.4 * gnn_predictions
        
        # Prepare graph visualization data
        graph_data = {
            'suspicious_patterns': graph_builder.detect_suspicious_patterns(),
            'visualization': graph_builder.export_for_visualization(max_nodes=30),
            'account_risks': account_risks
        }
        
        return ensemble_predictions, gnn_predictions, xgb_predictions, graph_data
        
    except Exception as e:
        import traceback
        print(f"ERROR in predict_ensemble: {str(e)}")
        print(traceback.format_exc())
        
        # Fallback: return XGBoost predictions only
        gnn_fallback = np.zeros_like(xgb_predictions)
        empty_graph_data = {
            'suspicious_patterns': {'circular_flow': [], 'rapid_movement': [], 'structuring': []},
            'visualization': {'nodes': [], 'edges': []},
            'account_risks': {}
        }
        
        return xgb_predictions, gnn_fallback, xgb_predictions, empty_graph_data


def calculate_network_factors(transactions_df: pd.DataFrame, graph_data: Dict, original_transactions: List[Dict] = None) -> Dict[str, float]:
    """
    Calculate network factor multipliers for accounts based on:
    1. Structuring patterns (multiple small transactions)
    2. Mule detection (receivers getting money from multiple senders)
    3. Velocity checks (rapid transactions between same accounts)
    
    Args:
        transactions_df: DataFrame with transaction features
        graph_data: Graph data with suspicious patterns
        original_transactions: Original transaction data with timestamps
        
    Returns:
        Dictionary mapping account ID -> network factor (1.0 to 3.0)
    """
    network_factors = {}
    
    if not isinstance(transactions_df, pd.DataFrame):
        return network_factors
    
    # === 1. MULE DETECTION ===
    # Track receivers and their unique senders
    receiver_senders = {}  # receiver_id -> set of sender_ids
    
    for idx, row in transactions_df.iterrows():
        # Get sender
        sender_id = None
        for col_name in ['Account', 'Sender', 'sender', 'Sender_ID']:
            if col_name in row.index and pd.notna(row[col_name]):
                sender_id = str(row[col_name])
                break
        
        # Get receiver
        receiver_id = None
        for col_name in ['Account.1', 'Receiver', 'receiver', 'Receiver_ID']:
            if col_name in row.index and pd.notna(row[col_name]):
                receiver_id = str(row[col_name])
                break
        
        if sender_id and receiver_id:
            if receiver_id not in receiver_senders:
                receiver_senders[receiver_id] = set()
            receiver_senders[receiver_id].add(sender_id)
    
    # Mule accounts: receivers with 3+ different senders
    for receiver_id, senders in receiver_senders.items():
        if len(senders) >= 3:
            network_factors[receiver_id] = 2.5  # Strong mule indicator
            print(f"DEBUG MULE DETECTED: {receiver_id} received from {len(senders)} different senders")
        elif len(senders) >= 2:
            network_factors[receiver_id] = 2.0  # Potential mule
    
    # === 2. VELOCITY CHECK ===
    # Group transactions by account pairs and check timestamps
    if original_transactions:
        from datetime import datetime, timedelta
        
        account_pairs = {}  # (sender, receiver) -> list of timestamps
        
        for tx in original_transactions:
            # Extract sender/receiver
            sender = tx.get('Account') or tx.get('Sender') or tx.get('Sender_ID')
            receiver = tx.get('Account.1') or tx.get('Receiver') or tx.get('Receiver_ID')
            timestamp_str = tx.get('Timestamp') or tx.get('timestamp')
            
            if sender and receiver:
                pair = (str(sender), str(receiver))
                
                if pair not in account_pairs:
                    account_pairs[pair] = []
                
                # Try to parse timestamp
                if timestamp_str:
                    try:
                        # Handle various timestamp formats
                        if isinstance(timestamp_str, str):
                            if 'T' in timestamp_str or ':' in timestamp_str:
                                ts = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                            else:
                                ts = datetime.strptime(timestamp_str, '%Y-%m-%d')
                        else:
                            ts = timestamp_str
                        account_pairs[pair].append(ts)
                    except:
                        pass
        
        # Check velocity: if same pair has transactions < 1 hour apart
        for (sender, receiver), timestamps in account_pairs.items():
            if len(timestamps) >= 2:
                timestamps.sort()
                for i in range(1, len(timestamps)):
                    time_diff = timestamps[i] - timestamps[i-1]
                    if time_diff < timedelta(hours=1):
                        # Rapid transaction detected
                        current_factor_sender = network_factors.get(sender, 1.0)
                        current_factor_receiver = network_factors.get(receiver, 1.0)
                        
                        network_factors[sender] = max(current_factor_sender, 3.0)
                        network_factors[receiver] = max(current_factor_receiver, 3.0)
                        
                        print(f"DEBUG VELOCITY: Rapid tx between {sender} -> {receiver} ({time_diff.total_seconds()/60:.1f} min)")
                        break
    
    # === 3. STRUCTURING PATTERNS ===
    # Count structuring attempts per account
    structuring_counts = {}
    
    for idx, row in transactions_df.iterrows():
        if 'Is_Structuring_Risk' in row.index and row['Is_Structuring_Risk'] == 1:
            # Get sender
            for col_name in ['Account', 'Sender', 'sender', 'Sender_ID']:
                if col_name in row.index and pd.notna(row[col_name]):
                    account = str(row[col_name])
                    structuring_counts[account] = structuring_counts.get(account, 0) + 1
                    break
            
            # Get receiver
            for col_name in ['Account.1', 'Receiver', 'receiver', 'Receiver_ID']:
                if col_name in row.index and pd.notna(row[col_name]):
                    account = str(row[col_name])
                    structuring_counts[account] = structuring_counts.get(account, 0) + 1
                    break
    
    # Apply structuring-based factors (only if not already higher)
    for account, count in structuring_counts.items():
        if count >= 5:
            factor = 2.5
        elif count >= 3:
            factor = 2.0
        elif count >= 2:
            factor = 1.5
        else:
            factor = 1.2
        
        # Keep the maximum factor
        current_factor = network_factors.get(account, 1.0)
        network_factors[account] = max(current_factor, factor)
    
    print(f"DEBUG NETWORK FACTORS: Calculated factors for {len(network_factors)} accounts")
    print(f"DEBUG NETWORK FACTORS: {dict(list(network_factors.items())[:10])}")
    
    return network_factors
