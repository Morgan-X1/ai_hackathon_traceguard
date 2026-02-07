"""
TraceGuard AI - Graph Construction Utilities
Converts transaction database into directed graph for GNN analysis
"""
import pandas as pd
import numpy as np
import networkx as nx
import torch
from torch_geometric.data import Data
from torch_geometric.utils import from_networkx
from typing import Dict, List, Tuple
from datetime import datetime
import json


class TransactionGraph:
    """Build and manage transaction network graph"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.account_features = {}
        self.account_risk_scores = {}
    
    def build_from_transactions(self, transactions_df: pd.DataFrame) -> nx.DiGraph:
        """
        Convert transactions DataFrame into directed graph.
        
        Args:
            transactions_df: DataFrame with transaction data
            
        Returns:
            NetworkX directed graph
        """
        # Validate input
        if not isinstance(transactions_df, pd.DataFrame):
            print(f"ERROR GRAPH: Expected DataFrame, got {type(transactions_df)}")
            return self.graph
        
        print(f"DEBUG GRAPH: Building from {len(transactions_df)} transactions")
        
        # Extract account IDs from transaction data
        # Assuming we have sender/receiver info in the original data
        for idx, row in transactions_df.iterrows():
            try:
                # Use hash of account strings if available, or create dummy IDs
                sender_id = self._get_account_id(row, 'sender')
                receiver_id = self._get_account_id(row, 'receiver')
            
                # Add nodes if they don't exist
                if not self.graph.has_node(sender_id):
                    self.graph.add_node(sender_id, account_type='sender', 
                                       total_sent=0, total_received=0, 
                                       transaction_count=0)
                
                if not self.graph.has_node(receiver_id):
                    self.graph.add_node(receiver_id, account_type='receiver',
                                       total_sent=0, total_received=0,
                                       transaction_count=0)
                
                # Get amount (handle pandas Series properly)
                if 'Amount Received' in row.index:
                    amount = row['Amount Received']
                elif 'Amount Paid' in row.index:
                    amount = row['Amount Paid']
                else:
                    amount = 0
                
                # Add edge (transaction)
                if self.graph.has_edge(sender_id, receiver_id):
                    # Update existing edge
                    self.graph[sender_id][receiver_id]['weight'] += 1
                    self.graph[sender_id][receiver_id]['total_amount'] += amount
                    self.graph[sender_id][receiver_id]['amounts'].append(amount)
                else:
                    # Create new edge
                    self.graph.add_edge(sender_id, receiver_id,
                                      weight=1,
                                      total_amount=amount,
                                      amounts=[amount],
                                      timestamp=idx)
                
                # Update node statistics
                self.graph.nodes[sender_id]['total_sent'] += amount
                self.graph.nodes[sender_id]['transaction_count'] += 1
                self.graph.nodes[receiver_id]['total_received'] += amount
                self.graph.nodes[receiver_id]['transaction_count'] += 1
                
            except Exception as e:
                print(f"ERROR GRAPH: Failed to process transaction {idx}: {str(e)}")
                import traceback
                traceback.print_exc()
                continue
        
        print(f"DEBUG GRAPH: Built graph with {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        return self.graph
    
    def _get_account_id(self, row, account_type):
        """Extract or generate account ID from transaction row"""
        # Try multiple possible column names
        if account_type == 'sender':
            candidates = ['Sender_ID', 'sender', 'from', 'Account', 'from_account']
        else:
            candidates = ['Receiver_ID', 'receiver', 'to', 'Account.1', 'to_account']
        
        for col in candidates:
            if col in row.index and pd.notna(row[col]):
                # Hash string IDs to integers
                if isinstance(row[col], str):
                    return abs(hash(row[col])) % 100000
                return int(row[col])
        
        # Fallback: use index-based ID
        return hash(f"{account_type}_{row.name}") % 100000
    
    def calculate_graph_features(self) -> Dict:
        """
        Calculate graph-based features for each account.
        
        Returns:
            Dictionary mapping account_id to feature vector
        """
        features = {}
        
        for node in self.graph.nodes():
            node_data = self.graph.nodes[node]
            
            # Centrality measures
            in_degree = self.graph.in_degree(node)
            out_degree = self.graph.out_degree(node)
            
            # Calculate PageRank (accounts receiving from many sources)
            pagerank = nx.pagerank(self.graph).get(node, 0)
            
            # Clustering coefficient (how interconnected neighbors are)
            try:
                clustering = nx.clustering(self.graph.to_undirected(), node)
            except:
                clustering = 0
            
            # Transaction statistics
            total_sent = node_data.get('total_sent', 0)
            total_received = node_data.get('total_received', 0)
            tx_count = node_data.get('transaction_count', 0)
            
            # Calculate velocity (transaction frequency)
            velocity = tx_count / max(1, total_sent + total_received) * 1000
            
            # Structuring indicator (many small transactions)
            avg_amount = (total_sent + total_received) / max(1, tx_count)
            structuring_score = 1.0 if avg_amount < 10000 and tx_count > 5 else 0.0
            
            # Build feature vector [8 features]
            feature_vector = [
                in_degree / 10.0,           # Normalized in-degree
                out_degree / 10.0,          # Normalized out-degree
                pagerank * 100,             # Scaled PageRank
                clustering,                 # Clustering coefficient
                np.log1p(total_sent) / 10,  # Log-scaled sent amount
                np.log1p(total_received) / 10, # Log-scaled received
                velocity,                   # Transaction velocity
                structuring_score           # Structuring indicator
            ]
            
            features[node] = feature_vector
        
        self.account_features = features
        return features
    
    def to_pyg_data(self) -> Data:
        """
        Convert NetworkX graph to PyTorch Geometric Data object.
        
        Returns:
            PyTorch Geometric Data object
        """
        # Calculate features first
        if not self.account_features:
            self.calculate_graph_features()
        
        # Create node feature matrix
        node_mapping = {node: idx for idx, node in enumerate(self.graph.nodes())}
        num_nodes = len(node_mapping)
        
        # Initialize feature matrix
        x = torch.zeros((num_nodes, 8), dtype=torch.float)
        
        for node, idx in node_mapping.items():
            if node in self.account_features:
                x[idx] = torch.tensor(self.account_features[node], dtype=torch.float)
        
        # Create edge index
        edge_index = []
        edge_attr = []
        
        for src, dst, data in self.graph.edges(data=True):
            src_idx = node_mapping[src]
            dst_idx = node_mapping[dst]
            edge_index.append([src_idx, dst_idx])
            
            # Edge features: [weight, log_amount]
            edge_attr.append([
                data.get('weight', 1),
                np.log1p(data.get('total_amount', 0))
            ])
        
        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(edge_attr, dtype=torch.float)
        
        # Create PyG Data object
        data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr)
        
        return data, node_mapping
    
    def detect_suspicious_patterns(self) -> Dict:
        """
        Detect suspicious transaction patterns.
        
        Returns:
            Dictionary with suspicious patterns found
        """
        suspicious_patterns = {
            'rapid_movement': [],
            'circular_flow': [],
            'structuring': [],
            'high_velocity': []
        }
        
        # Find cycles (circular money flow)
        try:
            cycles = list(nx.simple_cycles(self.graph))
            for cycle in cycles[:10]:  # Limit to top 10
                if len(cycle) >= 3:  # At least 3 accounts in cycle
                    suspicious_patterns['circular_flow'].append(cycle)
        except:
            pass
        
        # Find rapid movement chains
        for node in self.graph.nodes():
            out_edges = list(self.graph.out_edges(node, data=True))
            if len(out_edges) > 5:  # Account sending to many others
                total_amount = sum(e[2].get('total_amount', 0) for e in out_edges)
                if total_amount > 50000:  # High total
                    suspicious_patterns['rapid_movement'].append({
                        'account': node,
                        'recipients': len(out_edges),
                        'total_amount': total_amount
                    })
        
        # Find structuring patterns
        for node in self.graph.nodes():
            tx_count = self.graph.nodes[node].get('transaction_count', 0)
            total = (self.graph.nodes[node].get('total_sent', 0) + 
                    self.graph.nodes[node].get('total_received', 0))
            avg = total / max(1, tx_count)
            
            if tx_count > 10 and 9000 <= avg <= 9999:
                suspicious_patterns['structuring'].append({
                    'account': node,
                    'tx_count': tx_count,
                    'avg_amount': avg
                })
        
        return suspicious_patterns
    
    def get_subgraph_for_account(self, account_id: int, depth: int = 2) -> nx.DiGraph:
        """
        Extract subgraph around specific account.
        
        Args:
            account_id: Central account ID
            depth: Number of hops to include
            
        Returns:
            Subgraph centered on account
        """
        if account_id not in self.graph:
            return nx.DiGraph()
        
        # Get neighbors within depth
        nodes = {account_id}
        for _ in range(depth):
            new_nodes = set()
            for node in nodes:
                new_nodes.update(self.graph.successors(node))
                new_nodes.update(self.graph.predecessors(node))
            nodes.update(new_nodes)
        
        subgraph = self.graph.subgraph(nodes).copy()
        return subgraph
    
    def export_for_visualization(self, max_nodes: int = 50) -> Dict:
        """
        Export graph data for D3.js/Cytoscape visualization.
        
        Args:
            max_nodes: Maximum number of nodes to include
            
        Returns:
            Dictionary with nodes and edges for visualization
        """
        # Get most important nodes (highest degree)
        node_importance = {n: self.graph.degree(n) for n in self.graph.nodes()}
        top_nodes = sorted(node_importance.items(), key=lambda x: x[1], reverse=True)[:max_nodes]
        top_node_ids = {n[0] for n in top_nodes}
        
        # Build visualization data
        vis_data = {
            'nodes': [],
            'edges': []
        }
        
        for node in top_node_ids:
            node_data = self.graph.nodes[node]
            risk_score = self.account_risk_scores.get(node, 0)
            
            vis_data['nodes'].append({
                'id': str(node),
                'label': f'Account {node}',
                'size': node_data.get('transaction_count', 1) * 2,
                'risk_score': float(risk_score),
                'total_sent': float(node_data.get('total_sent', 0)),
                'total_received': float(node_data.get('total_received', 0)),
                'color': self._get_risk_color(risk_score)
            })
        
        for src, dst, data in self.graph.edges(data=True):
            if src in top_node_ids and dst in top_node_ids:
                vis_data['edges'].append({
                    'source': str(src),
                    'target': str(dst),
                    'weight': int(data.get('weight', 1)),
                    'amount': float(data.get('total_amount', 0)),
                    'label': f"${data.get('total_amount', 0):,.0f}"
                })
        
        return vis_data
    
    def _get_risk_color(self, risk_score: float) -> str:
        """Map risk score to color"""
        if risk_score > 60:
            return '#dc3545'  # Red
        elif risk_score > 30:
            return '#ffc107'  # Amber
        else:
            return '#28a745'  # Green
