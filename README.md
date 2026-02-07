# 🛡️ TraceGuard AI

**Anti-Money Laundering Dashboard with XGBoost + GNN + Network Analysis**

An intelligent transaction monitoring system for detecting money laundering patterns using ensemble machine learning and graph neural networks.

---

## 🎯 Features

### 🤖 **Dual-Model AI System**
- **XGBoost Model**: Transaction-level risk analysis with 16 engineered features
- **GraphSAGE GNN**: Graph neural network for relational pattern detection
- **Ensemble Predictions**: Combines both models with network factor boosting

### 🔗 **Advanced Network Analysis**
- **Mule Detection**: Identifies accounts receiving from multiple sources (2.5x risk multiplier)
- **Velocity Checks**: Flags rapid transactions under 1 hour (3.0x risk multiplier)
- **Structuring Detection**: Automatic flagging of transactions near $10k threshold
- **Graph Centrality**: PageRank and clustering coefficient analysis

### 📊 **Interactive Visualizations**
- **Cytoscape.js Network Maps**: Interactive transaction graphs with zoom/pan
- **Relational Highlighting**: Hover to see connected transactions
- **Connection Tooltips**: Shows linked transactions with amounts
- **Risk Heatmaps**: Color-coded nodes based on centrality scores

### 🧠 **Explainable AI**
- **Reasoning Column**: Plain-English explanations for each flagging
- **Model Breakdown Tooltips**: Hover to see XGBoost, GNN, and network scores
- **Logic Rules**: Transparent decision-making process

---

## 🚀 Quick Start

### Prerequisites
```bash
Python 3.11+
pip
```

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Morgan-X1/ai_hackathon_traceguard.git
cd ai_hackathon_traceguard
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the server**
```bash
python manage.py runserver
```

4. **Open in browser**
```
http://127.0.0.1:8000
```

---

## 📁 Project Structure

```
TraceGuard/
├── dashboard/                  # Django app
│   ├── batch_processor.py     # Batch transaction analysis (429 lines)
│   ├── gnn_model.py           # GraphSAGE neural network
│   ├── graph_utils.py         # Network analysis utilities
│   ├── feature_engineering.py # Feature extraction (289 lines)
│   └── views.py               # Django views
├── templates/
│   └── dashboard/
│       ├── batch_analysis.html # Main analysis UI (~1200 lines)
│       └── dashboard.html      # Single transaction UI
├── traceguard/                 # Django project settings
└── manage.py                   # Django entry point
```

**Total: ~3,900 lines of code**

---

## 💡 How It Works

### 1. **Feature Engineering**
Extracts 16 features from raw transaction data:
- Amount Received/Paid
- Structuring risk indicators
- Payment format (ACH, Wire, Bitcoin, etc.)
- Account activity patterns
- Round amount detection

### 2. **XGBoost Analysis**
Trained model analyzes transaction-level features:
```python
xgb_score = model.predict(transaction_features)
```

### 3. **GNN Graph Analysis**
Builds transaction graph and runs GraphSAGE:
```python
graph = TransactionGraph.from_transactions(batch)
gnn_score = graphsage_model(graph.node_features, graph.edge_index)
```

### 4. **Network Factor Boost**
Applies multipliers for suspicious patterns:
```python
if mule_detected:
    network_factor = 2.5
if velocity_pattern:
    network_factor = 3.0

final_score = xgb_score * network_factor
```

### 5. **Risk Categorization**
```python
if final_score > 40: "🚨 CRITICAL"
elif final_score > 15: "⚠️ ELEVATED"
else: "✅ LOW"
```

---

## 📊 Sample CSV Format

```csv
Account,Account.1,Timestamp,Amount Received,Receiving Currency,Amount Paid,Payment Currency,Payment Format
ACCT_123,ACCT_456,2024-01-15,9500,USD,9500,USD,Wire
ACCT_789,ACCT_999,2024-01-15,125.50,USD,125.50,USD,ACH
```

**Minimal Required:** Account (Sender), Account.1 (Receiver), Amount Received

---

## 🎨 Key Technologies

| Technology | Purpose |
|------------|---------|
| **Django 4.2** | Web framework |
| **XGBoost 2.0** | Gradient boosting ML |
| **PyTorch 2.x** | Deep learning framework |
| **PyTorch Geometric** | Graph neural networks |
| **NetworkX** | Graph algorithms |
| **Cytoscape.js** | Interactive visualizations |
| **Bootstrap 5** | Responsive UI |
| **Pandas** | Data processing |

---

## 🔍 Detection Capabilities

### Structuring Detection
```
Transaction: $9,500
Reasoning: 🎯 Potential Structuring: Near $10k limit
```

### Mule Account Detection
```
Transaction: Account 9999AAAA receives from 3+ unique senders
Reasoning: 👥 Mule Pattern: Multiple senders to same receiver
Network Factor: 2.5x
```

### Velocity Pattern
```
Transaction: Same accounts transact twice in 30 minutes
Reasoning: ⚡ Velocity Alert: Rapid transactions detected (<1 hour)
Network Factor: 3.0x
```

### Relational Risk
```
Transaction: $125.50 (low amount) but connected to high-risk network
Reasoning: 🔗 Relational Risk: Linked to suspicious account network
```

---

## 📸 Screenshots

### Main Dashboard
- Upload CSV/JSON files for batch analysis
- Instant risk scoring with explainability
- Network visualization with interactive graphs

### Batch Analysis View
- Summary statistics (total transactions, risk distribution)
- Critical risk transactions table
- Structuring attempts detection
- All transactions with reasoning column

### Network Map Modal
- Cytoscape.js interactive graph
- Centers on selected transaction
- Color-coded risk levels
- Hover tooltips with account details

---

## 🧪 Testing

Use the included sample files:
```bash
# Test with sample transactions
sample_transactions.csv  # Basic test cases
simple_transactions.csv  # Minimal example
```

Or paste JSON directly:
```json
[
  {
    "Account": "ACCT_001",
    "Account.1": "ACCT_002",
    "Amount Received": 9500,
    "Payment Format": "Wire"
  }
]
```

---

## 🛠️ Configuration

### Model Location
XGBoost model: `traceguard_milestone2_final.json`

### Django Settings
- Debug mode: Enabled (disable for production)
- Allowed hosts: localhost, 127.0.0.1
- Database: SQLite (upgrade to PostgreSQL for production)

---

## 🎓 Educational Context

Built for **IT 4th Year Final Project / AI Hackathon**

**Problem Statement**: Traditional AML systems miss sophisticated laundering patterns because they analyze transactions in isolation. TraceGuard solves this by combining:
1. Transaction-level ML (XGBoost)
2. Relational analysis (GNN)
3. Network pattern detection (velocity, mules)

**Innovation**: First system to apply Graph Neural Networks to real-time AML detection with explainable AI reasoning.

---

## 📜 License

Educational project - MIT License

---

## 👨‍💻 Author

**Morgan-X1**

GitHub: [@Morgan-X1](https://github.com/Morgan-X1)

---

## 🙏 Acknowledgments

- XGBoost library for gradient boosting
- PyTorch Geometric for GNN implementation
- Cytoscape.js for network visualization
- Bootstrap team for UI framework

---

## 📞 Support

For issues or questions:
1. Open an issue on GitHub
2. Check the project wiki
3. Review sample CSV files

---

**⭐ Star this repo if you find it useful!**
