"""
Forensic Analysis Service using Ollama AI
Provides automated forensic analysis of transaction patterns for money laundering detection
Ensures privacy by using only anonymized transaction metadata (no PII)
"""
import ollama
import json
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


def anonymize_transaction_data(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove PII from transaction data before sending to AI model.
    Only keeps anonymized tokens and metadata.
    
    Args:
        transactions: List of transaction dictionaries
        
    Returns:
        List of anonymized transaction dictionaries
    """
    anonymized = []
    
    for idx, tx in enumerate(transactions):
        # Extract only non-PII fields
        anon_tx = {
            'tx_id': f"TX_{idx + 1}",  # Use generic ID instead of real ID
            'amount': tx.get('amount', 0),
            'risk_score': tx.get('risk_score', 0),
            'xgb_score': tx.get('xgb_score', 0),
            'gnn_score': tx.get('gnn_score', 0),
            'network_factor': tx.get('network_factor', 1.0),
            'risk_level': tx.get('risk_level', 'UNKNOWN'),
            'tx_type': tx.get('tx_type', 'UNKNOWN'),
            'location_risk': tx.get('location_risk', 'NORMAL'),
            'is_round_amount': tx.get('is_round_amount', False),
            'is_structuring': tx.get('is_structuring_risk', False),
            'velocity': tx.get('velocity', 0),
            'reasoning': tx.get('reasoning', ''),
        }
        
        # Add network connection info if available (anonymized)
        if tx.get('sender_account'):
            anon_tx['sender_node'] = f"NODE_{hash(tx['sender_account']) % 1000}"
        if tx.get('receiver_account'):
            anon_tx['receiver_node'] = f"NODE_{hash(tx['receiver_account']) % 1000}"
            
        anonymized.append(anon_tx)
    
    return anonymized


def serialize_graph_data(graph_data: Dict[str, Any]) -> str:
    """
    Serialize graph/network data into structured text format for AI analysis.
    
    Args:
        graph_data: Dictionary containing nodes and edges from network analysis
        
    Returns:
        Formatted string representation of the graph
    """
    if not graph_data:
        return "No network data available."
    
    output = []
    
    # Nodes information
    nodes = graph_data.get('nodes', [])
    edges = graph_data.get('edges', [])
    
    output.append(f"NETWORK STRUCTURE:")
    output.append(f"- Total Nodes (Accounts): {len(nodes)}")
    output.append(f"- Total Edges (Transactions): {len(edges)}")
    output.append("")
    
    # High-risk nodes
    high_risk_nodes = [n for n in nodes if n.get('risk_score', 0) > 70]
    if high_risk_nodes:
        output.append(f"HIGH-RISK NODES ({len(high_risk_nodes)}):")
        for node in high_risk_nodes[:10]:  # Limit to top 10
            output.append(f"  - {node.get('label', 'Unknown')}: Risk {node.get('risk_score', 0):.1f}, Size {node.get('size', 1)}")
        output.append("")
    
    # Suspicious patterns
    patterns = graph_data.get('suspicious_patterns', {})
    if patterns:
        output.append("SUSPICIOUS PATTERNS DETECTED:")
        
        circular = patterns.get('circular_flow', [])
        if circular:
            output.append(f"  - Circular Flows: {len(circular)} detected (potential layering)")
            
        rapid = patterns.get('rapid_movement', [])
        if rapid:
            output.append(f"  - Rapid Money Movement: {len(rapid)} accounts (potential placement)")
            
        structuring = patterns.get('structuring', [])
        if structuring:
            output.append(f"  - Structuring Behavior: {len(structuring)} accounts (smurfing)")
        
        output.append("")
    
    # Transaction flow summary
    if edges:
        total_amount = sum(e.get('amount', 0) for e in edges)
        avg_amount = total_amount / len(edges) if edges else 0
        output.append(f"TRANSACTION FLOW:")
        output.append(f"  - Total Volume: ${total_amount:,.2f}")
        output.append(f"  - Average Transaction: ${avg_amount:,.2f}")
        output.append(f"  - Number of Transactions: {len(edges)}")
        output.append("")
    
    return "\n".join(output)


def serialize_transaction_patterns(transactions: List[Dict[str, Any]]) -> str:
    """
    Create a structured text summary of transaction patterns for AI analysis.
    
    Args:
        transactions: List of anonymized transaction dictionaries
        
    Returns:
        Formatted string with transaction pattern summary
    """
    if not transactions:
        return "No transaction data available."
    
    output = []
    
    # Summary statistics
    output.append(f"TRANSACTION ANALYSIS SUMMARY:")
    output.append(f"Total Transactions: {len(transactions)}")
    output.append("")
    
    # Risk distribution
    critical = [tx for tx in transactions if tx.get('risk_score', 0) >= 40]
    elevated = [tx for tx in transactions if 15 <= tx.get('risk_score', 0) < 40]
    low = [tx for tx in transactions if tx.get('risk_score', 0) < 15]
    
    output.append("RISK DISTRIBUTION:")
    output.append(f"  - Critical Risk (≥40): {len(critical)} transactions ({len(critical)/len(transactions)*100:.1f}%)")
    output.append(f"  - Elevated Risk (15-40): {len(elevated)} transactions ({len(elevated)/len(transactions)*100:.1f}%)")
    output.append(f"  - Low Risk (<15): {len(low)} transactions ({len(low)/len(transactions)*100:.1f}%)")
    output.append("")
    
    # Financial summary
    total_amount = sum(tx.get('amount', 0) for tx in transactions)
    avg_amount = total_amount / len(transactions)
    
    output.append("FINANCIAL SUMMARY:")
    output.append(f"  - Total Volume: ${total_amount:,.2f}")
    output.append(f"  - Average Amount: ${avg_amount:,.2f}")
    output.append(f"  - Largest Transaction: ${max(tx.get('amount', 0) for tx in transactions):,.2f}")
    output.append("")
    
    # Structuring indicators
    structuring_txs = [tx for tx in transactions if tx.get('is_structuring', False)]
    round_amounts = [tx for tx in transactions if tx.get('is_round_amount', False)]
    
    output.append("TYPOLOGY INDICATORS:")
    output.append(f"  - Structuring Attempts: {len(structuring_txs)} transactions")
    output.append(f"  - Round Amount Transactions: {len(round_amounts)}")
    output.append("")
    
    # Top critical transactions (anonymized)
    if critical:
        output.append("TOP CRITICAL RISK TRANSACTIONS:")
        for tx in sorted(critical, key=lambda x: x.get('risk_score', 0), reverse=True)[:5]:
            output.append(f"  - {tx['tx_id']}: ${tx['amount']:,.2f}, Risk Score: {tx['risk_score']:.1f}")
            output.append(f"    Reason: {tx.get('reasoning', 'Unknown')}")
        output.append("")
    
    return "\n".join(output)


def generate_forensic_report(
    transaction_data: List[Dict[str, Any]],
    graph_data: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate AI-powered forensic analysis report using Ollama.
    
    Args:
        transaction_data: List of transaction dictionaries
        graph_data: Optional network graph data with nodes and edges
        model: Ollama model to use (default: auto-detect from available models)
        
    Returns:
        Dictionary containing:
        - success: Boolean indicating if analysis succeeded
        - report: AI-generated forensic report text
        - error: Error message if failed
        - metadata: Additional context (typologies detected, risk summary, etc.)
    """
    # Auto-detect model if not specified
    if model is None:
        try:
            availability = check_ollama_availability()
            if availability.get('available') and availability.get('models'):
                models = availability['models']
                # Prefer llama3.2, gemma3:4b, or use first available
                if 'llama3.2' in models:
                    model = 'llama3.2'
                elif 'gemma3:4b' in models:
                    model = 'gemma3:4b'
                elif 'gemma:latest' in models:
                    model = 'gemma:latest'
                elif len(models) > 0:
                    model = models[0]
                else:
                    model = 'gemma3:4b'  # fallback
                logger.info(f"Auto-detected Ollama model: {model}")
            else:
                model = 'gemma3:4b'  # fallback
        except Exception as e:
            logger.warning(f"Failed to auto-detect model: {e}. Using fallback.")
            model = 'gemma3:4b'
    
    # Ensure model is a valid string
    if not model or not isinstance(model, str):
        logger.error(f"Invalid model value: {model}. Using fallback.")
        model = 'gemma3:4b'
    
    logger.info(f"Generating forensic report with model: {model}")
    
    try:
        # Step 1: Anonymize transaction data (remove PII)
        anonymized_transactions = anonymize_transaction_data(transaction_data)
        
        # Step 2: Serialize data into structured text
        transaction_summary = serialize_transaction_patterns(anonymized_transactions)
        graph_summary = serialize_graph_data(graph_data) if graph_data else "No network graph data available."
        
        # Step 3: Construct the context for AI
        context = f"""
{transaction_summary}

{graph_summary}

TRANSACTION PATTERNS:
{json.dumps(anonymized_transactions[:10], indent=2)}  # Include first 10 for detailed analysis
"""
        
        # Step 4: System prompt for forensic analyst role
        system_prompt = """You are a Senior Financial Forensic Analyst specializing in Anti-Money Laundering (AML) investigations. 

Your task is to review transaction patterns and network analysis data to identify potential money laundering typologies including:
- Smurfing/Structuring: Breaking large amounts into smaller transactions below reporting thresholds
- Layering: Complex chains of transactions to obscure the origin of funds
- Circular Flows: Money moving in circles through multiple accounts to create false legitimacy
- Rapid Movement: Fast velocity of funds indicating placement phase
- Placement: Initial entry of illicit funds into the financial system

Provide a concise, professional forensic analysis that includes:
1. Executive Summary (2-3 sentences)
2. Key Findings: List the most significant red flags
3. Typologies Identified: Specific money laundering patterns detected with evidence
4. Risk Assessment: Overall risk level with justification
5. Recommendations: Actions for compliance team

Use professional language suitable for CBK (Central Bank of Kenya) compliance reporting. Base your analysis solely on the anonymized transaction metadata provided."""

        # Step 5: Make API call to Ollama
        logger.info(f"Generating forensic report using model: {model}")
        
        response = ollama.chat(
            model=model,
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': f"Please analyze the following transaction data and provide a forensic report:\n\n{context}"
                }
            ],
            options={
                'temperature': 0.3,  # Lower temperature for more consistent, factual analysis
                'top_p': 0.9,
            }
        )
        
        # Step 6: Extract AI response
        ai_report = response['message']['content']
        
        # Step 7: Extract metadata for quick reference
        metadata = {
            'total_transactions': len(transaction_data),
            'critical_count': len([tx for tx in transaction_data if tx.get('risk_score', 0) >= 40]),
            'structuring_detected': len([tx for tx in transaction_data if tx.get('is_structuring_risk', False)]),
            'network_patterns': len(graph_data.get('suspicious_patterns', {}).get('circular_flow', [])) if graph_data else 0,
            'model_used': model,
        }
        
        logger.info("Forensic report generated successfully")
        
        return {
            'success': True,
            'report': ai_report,
            'metadata': metadata,
            'context_summary': {
                'transactions': transaction_summary,
                'network': graph_summary
            }
        }
        
    except ollama.ResponseError as e:
        logger.error(f"Ollama API error: {str(e)}")
        return {
            'success': False,
            'error': f"AI model error: {str(e)}. Make sure Ollama is running and llama3.2 model is installed.",
            'report': None
        }
    
    except Exception as e:
        logger.error(f"Forensic report generation failed: {str(e)}", exc_info=True)
        return {
            'success': False,
            'error': f"Failed to generate report: {str(e)}",
            'report': None
        }


def check_ollama_availability() -> Dict[str, Any]:
    """
    Check if Ollama service is running and what models are available.
    
    Returns:
        Dictionary with availability status and list of models
    """
    try:
        # Try to list models
        models = ollama.list()
        
        # Get all available model names
        available_models = [m.get('name') for m in models.get('models', [])]
        
        return {
            'available': True,
            'has_compatible_model': len(available_models) > 0,
            'models': available_models
        }
    except Exception as e:
        return {
            'available': False,
            'error': str(e),
            'message': 'Ollama service is not running. Please start Ollama: https://ollama.ai'
        }
