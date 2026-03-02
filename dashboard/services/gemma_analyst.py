"""
Gemma Reasoning Engine for TraceGuard AI
Lead Investigator AI for Kenya Financial Reporting Centre (FRC)

Transforms GraphSAGE/Isolation Forest outputs into National Security Forensic Insights
"""
import ollama
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from django.utils import timezone
import hashlib

logger = logging.getLogger(__name__)


def anonymize_entities(data: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, str]]:
    """
    Privacy Mask: Anonymize all PII before sending to LLM
    
    Ensures sovereignty compliance - no real names, accounts, or phone numbers to external models.
    
    Args:
        data: Transaction and network data with PII
    
    Returns:
        Tuple of (anonymized_data, entity_mapping) for audit trail
    """
    entity_map = {}
    anonymized = {
        'transactions': [],
        'network': data.get('network', {}),
        'timestamp': timezone.now().isoformat()
    }
    
    # Anonymize transaction entities
    entity_counter = {}
    
    def get_anonymous_id(entity_id: str, entity_type: str = 'ENTITY') -> str:
        """Generate consistent anonymous IDs (e.g., ENTITY_ALPHA, ENTITY_BETA)"""
        if entity_id not in entity_map:
            if entity_type not in entity_counter:
                entity_counter[entity_type] = 0
            
            # Use phonetic alphabet for readability
            phonetic = ['ALPHA', 'BRAVO', 'CHARLIE', 'DELTA', 'ECHO', 'FOXTROT', 
                       'GOLF', 'HOTEL', 'INDIA', 'JULIET', 'KILO', 'LIMA', 'MIKE',
                       'NOVEMBER', 'OSCAR', 'PAPA', 'QUEBEC', 'ROMEO', 'SIERRA', 
                       'TANGO', 'UNIFORM', 'VICTOR', 'WHISKEY', 'XRAY', 'YANKEE', 'ZULU']
            
            idx = entity_counter[entity_type]
            if idx < len(phonetic):
                entity_map[entity_id] = f"{entity_type}_{phonetic[idx]}"
            else:
                entity_map[entity_id] = f"{entity_type}_{idx}"
            
            entity_counter[entity_type] += 1
        
        return entity_map[entity_id]
    
    # Anonymize transactions
    for txn in data.get('transactions', []):
        anon_txn = {
            'sender': get_anonymous_id(str(txn.get('sender_account', 'UNK')), 'SENDER'),
            'receiver': get_anonymous_id(str(txn.get('receiver_account', 'UNK')), 'RECEIVER'),
            'amount_usd': txn.get('amount', 0),
            'risk_score': txn.get('risk_score', 0),
            'xgb_score': txn.get('xgb_score', 0),
            'gnn_score': txn.get('gnn_score', 0),
            'network_factor': txn.get('network_factor', 0),
            'tx_type': txn.get('tx_type', 'UNKNOWN'),
            'is_structuring': txn.get('is_structuring', False),
            'is_round_amount': txn.get('is_round_amount', False),
            'reasoning': txn.get('reasoning', 'N/A')
        }
        anonymized['transactions'].append(anon_txn)
    
    # Anonymize network nodes
    if 'nodes' in anonymized['network']:
        for node in anonymized['network']['nodes']:
            original_id = node.get('id', 'UNK')
            node['id'] = get_anonymous_id(str(original_id), 'NODE')
    
    if 'edges' in anonymized['network']:
        for edge in anonymized['network']['edges']:
            edge['source'] = get_anonymous_id(str(edge.get('source', 'UNK')), 'NODE')
            edge['target'] = get_anonymous_id(str(edge.get('target', 'UNK')), 'NODE')
    
    logger.info(f"Anonymized {len(entity_map)} entities for LLM processing")
    return anonymized, entity_map


def analyze_graph_topology(network_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze network structure for suspicious patterns
    
    Returns topology analysis for Gemma context
    """
    nodes = network_data.get('nodes', [])
    edges = network_data.get('edges', [])
    
    # Calculate in-degree and out-degree
    in_degree = {}
    out_degree = {}
    
    for edge in edges:
        source = edge.get('source')
        target = edge.get('target')
        
        out_degree[source] = out_degree.get(source, 0) + 1
        in_degree[target] = in_degree.get(target, 0) + 1
    
    # Identify patterns
    smurfing_candidates = []  # Many-to-one (high in-degree)
    structuring_candidates = []  # Transactions under $10,000
    layering_chains = []  # Long chains (high out-degree)
    
    for node_id, degree in in_degree.items():
        if degree >= 3:  # Multiple sources to one destination
            smurfing_candidates.append({'node': node_id, 'in_degree': degree})
    
    for node_id, degree in out_degree.items():
        if degree >= 3:  # One source to multiple destinations
            layering_chains.append({'node': node_id, 'out_degree': degree})
    
    # Check for structuring (amounts under $10,000)
    for edge in edges:
        amount = edge.get('amount', 0)
        if 0 < amount < 10000:
            structuring_candidates.append({
                'from': edge.get('source'),
                'to': edge.get('target'),
                'amount_usd': amount
            })
    
    return {
        'total_nodes': len(nodes),
        'total_edges': len(edges),
        'smurfing_patterns': smurfing_candidates[:5],  # Top 5
        'layering_patterns': layering_chains[:5],
        'structuring_attempts': len(structuring_candidates),
        'structuring_examples': structuring_candidates[:3]
    }


def generate_forensic_insight(
    anomaly_data: Dict[str, Any],
    model: str = "gemma3:4b"
) -> Dict[str, Any]:
    """
    Generate National Security Forensic Dossier using Gemma Reasoning Engine
    
    Transforms raw ML outputs into Kenya FRC-style investigative narrative.
    
    Args:
        anomaly_data: Dict containing:
            - transactions: List of suspicious transactions
            - network: Graph data with nodes and edges
            - case_metadata: Optional case info
        model: Ollama model to use (default: gemma3:4b)
    
    Returns:
        Dict containing:
            - success: bool
            - risk_narrative: str (Gemma-generated analysis)
            - network_summary: Dict (quantitative evidence)
            - case_id: str (unique identifier)
            - evidence_timestamp: str (ISO 8601)
            - typologies_detected: List[str]
            - entity_mapping: Dict (for internal audit)
    """
    try:
        # Step 1: Privacy Mask - Anonymize all PII
        anonymized_data, entity_mapping = anonymize_entities(anomaly_data)
        
        # Step 2: Analyze graph topology
        topology = analyze_graph_topology(anonymized_data['network'])
        
        # Step 3: Generate Case ID (hash-based for uniqueness)
        case_id = f"FRC-{datetime.now().strftime('%Y%m%d')}-{hashlib.sha256(json.dumps(anonymized_data['transactions'][:5]).encode()).hexdigest()[:8].upper()}"
        
        # Step 4: Prepare structured context for Gemma
        transactions_summary = []
        total_volume_usd = 0
        high_risk_count = 0
        
        for txn in anonymized_data['transactions']:
            total_volume_usd += txn['amount_usd']
            if txn['risk_score'] >= 40:
                high_risk_count += 1
            
            transactions_summary.append({
                'from': txn['sender'],
                'to': txn['receiver'],
                'amount_usd': round(txn['amount_usd'], 2),
                'risk_score': round(txn['risk_score'], 1),
                'flags': {
                    'structuring': txn['is_structuring'],
                    'round_amount': txn['is_round_amount']
                },
                'ai_reasoning': txn['reasoning']
            })
        
        # Step 5: Construct investigative context
        context = f"""
CASE ID: {case_id}
TIMESTAMP: {anonymized_data['timestamp']}

EXECUTIVE SUMMARY:
- Total Transactions Analyzed: {len(anonymized_data['transactions'])}
- Critical Risk Alerts: {high_risk_count}
- Total Financial Volume: ${total_volume_usd:,.2f} USD
- Network Entities Involved: {topology['total_nodes']}
- Network Connections: {topology['total_edges']}

NETWORK TOPOLOGY ANALYSIS:
- Smurfing Patterns Detected: {len(topology['smurfing_patterns'])} (many-to-one)
- Layering Patterns Detected: {len(topology['layering_patterns'])} (one-to-many)
- Structuring Attempts: {topology['structuring_attempts']} (amounts < $10,000 USD)

SUSPICIOUS TRANSACTIONS (Anonymized):
{json.dumps(transactions_summary[:10], indent=2)}

SMURFING CANDIDATES (Many-to-One Flow):
{json.dumps(topology['smurfing_patterns'], indent=2)}

LAYERING CANDIDATES (One-to-Many Flow):
{json.dumps(topology['layering_patterns'], indent=2)}

STRUCTURING EVIDENCE (Sub-Threshold Amounts):
{json.dumps(topology['structuring_examples'], indent=2)}
"""
        
        # Step 6: System Instructions for Gemma (Kenya FRC Investigator)
        system_prompt = """You are a Lead Investigator for the Kenya Financial Reporting Centre (FRC), specializing in Anti-Money Laundering (AML) and Counter-Terrorism Financing (CTF) investigations.

Your mandate is to analyze suspicious transaction networks and produce evidence-based forensic narratives suitable for:
1. Central Bank of Kenya (CBK) regulatory reporting
2. Law enforcement referrals
3. Financial Intelligence Unit (FIU) case files

TYPOLOGY DEFINITIONS:
- SMURFING: Multiple small deposits from different sources converging to one destination (many-to-one pattern)
- LAYERING: Complex chains of transactions to obscure fund origins (one-to-many, then many-to-one)
- STRUCTURING: Breaking large amounts into sub-$10,000 transactions to avoid reporting thresholds
- RAPID MOVEMENT: High velocity funds indicating placement phase
- CIRCULAR FLOWS: Money moving in loops to create false legitimacy

ANALYSIS REQUIREMENTS:
1. Identify specific typologies with quantitative evidence
2. Calculate financial exposure and money trail complexity
3. Assess national security implications
4. Recommend investigative actions
5. Use professional, court-admissible language

OUTPUT FORMAT:
Produce a formal forensic narrative with these sections:
- RISK ASSESSMENT: Overall threat level (CRITICAL/HIGH/MEDIUM/LOW)
- TYPOLOGIES IDENTIFIED: Specific AML patterns with evidence
- FINANCIAL EXPOSURE: Total USD volume and velocity metrics
- NETWORK STRUCTURE: Key entities and flow patterns
- INVESTIGATIVE RECOMMENDATIONS: Next steps for compliance officers
- LEGAL BASIS: Relevant KYC/AML regulations cited

Base your analysis ONLY on the anonymized data provided. Use precise financial terminology. Cite specific transaction patterns as evidence."""

        # Step 7: Call Gemma via Ollama
        logger.info(f"Generating forensic insight using {model} for case {case_id}")
        
        response = ollama.chat(
            model=model,
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': f"Analyze this suspicious transaction network and produce a forensic investigation dossier:\n\n{context}"}
            ],
            options={
                'temperature': 0.2,  # Low temperature for factual, consistent analysis
                'top_p': 0.9,
                'num_predict': 1500  # Allow detailed response
            }
        )
        
        risk_narrative = response['message']['content']
        
        # Step 8: Extract typologies from narrative
        typologies_detected = []
        if 'SMURFING' in risk_narrative.upper() or 'MANY-TO-ONE' in risk_narrative.upper():
            typologies_detected.append('SMURFING')
        if 'LAYERING' in risk_narrative.upper():
            typologies_detected.append('LAYERING')
        if 'STRUCTURING' in risk_narrative.upper():
            typologies_detected.append('STRUCTURING')
        if 'CIRCULAR' in risk_narrative.upper():
            typologies_detected.append('CIRCULAR_FLOWS')
        if 'RAPID' in risk_narrative.upper():
            typologies_detected.append('RAPID_MOVEMENT')
        
        # Step 9: Compile network summary (quantitative evidence)
        network_summary = {
            'case_id': case_id,
            'total_entities': topology['total_nodes'],
            'total_transactions': len(anonymized_data['transactions']),
            'total_volume_usd': round(total_volume_usd, 2),
            'critical_risk_count': high_risk_count,
            'smurfing_patterns': len(topology['smurfing_patterns']),
            'layering_patterns': len(topology['layering_patterns']),
            'structuring_attempts': topology['structuring_attempts'],
            'entities_involved': list(entity_mapping.values())[:20]  # Top 20 anonymized IDs
        }
        
        logger.info(f"Successfully generated forensic insight for {case_id}. Typologies: {typologies_detected}")
        
        return {
            'success': True,
            'case_id': case_id,
            'evidence_timestamp': anonymized_data['timestamp'],
            'risk_narrative': risk_narrative,
            'network_summary': network_summary,
            'typologies_detected': typologies_detected,
            'entity_mapping': entity_mapping,  # For internal audit only
            'model_used': model,
            'topology_analysis': topology
        }
        
    except ollama.ResponseError as e:
        logger.error(f"Ollama API error: {str(e)}")
        return {
            'success': False,
            'error': 'Gemma service unavailable',
            'message': f'Failed to connect to Gemma reasoning engine: {str(e)}'
        }
    except Exception as e:
        logger.error(f"Forensic insight generation failed: {str(e)}", exc_info=True)
        return {
            'success': False,
            'error': 'Analysis failed',
            'message': f'Error during forensic analysis: {str(e)}'
        }


def verify_ollama_gemma() -> Dict[str, Any]:
    """
    Verify Ollama service is running and Gemma model is available
    
    Returns:
        Dict with availability status
    """
    try:
        models = ollama.list()
        # Handle both dict and Model object formats
        available_models = []
        for m in models.get('models', []):
            if hasattr(m, 'model'):
                available_models.append(m.model)
            elif isinstance(m, dict):
                available_models.append(m.get('name', m.get('model', '')))
        
        gemma_variants = [m for m in available_models if 'gemma' in m.lower()]
        
        return {
            'available': True,
            'gemma_installed': len(gemma_variants) > 0,
            'gemma_models': gemma_variants,
            'all_models': available_models
        }
    except Exception as e:
        logger.error(f"Ollama verification failed: {e}")
        return {
            'available': False,
            'error': str(e),
            'message': 'Ollama service not running. Start with: ollama serve'
        }
