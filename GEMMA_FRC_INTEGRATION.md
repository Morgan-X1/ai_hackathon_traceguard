# TraceGuard AI - National Security Forensic Dossier System

## Top 60 MVP Features - Kenya FRC Integration

### Overview
TraceGuard AI now includes **Gemma Reasoning Engine** for generating professional FRC (Financial Reporting Centre) forensic dossiers from GraphSAGE/Isolation Forest outputs.

---

## New Features

### 1. **Gemma Reasoning Engine** (`services/gemma_analyst.py`)
- **Lead Investigator AI** for Kenya Financial Reporting Centre
- Transforms raw ML outputs into **National Security Forensic Narratives**
- **Privacy Mask**: Anonymizes all PII before LLM processing
  - Real names → ENTITY_ALPHA, ENTITY_BRAVO, etc.
  - Account numbers → NODE_XXX identifiers
  - No phone numbers or personal data sent to AI
- **Typology Detection**:
  - **Smurfing**: Many-to-one patterns (multiple sources → one destination)
  - **Layering**: One-to-many chains (complex fund obscuration)
  - **Structuring**: Sub-$10,000 transactions (threshold avoidance)
  - **Circular Flows**: Money moving in loops
  - **Rapid Movement**: High-velocity fund transfers

### 2. **Automated FRC Report Generation**
#### **PDF Export View** (`export_forensic_pdf`)
- Downloadable **National Security Dossier** in PDF format
- Includes:
  - **Risk Narrative** (Gemma-generated analysis)
  - **Network Summary** (Quantitative evidence)
  - **Evidence Timestamp** (ISO 8601)
  - **Unique Case ID** (e.g., `FRC-20260228-A7B3C9D2`)
  - **Officer Verification** (Name, Role, Employee ID)
  - **Legal Disclaimer** with sovereignty safeguards
  - **Document Hash** for integrity verification

#### **Uses ReportLab** for professional PDF generation:
- CBK-compliant formatting
- Classification banners (CONFIDENTIAL)
- Structured tables and typography
- Court-admissible presentation

### 3. **Public Trust & Sovereignty Safeguards**
#### **Privacy Mask Function** (`anonymize_entities`)
- **Zero PII Exposure**: No real names, accounts, or phone numbers to LLM
- Consistent anonymization (same entity always gets same token)
- **Phonetic Alphabet Mapping**:
  ```
  Real Account: 1234567890
  Anonymized:   ENTITY_ALPHA
  
  Real Account: 0987654321
  Anonymized:   ENTITY_BRAVO
  ```
- Entity mapping stored for internal audit only

#### **Verification Log** (`ForensicReportLog` Model)
- **Ethical Leadership Criterion**: Tracks which officer generated report
- Database fields:
  - `case_id`: Unique identifier
  - `generated_by`: User foreign key
  - `officer_name`: Full name
  - `officer_role`: COMPLIANCE_OFFICER / ADMIN
  - `officer_employee_id`: Staff ID
  - `verification_status`: DRAFT / VERIFIED / SUBMITTED / ARCHIVED
  - `cbk_reporting_required`: Boolean flag
  - `pdf_file_hash`: SHA-256 for document integrity
  - `entity_anonymization_applied`: Privacy confirmation

### 4. **Frontend Integration**
#### **Gemma Deep Analysis Button**
- **Yellow "Gemma Deep Analysis" button** on batch analysis page
- Only visible to Compliance Officers and Admins
- Triggers FRC-style investigative narrative

#### **Official Document Side-Panel**
- **700px wide sliding panel** (right side of screen)
- **Dark theme** with FRC branding
- Sections:
  1. **Classification Banner** (CONFIDENTIAL - CBK COMPLIANCE USE ONLY)
  2. **Case Header** (Case ID, Timestamp, Officer info)
  3. **Typologies Identified** (Color-coded badges)
  4. **Network Summary** (Quantitative cards)
  5. **Forensic Risk Narrative** (Gemma-generated text)
  6. **Export PDF Button** (Downloads official dossier)
  7. **Legal Disclaimer** (Privacy safeguards, regulatory authority)

---

## 📋 System Instructions for Gemma

```
You are a Lead Investigator for the Kenya Financial Reporting Centre (FRC), 
specializing in Anti-Money Laundering (AML) and Counter-Terrorism Financing (CTF) investigations.

Your mandate is to analyze suspicious transaction networks and produce evidence-based 
forensic narratives suitable for:
1. Central Bank of Kenya (CBK) regulatory reporting
2. Law enforcement referrals
3. Financial Intelligence Unit (FIU) case files

TYPOLOGY DEFINITIONS:
- SMURFING: Multiple small deposits from different sources converging to one destination (many-to-one pattern)
- LAYERING: Complex chains of transactions to obscure fund origins (one-to-many, then many-to-one)
- STRUCTURING: Breaking large amounts into sub-$10,000 transactions to avoid reporting thresholds
- RAPID MOVEMENT: High velocity funds indicating placement phase
- CIRCULAR FLOWS: Money moving in loops to create false legitimacy

OUTPUT FORMAT:
- RISK ASSESSMENT: Overall threat level (CRITICAL/HIGH/MEDIUM/LOW)
- TYPOLOGIES IDENTIFIED: Specific AML patterns with evidence
- FINANCIAL EXPOSURE: Total USD volume and velocity metrics
- NETWORK STRUCTURE: Key entities and flow patterns
- INVESTIGATIVE RECOMMENDATIONS: Next steps for compliance officers
- LEGAL BASIS: Relevant KYC/AML regulations cited
```

---

## Installation & Setup

### Prerequisites
```bash
# 1. Install Ollama
# Visit https://ollama.ai and download installer

# 2. Start Ollama service
ollama serve

# 3. Pull Gemma 3 model (4B parameters)
ollama pull gemma3:4b

# Alternative: Gemma 2
# ollama pull gemma2

# 4. Verify installation
ollama list
# Should show: gemma3:4b
```

### Python Dependencies
```bash
pip install reportlab  # Already installed
```

### Database Migration
```bash
python manage.py makemigrations
python manage.py migrate
```

### Start Server
```bash
python manage.py runserver
```

---

## Usage

### 1. **Run Batch Analysis**
- Upload CSV/JSON transactions at `/batch-analysis/`
- Wait for GraphSAGE + XGBoost analysis to complete

### 2. **Generate Forensic Dossier**
- Click **"Gemma Deep Analysis"** button (yellow button)
- Official document side-panel slides in from right
- Wait 20-45 seconds for Gemma to generate narrative

### 3. **Review FRC Dossier**
- Read **Risk Narrative** (professional FRC-style analysis)
- Check **Typologies Detected** (badges)
- Examine **Network Summary** (quantitative evidence)
- Verify **Officer Information** (accountability)

### 4. **Export PDF**
- Click **"Export as PDF"** button
- Downloads: `FRC_Dossier_FRC-20260228-XXXXXXXX.pdf`
- PDF includes:
  - Classification banner
  - Case ID and timestamps
  - Full narrative and evidence
  - Officer signature
  - Legal disclaimer

---

## Top 60 Judging Criteria Alignment

### **Innovation & Impact**
- **Gemma Reasoning Engine**: First-of-its-kind FRC forensic AI for Kenya
✅ **National Security Focus**: AML/CTF compliance for CBK
✅ **Actionable Intelligence**: PDF dossiers ready for law enforcement

### **Public Trust & Sovereignty**
✅ **Privacy Mask**: Zero PII to external LLMs (sovereignty compliance)
✅ **Entity Anonymization**: Phonetic alphabet mapping (ENTITY_ALPHA, etc.)
✅ **Local AI Deployment**: Ollama runs on-premise (no cloud dependency)

### **Ethical Leadership**
✅ **Verification Log**: Tracks which officer generated each report
✅ **Officer Accountability**: Name, role, employee ID in every dossier
✅ **Audit Trail**: Complete chain of custody for evidence

### **Technical Excellence**
✅ **GraphSAGE Integration**: ML outputs → human-readable narratives
✅ **Topology Analysis**: Smurfing, layering, structuring detection
✅ **Professional PDFs**: Court-admissible formatting with ReportLab

### **Scalability & Reliability**
✅ **Session-Based State**: Handles large transaction volumes
✅ **Error Handling**: Graceful fallbacks for Ollama unavailability
✅ **Database Logging**: `ForensicReportLog` for long-term storage

---

## Data Flow

```
1. User uploads transactions → Batch Analysis
                                    ↓
2. XGBoost + GraphSAGE analysis → Risk scores + Network graph
                                    ↓
3. Store in Django session → raw_results + graph_data
                                    ↓
4. User clicks "Gemma Deep Analysis"
                                    ↓
5. Backend: anonymize_entities() → Remove PII (Privacy Mask)
                                    ↓
6. Backend: analyze_graph_topology() → Detect patterns
                                    ↓
7. Backend: generate_forensic_insight() → Call Gemma via Ollama
                                    ↓
8. Gemma generates FRC narrative (20-45 seconds)
                                    ↓
9. Backend: Create ForensicReportLog → Store in database
                                    ↓
10. Frontend: Display in Official Document Side-Panel
                                    ↓
11. User clicks "Export PDF" → Django generates PDF with ReportLab
                                    ↓
12. Download FRC_Dossier_CASE-ID.pdf → Ready for submission
```

---

## File Structure

```
dashboard/
├── services/
│   ├── __init__.py
│   ├── forensic_service.py      # Old AI report (generic)
│   └── gemma_analyst.py         # NEW: FRC Gemma Reasoning Engine
├── models.py
│   └── ForensicReportLog        # NEW: Verification log model
├── views.py
│   ├── gemma_deep_analysis()    # NEW: Generate FRC dossier
│   └── export_forensic_pdf()    # NEW: PDF export view
├── urls.py
│   ├── /api/gemma-deep-analysis/
│   └── /export-forensic-pdf/<case_id>/
└── templates/
    └── batch_analysis.html
        ├── Gemma Deep Analysis button
        └── Official Document Side-Panel
```

---

## Security Features

### 1. **Privacy Mask (Sovereignty Compliance)**
```python
# Before AI processing:
Real Data:
  {
    "sender_account": "1234567890",
    "receiver_account": "0987654321",
    "customer_name": "John Doe"
  }

# After anonymization:
Anonymized Data:
  {
    "sender": "ENTITY_ALPHA",
    "receiver": "ENTITY_BRAVO",
    "customer_name": "[REDACTED]"
  }
```

### 2. **Officer Verification**
- Every report logged with:
  - Officer full name
  - Role (COMPLIANCE_OFFICER / ADMIN)
  - Employee ID
  - Generation timestamp
- Prevents anonymous or unaccountable reports

### 3. **Document Integrity**
- SHA-256 hash of PDF content
- Evidence timestamp (ISO 8601)
- Case ID (hash-based uniqueness)
- Immutable audit log in database

---

## UI Components

### Gemma Deep Analysis Button
```html
<button class="btn btn-warning ms-2" onclick="gemmaDeepAnalysis()" title="FRC National Security Dossier">
    <i class="bi bi-shield-check"></i> Gemma Deep Analysis
</button>
```

### Official Document Side-Panel
- **Width**: 700px
- **Position**: Fixed right, slides in with CSS transition
- **Theme**: Dark gradient (`#1a1a1a` → `#2d2d2d`)
- **Header**: Red gradient with FRC branding
- **Content**: Professional typography (Courier New for headers, Georgia for narrative)

---

## Example Output

### Case ID
```
FRC-20260228-A7B3C9D2
```

### Typologies Detected
```
[ SMURFING ] [ LAYERING ] [ STRUCTURING ]
```

### Network Summary
```
Total Entities:         47
Total Transactions:     128
Total Volume (USD):     $1,247,893.50
Critical Risk Alerts:   23
Smurfing Patterns:      8
Layering Patterns:      5
Structuring Attempts:   12
```

### Risk Narrative (Excerpt)
```
RISK ASSESSMENT: CRITICAL

This investigation reveals a sophisticated money laundering network exhibiting 
multiple AML typologies. The transaction graph demonstrates classic smurfing 
behavior with 8 distinct many-to-one convergence patterns...

TYPOLOGIES IDENTIFIED:

1. SMURFING (Many-to-One Pattern)
   Evidence: ENTITY_ALPHA received 12 incoming transactions from 8 different 
   sources within a 48-hour window, totaling $89,450 USD. Individual amounts 
   ranged from $4,800 to $9,900, suggesting deliberate threshold avoidance...

2. LAYERING (Complex Transaction Chains)
   Evidence: ENTITY_CHARLIE initiated 7 outbound transactions to separate 
   destinations, followed by rapid consolidation through ENTITY_DELTA...

INVESTIGATIVE RECOMMENDATIONS:
- Freeze accounts: ENTITY_ALPHA, ENTITY_CHARLIE
- Request KYC documentation for all 47 entities
- Submit Suspicious Activity Report (SAR) to Kenya FIU
- Coordinate with CBK Financial Crimes Unit
```

---

## Legal Compliance

### Regulatory Framework
- **Central Bank of Kenya (CBK)** AML/CTF regulations
- **Financial Reporting Centre Act** (Kenya)
- **Proceeds of Crime and Anti-Money Laundering Act**
- **KYC Requirements** for financial institutions

### Report Usage
1. **CBK Regulatory Reporting**: Submit PDF to Central Bank
2. **FIU Referrals**: Forward dossier to Financial Intelligence Unit
3. **Law Enforcement**: Evidence for criminal investigations
4. **Internal Compliance**: Risk assessment documentation

---

## Troubleshooting

### "Gemma service not available"
**Solution**: Start Ollama
```bash
ollama serve
```

### "Gemma model not found"
**Solution**: Pull Gemma model
```bash
ollama pull gemma3:4b
```

### "No anomaly data"
**Solution**: Run batch analysis first to generate transaction data

### PDF Export Fails
**Check**: ReportLab installation
```bash
pip install reportlab
```

---

## API Endpoints

### Gemma Deep Analysis
```http
POST /api/gemma-deep-analysis/
Authorization: Bearer <token>
Content-Type: application/json

Response:
{
  "success": true,
  "case_id": "FRC-20260228-A7B3C9D2",
  "risk_narrative": "RISK ASSESSMENT: CRITICAL...",
  "network_summary": {...},
  "typologies_detected": ["SMURFING", "LAYERING"],
  "officer_name": "Jane Doe",
  "cbk_reporting_required": true
}
```

### Export Forensic PDF
```http
GET /export-forensic-pdf/FRC-20260228-A7B3C9D2/
Authorization: Bearer <token>

Response: application/pdf (downloadable file)
```

---

## Success Metrics

### Performance
- **Analysis Time**: 20-45 seconds (Gemma inference)
- **PDF Generation**: <2 seconds (ReportLab)
- **Privacy Mask**: <1 second (entity anonymization)

### Accuracy
- **Typology Detection**: Pattern-based heuristics
- **Network Analysis**: GraphSAGE embeddings
- **Risk Scoring**: XGBoost + GNN ensemble

### Compliance
- **100% PII Anonymization**: Before AI processing
- **Officer Accountability**: Every report logged
- **Audit Trail**: Complete verification chain

---

## Future Enhancements

1. **Multi-Language Support**: Swahili translations for local officers
2. **Real-Time Alerts**: Webhook integration for critical cases
3. **Bulk PDF Export**: Generate multiple dossiers at once
4. **Dashboard Analytics**: Typology trends over time
5. **Integration with CBK Systems**: Direct API submission

---

## Support

For issues or questions:
- **GitHub Issues**: [Your Repo]
- **Documentation**: This README
- **Demo Video**: [YouTube Link]

---

## Top 60 Submission Checklist

- **Innovation**: Gemma Reasoning Engine for FRC
- **Sovereignty**: Privacy Mask (no PII to LLM)
- **Actionability**: Downloadable PDF dossiers
- **Ethical Leadership**: Officer verification logs
- **Technical Excellence**: GraphSAGE → Gemma pipeline
- **Public Trust**: Transparent anonymization
- **Scalability**: Session-based state management
- **Professional UI**: Official document side-panel
- **Legal Compliance**: CBK/FRC regulatory alignment

---

**TraceGuard AI** is now a complete **National Security Forensic Dossier System** 
ready for Kenya's Top 60 competition!
