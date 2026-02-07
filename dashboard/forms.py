"""
TraceGuard AI - Transaction Forms
Forms for manual transaction entry and risk analysis
"""
from django import forms


class TransactionForm(forms.Form):
    """Form for manual transaction entry with all 16 features"""
    
    # Transaction Details
    Amount = forms.DecimalField(
        label='Transaction Amount ($)',
        max_digits=12,
        decimal_places=2,
        min_value=0.01,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter amount (e.g., 9500.00)',
            'step': '0.01'
        }),
        help_text='Transaction amount in USD'
    )
    
    Sender_ID = forms.IntegerField(
        label='Sender ID',
        min_value=1,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Sender account ID'
        }),
        help_text='Unique identifier for the sender'
    )
    
    Receiver_ID = forms.IntegerField(
        label='Receiver ID',
        min_value=1,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Receiver account ID'
        }),
        help_text='Unique identifier for the receiver'
    )
    
    Tx_Type = forms.ChoiceField(
        label='Transaction Type',
        choices=[
            (0, 'Wire Transfer'),
            (1, 'Cash Deposit'),
            (2, 'Check'),
            (3, 'ACH Transfer'),
            (4, 'Card Payment'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text='Type of transaction'
    )
    
    # Location & Device
    Location = forms.IntegerField(
        label='Location Code',
        min_value=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Location/Country code'
        }),
        help_text='Encoded location or country code'
    )
    
    Device_ID = forms.IntegerField(
        label='Device ID',
        min_value=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Device identifier'
        }),
        help_text='Device used for transaction'
    )
    
    IP_Prefix = forms.IntegerField(
        label='IP Prefix',
        min_value=0,
        max_value=255,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'IP address prefix'
        }),
        help_text='First octet of IP address'
    )
    
    # Risk Indicators (Binary)
    Is_High_Risk_Country = forms.ChoiceField(
        label='High Risk Country',
        choices=[
            (0, 'No'),
            (1, 'Yes'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text='Transaction from/to high-risk jurisdiction'
    )
    
    Is_Proxy = forms.ChoiceField(
        label='Proxy/VPN Detected',
        choices=[
            (0, 'No'),
            (1, 'Yes'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text='Transaction uses proxy or VPN'
    )
    
    Is_Round_Amount = forms.ChoiceField(
        label='Round Amount',
        choices=[
            (0, 'No'),
            (1, 'Yes'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text='Amount is a round number (e.g., $5,000)'
    )
    
    Is_Structuring_Risk = forms.ChoiceField(
        label='Structuring Risk',
        choices=[
            (0, 'No'),
            (1, 'Yes'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text='Transaction near $10,000 threshold (structuring)'
    )
    
    # Behavioral Features
    Transaction_Frequency = forms.IntegerField(
        label='Transaction Frequency (24h)',
        min_value=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Number of transactions in last 24h'
        }),
        help_text='Number of transactions in the last 24 hours'
    )
    
    Avg_Transaction_Amount = forms.DecimalField(
        label='Average Transaction Amount ($)',
        max_digits=12,
        decimal_places=2,
        min_value=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Historical average amount',
            'step': '0.01'
        }),
        help_text='Historical average transaction amount for this account'
    )
    
    Time_Since_Last_Tx = forms.IntegerField(
        label='Time Since Last Transaction (hours)',
        min_value=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Hours since last transaction'
        }),
        help_text='Time elapsed since the last transaction (in hours)'
    )
    
    Sender_Receiver_Relationship = forms.ChoiceField(
        label='Sender-Receiver Relationship',
        choices=[
            (0, 'Unknown'),
            (1, 'Known/Related'),
            (2, 'Frequent'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-select'
        }),
        help_text='Relationship between sender and receiver'
    )
    
    Account_Age_Days = forms.IntegerField(
        label='Account Age (days)',
        min_value=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'placeholder': 'Account age in days'
        }),
        help_text='Age of the sender account in days'
    )
    
    def clean_Amount(self):
        """Validate and flag structuring risk based on amount"""
        amount = self.cleaned_data['Amount']
        if amount < 0:
            raise forms.ValidationError("Amount must be positive")
        return amount
    
    def clean(self):
        """Cross-field validation"""
        cleaned_data = super().clean()
        amount = cleaned_data.get('Amount')
        is_structuring = cleaned_data.get('Is_Structuring_Risk')
        
        # Auto-detect structuring risk
        if amount and 9000 <= amount <= 10500:
            if is_structuring == '0':
                self.add_warning('Is_Structuring_Risk', 
                               'Amount is near $10,000 - consider flagging as structuring risk')
        
        return cleaned_data
    
    def add_warning(self, field, message):
        """Add a warning (non-blocking) to a field"""
        if not hasattr(self, '_warnings'):
            self._warnings = {}
        self._warnings[field] = message
    
    def get_warnings(self):
        """Get all warnings"""
        return getattr(self, '_warnings', {})
