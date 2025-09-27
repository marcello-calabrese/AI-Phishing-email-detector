"""
Email Header Parser Module

This module provides functionality to parse and analyze email headers
for phishing detection purposes.
"""

import re
import email
from email.message import EmailMessage
from typing import Dict, List, Optional, Union, TYPE_CHECKING
from datetime import datetime

if TYPE_CHECKING:
    from security_analyzer import SecurityAnalyzer

# Optional imports with fallbacks
try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    from email_validator import validate_email, EmailNotValidError
    EMAIL_VALIDATOR_AVAILABLE = True
except ImportError:
    EMAIL_VALIDATOR_AVAILABLE = False
    # Fallback for email validation
    class EmailNotValidError(Exception):
        pass


class EmailHeaderParser:
    """Parse and analyze email headers for security indicators."""
    
    def __init__(self, security_analyzer: Optional['SecurityAnalyzer'] = None):
        self.suspicious_indicators = []
        self.parsed_data = {}
        self.security_analyzer = security_analyzer
    
    def parse_headers(self, email_content: str) -> Dict:
        """
        Parse email headers from raw email content or header string.
        
        Args:
            email_content: Raw email content or header string
            
        Returns:
            Dictionary containing parsed header information
        """
        try:
            # Try to parse as full email message first
            if '\n\n' in email_content or '\r\n\r\n' in email_content:
                msg = email.message_from_string(email_content)
            else:
                # If it's just headers, add empty body
                msg = email.message_from_string(email_content + '\n\n')
            
            parsed_data = {
                'headers': dict(msg.items()),
                'sender_info': self._analyze_sender(msg),
                'routing_info': self._analyze_routing(msg),
                'authentication': self._analyze_authentication(msg),
                'suspicious_indicators': [],
                'confidence_factors': {},
                'security_analysis': {}
            }
            
            # Analyze for suspicious patterns
            parsed_data['suspicious_indicators'] = self._detect_suspicious_patterns(parsed_data)
            parsed_data['confidence_factors'] = self._calculate_confidence_factors(parsed_data)
            
            # Perform security analysis if analyzer is available
            if self.security_analyzer:
                try:
                    parsed_data['security_analysis'] = self.security_analyzer.analyze_email_security(email_content)
                except Exception as e:
                    parsed_data['security_analysis'] = {
                        'error': f'Security analysis failed: {str(e)}',
                        'urls': [],
                        'ips': [],
                        'url_analysis': [],
                        'ip_analysis': [],
                        'overall_threat_level': 'unknown'
                    }
            
            self.parsed_data = parsed_data
            return parsed_data
            
        except Exception as e:
            return {
                'error': f"Failed to parse email headers: {str(e)}",
                'headers': {},
                'sender_info': {},
                'routing_info': {},
                'authentication': {},
                'suspicious_indicators': [],
                'confidence_factors': {}
            }
    
    def _analyze_sender(self, msg: EmailMessage) -> Dict:
        """Analyze sender-related information."""
        sender_info = {
            'from_address': msg.get('From', ''),
            'reply_to': msg.get('Reply-To', ''),
            'return_path': msg.get('Return-Path', ''),
            'sender': msg.get('Sender', ''),
            'display_name': '',
            'domain': '',
            'is_valid_email': False,
            'domain_reputation': 'unknown'
        }
        
        # Extract display name and email from From field
        from_field = sender_info['from_address']
        if from_field:
            # Parse "Display Name <email@domain.com>" format
            match = re.match(r'^(.+?)\s*<(.+?)>$', from_field.strip())
            if match:
                sender_info['display_name'] = match.group(1).strip(' "\'')
                sender_info['from_address'] = match.group(2).strip()
            
            # Extract domain
            email_match = re.search(r'@([a-zA-Z0-9.-]+)', sender_info['from_address'])
            if email_match:
                sender_info['domain'] = email_match.group(1).lower()
                
                # Validate email
                try:
                    if EMAIL_VALIDATOR_AVAILABLE:
                        validate_email(sender_info['from_address'])
                        sender_info['is_valid_email'] = True
                    else:
                        # Basic email validation fallback
                        sender_info['is_valid_email'] = self._basic_email_validation(sender_info['from_address'])
                except EmailNotValidError:
                    sender_info['is_valid_email'] = False
                except Exception:
                    # Fallback validation
                    sender_info['is_valid_email'] = self._basic_email_validation(sender_info['from_address'])
        
        return sender_info
    
    def _analyze_routing(self, msg: EmailMessage) -> Dict:
        """Analyze email routing information."""
        routing_info = {
            'received_headers': [],
            'message_id': msg.get('Message-ID', ''),
            'x_originating_ip': msg.get('X-Originating-IP', ''),
            'x_forwarded_for': msg.get('X-Forwarded-For', ''),
            'x_real_ip': msg.get('X-Real-IP', ''),
            'hop_count': 0,
            'suspicious_hops': []
        }
        
        # Parse Received headers
        received_headers = msg.get_all('Received') or []
        for i, received in enumerate(received_headers):
            hop_info = self._parse_received_header(received, i)
            routing_info['received_headers'].append(hop_info)
        
        routing_info['hop_count'] = len(received_headers)
        
        return routing_info
    
    def _parse_received_header(self, received: str, hop_number: int) -> Dict:
        """Parse individual Received header."""
        hop_info = {
            'hop_number': hop_number,
            'raw': received,
            'from_server': '',
            'by_server': '',
            'timestamp': '',
            'ip_address': '',
            'suspicious': False
        }
        
        # Extract 'from' server
        from_match = re.search(r'from\s+([^\s\[\(]+)', received, re.IGNORECASE)
        if from_match:
            hop_info['from_server'] = from_match.group(1)
        
        # Extract 'by' server
        by_match = re.search(r'by\s+([^\s\[\(]+)', received, re.IGNORECASE)
        if by_match:
            hop_info['by_server'] = by_match.group(1)
        
        # Extract IP address
        ip_match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
        if ip_match:
            hop_info['ip_address'] = ip_match.group(1)
        
        # Extract timestamp
        timestamp_match = re.search(r';\s*(.+)$', received)
        if timestamp_match:
            hop_info['timestamp'] = timestamp_match.group(1).strip()
        
        return hop_info
    
    def _analyze_authentication(self, msg: EmailMessage) -> Dict:
        """Analyze email authentication headers."""
        auth_info = {
            'spf': self._parse_auth_header(msg.get('Received-SPF', '')),
            'dkim': self._parse_auth_header(msg.get('DKIM-Signature', '')),
            'dmarc': self._parse_auth_header(msg.get('Authentication-Results', '')),
            'arc': self._parse_auth_header(msg.get('ARC-Authentication-Results', '')),
            'overall_auth_status': 'unknown'
        }
        
        # Determine overall authentication status
        auth_passes = 0
        auth_total = 0
        
        for auth_type, result in auth_info.items():
            if auth_type != 'overall_auth_status' and result.get('status'):
                auth_total += 1
                if result['status'].lower() in ['pass', 'valid', 'success']:
                    auth_passes += 1
        
        if auth_total > 0:
            auth_ratio = auth_passes / auth_total
            if auth_ratio >= 0.8:
                auth_info['overall_auth_status'] = 'strong'
            elif auth_ratio >= 0.5:
                auth_info['overall_auth_status'] = 'moderate'
            else:
                auth_info['overall_auth_status'] = 'weak'
        
        return auth_info
    
    def _parse_auth_header(self, header_value: str) -> Dict:
        """Parse authentication header value."""
        if not header_value:
            return {'status': 'not_present', 'details': ''}
        
        # Simple parsing - can be enhanced for specific auth types
        header_lower = header_value.lower()
        if 'pass' in header_lower:
            status = 'pass'
        elif 'fail' in header_lower:
            status = 'fail'
        elif 'none' in header_lower:
            status = 'none'
        else:
            status = 'unknown'
        
        return {
            'status': status,
            'details': header_value
        }
    
    def _detect_suspicious_patterns(self, parsed_data: Dict) -> List[Dict]:
        """Detect suspicious patterns in parsed email data."""
        indicators = []
        
        # Check sender-related suspicions
        sender_info = parsed_data['sender_info']
        
        # Suspicious display name vs email mismatch
        if sender_info['display_name'] and sender_info['from_address']:
            if self._is_display_name_spoofed(sender_info['display_name'], sender_info['from_address']):
                indicators.append({
                    'type': 'display_name_spoofing',
                    'severity': 'high',
                    'description': 'Display name doesn\'t match email domain',
                    'details': f"Display: {sender_info['display_name']}, Email: {sender_info['from_address']}"
                })
        
        # Invalid email format
        if not sender_info['is_valid_email'] and sender_info['from_address']:
            indicators.append({
                'type': 'invalid_email',
                'severity': 'medium',
                'description': 'From address has invalid email format',
                'details': sender_info['from_address']
            })
        
        # Suspicious domains
        if sender_info['domain']:
            domain_issues = self._check_domain_reputation(sender_info['domain'])
            indicators.extend(domain_issues)
        
        # Authentication failures
        auth_info = parsed_data['authentication']
        if auth_info['overall_auth_status'] == 'weak':
            indicators.append({
                'type': 'weak_authentication',
                'severity': 'medium',
                'description': 'Email failed multiple authentication checks',
                'details': f"SPF: {auth_info['spf']['status']}, DKIM: {auth_info['dkim']['status']}"
            })
        
        # Reply-To mismatch
        if (sender_info['reply_to'] and sender_info['from_address'] and 
            sender_info['reply_to'] != sender_info['from_address']):
            indicators.append({
                'type': 'reply_to_mismatch',
                'severity': 'low',
                'description': 'Reply-To address differs from From address',
                'details': f"From: {sender_info['from_address']}, Reply-To: {sender_info['reply_to']}"
            })
        
        return indicators
    
    def _is_display_name_spoofed(self, display_name: str, email_address: str) -> bool:
        """Check if display name appears to be spoofing a legitimate service."""
        # Common spoofed service indicators
        legitimate_services = [
            'paypal', 'amazon', 'microsoft', 'google', 'apple', 'bank',
            'visa', 'mastercard', 'dhl', 'fedex', 'ups', 'netflix'
        ]
        
        display_lower = display_name.lower()
        email_lower = email_address.lower()
        
        for service in legitimate_services:
            if service in display_lower and service not in email_lower:
                return True
        
        return False
    
    def _basic_email_validation(self, email_address: str) -> bool:
        """Basic email validation when email_validator is not available."""
        if not email_address:
            return False
        
        # Basic regex for email validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email_address))
    
    def _check_domain_reputation(self, domain: str) -> List[Dict]:
        """Check domain reputation indicators."""
        indicators = []
        
        # Extract domain components
        if TLDEXTRACT_AVAILABLE:
            ext_result = tldextract.extract(domain)
            domain_name = ext_result.domain
            domain_suffix = ext_result.suffix
        else:
            # Fallback domain parsing
            parts = domain.split('.')
            if len(parts) >= 2:
                domain_name = parts[-2]
                domain_suffix = parts[-1]
            else:
                domain_name = domain
                domain_suffix = ''
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
        if f".{domain_suffix}" in suspicious_tlds:
            indicators.append({
                'type': 'suspicious_tld',
                'severity': 'medium',
                'description': f'Domain uses suspicious TLD: .{domain_suffix}',
                'details': domain
            })
        
        # Check for recently registered domains (simplified check)
        if len(domain_name) < 4:
            indicators.append({
                'type': 'short_domain',
                'severity': 'low',
                'description': 'Very short domain name',
                'details': domain
            })
        
        # Check for homograph attacks (basic)
        if self._contains_suspicious_chars(domain):
            indicators.append({
                'type': 'suspicious_characters',
                'severity': 'medium',
                'description': 'Domain contains suspicious characters',
                'details': domain
            })
        
        return indicators
    
    def _contains_suspicious_chars(self, domain: str) -> bool:
        """Check for suspicious characters that might indicate homograph attacks."""
        # Basic check for mixed scripts or suspicious Unicode
        suspicious_patterns = [
            r'[а-я]',  # Cyrillic characters
            r'[αβγδε]',  # Greek characters
            r'\d{4,}',  # Long sequences of numbers
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return True
        
        return False
    
    def _calculate_confidence_factors(self, parsed_data: Dict) -> Dict:
        """Calculate factors that contribute to phishing confidence."""
        factors = {
            'authentication_score': 0,
            'sender_legitimacy': 0,
            'domain_reputation': 0,
            'routing_anomalies': 0,
            'overall_risk_score': 0
        }
        
        # Authentication score (0-100)
        auth_status = parsed_data['authentication']['overall_auth_status']
        if auth_status == 'strong':
            factors['authentication_score'] = 90
        elif auth_status == 'moderate':
            factors['authentication_score'] = 60
        elif auth_status == 'weak':
            factors['authentication_score'] = 20
        else:
            factors['authentication_score'] = 10
        
        # Sender legitimacy (0-100)
        sender_info = parsed_data['sender_info']
        if sender_info['is_valid_email']:
            factors['sender_legitimacy'] = 70
        else:
            factors['sender_legitimacy'] = 20
        
        # Domain reputation (inverse scoring - lower is better)
        domain_indicators = [ind for ind in parsed_data['suspicious_indicators'] 
                           if ind['type'] in ['suspicious_tld', 'short_domain', 'suspicious_characters']]
        factors['domain_reputation'] = max(0, 80 - (len(domain_indicators) * 30))
        
        # Calculate overall risk score (0-100, higher = more suspicious)
        high_severity = len([ind for ind in parsed_data['suspicious_indicators'] if ind['severity'] == 'high'])
        medium_severity = len([ind for ind in parsed_data['suspicious_indicators'] if ind['severity'] == 'medium'])
        low_severity = len([ind for ind in parsed_data['suspicious_indicators'] if ind['severity'] == 'low'])
        
        risk_score = (high_severity * 40) + (medium_severity * 25) + (low_severity * 10)
        
        # Factor in authentication
        if factors['authentication_score'] < 50:
            risk_score += 30
        
        factors['overall_risk_score'] = min(100, risk_score)
        
        return factors