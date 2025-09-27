"""
Dataset Management Module

Handles phishing email dataset for pattern analysis and prompt enhancement.
"""
import pandas as pd
import json
import re
import logging
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from collections import Counter


class PhishingDatasetManager:
    """Manage phishing email dataset for analysis enhancement."""
    
    def __init__(self, dataset_path: str = "data/phishing_email.csv"):
        self.dataset_path = Path(dataset_path)
        self.df = None
        self.patterns = {}
        self.loaded = False
        self.logger = logging.getLogger(__name__)
        
    def load_dataset(self) -> bool:
        """Load and validate the phishing dataset."""
        try:
            if not self.dataset_path.exists():
                self.logger.error(f"Dataset not found at {self.dataset_path}")
                return False
                
            # Load CSV with encoding handling
            try:
                self.df = pd.read_csv(self.dataset_path, encoding='utf-8')
            except UnicodeDecodeError:
                try:
                    self.df = pd.read_csv(self.dataset_path, encoding='latin-1')
                except UnicodeDecodeError:
                    self.df = pd.read_csv(self.dataset_path, encoding='cp1252', errors='replace')
            
            # Try to identify text and label columns
            possible_text_cols = ['text', 'body', 'content', 'message', 'email']
            possible_label_cols = ['label', 'class', 'target', 'is_phishing']
            
            text_col = None
            label_col = None
            
            # Find text column
            for col in self.df.columns:
                if col.lower() in possible_text_cols:
                    text_col = col
                    break
            
            # Find label column
            for col in self.df.columns:
                if col.lower() in possible_label_cols:
                    label_col = col
                    break
            
            # If not found, use first two columns
            if text_col is None:
                text_col = self.df.columns[0]
            if label_col is None:
                label_col = self.df.columns[1] if len(self.df.columns) > 1 else self.df.columns[0]
            
            # Standardize column names
            self.df = self.df.rename(columns={text_col: 'text', label_col: 'label'})
            
            # Validate labels - convert to 0/1 if needed
            unique_labels = self.df['label'].unique()
            if set(unique_labels) == {0, 1}:
                pass  # Already correct
            elif set(unique_labels) == {'0', '1'}:
                self.df['label'] = self.df['label'].astype(int)
            elif len(unique_labels) == 2:
                # Map to 0/1
                label_mapping = {unique_labels[0]: 0, unique_labels[1]: 1}
                self.df['label'] = self.df['label'].map(label_mapping)
            else:
                self.logger.error(f"Invalid labels found: {unique_labels}")
                return False
            
            # Clean text data
            self.df['text'] = self.df['text'].fillna('').astype(str)
            
            self.logger.info(f"✅ Dataset loaded successfully!")
            self.logger.info(f"📊 Total emails: {len(self.df)}")
            self.logger.info(f"🎣 Phishing emails: {len(self.df[self.df['label'] == 1])}")
            self.logger.info(f"✅ Legitimate emails: {len(self.df[self.df['label'] == 0])}")
            
            self.loaded = True
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading dataset: {e}")
            return False
    
    def extract_phishing_patterns(self) -> Dict:
        """Extract common patterns from phishing emails."""
        if not self.loaded:
            return {}
            
        phishing_emails = self.df[self.df['label'] == 1]['text'].tolist()
        legitimate_emails = self.df[self.df['label'] == 0]['text'].tolist()
        
        if not phishing_emails or not legitimate_emails:
            self.logger.warning("Insufficient data for pattern extraction")
            return {}
        
        patterns = {
            'urgent_words': self._extract_urgent_words(phishing_emails, legitimate_emails),
            'suspicious_phrases': self._extract_suspicious_phrases(phishing_emails, legitimate_emails),
            'common_domains': self._extract_domains(phishing_emails),
            'subject_patterns': self._extract_subject_patterns(phishing_emails),
            'call_to_action': self._extract_cta_patterns(phishing_emails),
            'impersonation_patterns': self._extract_impersonation_patterns(phishing_emails),
            'length_indicators': self._analyze_length_patterns(phishing_emails, legitimate_emails)
        }
        
        self.patterns = patterns
        self.logger.info(f"✅ Extracted {len(patterns)} pattern categories")
        return patterns
    
    def _extract_urgent_words(self, phishing_emails: List[str], legitimate_emails: List[str]) -> List[str]:
        """Extract words that appear more frequently in phishing emails."""
        urgent_words = [
            'urgent', 'immediately', 'expire', 'suspend', 'verify', 'confirm',
            'update', 'security', 'alert', 'warning', 'attention', 'action',
            'required', 'deadline', 'limited', 'offer', 'click', 'now',
            'account', 'blocked', 'frozen', 'locked', 'unauthorized', 'winner',
            'congratulations', 'prize', 'claim', 'act', 'fast', 'hurry'
        ]
        
        # Count occurrences in phishing vs legitimate
        phishing_text = ' '.join(phishing_emails).lower()
        legitimate_text = ' '.join(legitimate_emails).lower()
        
        filtered_words = []
        for word in urgent_words:
            phishing_count = phishing_text.count(word)
            legitimate_count = legitimate_text.count(word)
            
            # If word appears significantly more in phishing than legitimate
            if phishing_count > 5 and (phishing_count / max(legitimate_count, 1)) > 2:
                filtered_words.append({
                    'word': word,
                    'phishing_count': phishing_count,
                    'legitimate_count': legitimate_count,
                    'risk_ratio': phishing_count / max(legitimate_count, 1)
                })
        
        # Sort by risk ratio and return top words
        filtered_words.sort(key=lambda x: x['risk_ratio'], reverse=True)
        return [item['word'] for item in filtered_words[:15]]
    
    def _extract_suspicious_phrases(self, phishing_emails: List[str], legitimate_emails: List[str]) -> List[str]:
        """Extract common suspicious phrases."""
        phrases = []
        
        # Common phishing phrase patterns
        common_patterns = [
            r'verify your account',
            r'click here to',
            r'your account will be',
            r'suspended.*account',
            r'confirm your identity',
            r'update.*payment',
            r'security.*alert',
            r'immediate.*action',
            r'limited.*time',
            r'dear customer',
            r'congratulations.*won',
            r'claim.*prize',
            r'act now',
            r'expires today',
            r'final notice'
        ]
        
        phrase_counts = Counter()
        
        for email in phishing_emails:
            email_lower = email.lower()
            for pattern in common_patterns:
                matches = re.findall(pattern, email_lower)
                phrase_counts.update(matches)
        
        # Filter out phrases that also appear frequently in legitimate emails
        legitimate_text = ' '.join(legitimate_emails).lower()
        filtered_phrases = []
        
        for phrase, phishing_count in phrase_counts.most_common(20):
            legitimate_count = legitimate_text.count(phrase)
            if phishing_count > 3 and (phishing_count / max(legitimate_count, 1)) > 3:
                filtered_phrases.append(phrase)
        
        return filtered_phrases[:10]
    
    def _extract_domains(self, phishing_emails: List[str]) -> List[str]:
        """Extract suspicious domains from phishing emails."""
        domains = []
        
        # Extract domains from URLs and email addresses
        domain_pattern = r'(?:https?://|www\.|@)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        
        for email in phishing_emails:
            matches = re.findall(domain_pattern, email.lower())
            domains.extend(matches)
        
        # Filter common legitimate domains
        legitimate_domains = {
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com'
        }
        
        suspicious_domains = [domain for domain in domains 
                             if domain not in legitimate_domains]
        
        # Return most common suspicious domains
        return [domain for domain, count in Counter(suspicious_domains).most_common(8)]
    
    def _extract_subject_patterns(self, phishing_emails: List[str]) -> List[str]:
        """Extract common subject line patterns."""
        subject_keywords = []
        
        # Look for subject-like patterns at the beginning of emails
        for email in phishing_emails:
            lines = email.split('\n')
            first_line = lines[0].strip() if lines else ''
            
            # Extract keywords from first line (likely subject)
            words = re.findall(r'\b[a-zA-Z]{3,}\b', first_line.lower())
            subject_keywords.extend(words[:5])  # First 5 words
        
        return [word for word, count in Counter(subject_keywords).most_common(10)]
    
    def _extract_cta_patterns(self, phishing_emails: List[str]) -> List[str]:
        """Extract call-to-action patterns."""
        cta_patterns = [
            r'click\s+(?:here|now|this|link)',
            r'download\s+(?:now|here|attachment)',
            r'verify\s+(?:now|here|account|identity)',
            r'update\s+(?:now|here|information|details)',
            r'confirm\s+(?:now|here|identity|account)',
            r'sign\s+(?:in|up)\s+(?:now|here)',
            r'visit\s+(?:now|here|link)',
            r'call\s+(?:now|immediately)',
            r'reply\s+(?:now|immediately)'
        ]
        
        ctas = []
        for email in phishing_emails:
            email_lower = email.lower()
            for pattern in cta_patterns:
                matches = re.findall(pattern, email_lower)
                ctas.extend(matches)
        
        return [cta for cta, count in Counter(ctas).most_common(8)]
    
    def _extract_impersonation_patterns(self, phishing_emails: List[str]) -> List[str]:
        """Extract common impersonation patterns."""
        impersonation_keywords = [
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'bank', 'visa', 'mastercard', 'irs', 'fedex', 'ups', 'dhl',
            'netflix', 'ebay', 'linkedin', 'twitter', 'instagram', 'spotify',
            'adobe', 'dropbox', 'zoom', 'skype', 'whatsapp'
        ]
        
        found_impersonations = []
        for email in phishing_emails:
            email_lower = email.lower()
            for keyword in impersonation_keywords:
                if keyword in email_lower:
                    found_impersonations.append(keyword)
        
        return [imp for imp, count in Counter(found_impersonations).most_common(8)]
    
    def _analyze_length_patterns(self, phishing_emails: List[str], legitimate_emails: List[str]) -> Dict:
        """Analyze email length patterns."""
        phishing_lengths = [len(email) for email in phishing_emails]
        legitimate_lengths = [len(email) for email in legitimate_emails]
        
        return {
            'phishing_avg_length': sum(phishing_lengths) / len(phishing_lengths) if phishing_lengths else 0,
            'legitimate_avg_length': sum(legitimate_lengths) / len(legitimate_lengths) if legitimate_lengths else 0,
            'phishing_short_threshold': 200,  # Emails shorter than this are often phishing
            'phishing_long_threshold': 2000   # Very long emails might be spam
        }
    
    def get_sample_emails(self, label: int, count: int = 3) -> List[str]:
        """Get sample emails for prompt examples."""
        if not self.loaded:
            return []
            
        samples = self.df[self.df['label'] == label]['text'].head(count).tolist()
        # Truncate long samples for prompt efficiency
        return [email[:500] + "..." if len(email) > 500 else email for email in samples]
    
    def save_patterns(self, output_path: str = "data/phishing_patterns.json") -> bool:
        """Save extracted patterns to JSON file."""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.patterns, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"✅ Patterns saved to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving patterns: {e}")
            return False
    
    def load_patterns(self, input_path: str = "data/phishing_patterns.json") -> bool:
        """Load patterns from JSON file."""
        try:
            input_file = Path(input_path)
            if not input_file.exists():
                return False
                
            with open(input_file, 'r', encoding='utf-8') as f:
                self.patterns = json.load(f)
            
            self.logger.info(f"✅ Patterns loaded from {input_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading patterns: {e}")
            return False
    
    def get_dataset_stats(self) -> Dict:
        """Get dataset statistics for reporting."""
        if not self.loaded:
            return {}
            
        phishing_count = len(self.df[self.df['label'] == 1])
        legitimate_count = len(self.df[self.df['label'] == 0])
        total_count = len(self.df)
        
        stats = {
            'total_emails': total_count,
            'phishing_emails': phishing_count,
            'legitimate_emails': legitimate_count,
            'phishing_percentage': (phishing_count / total_count) * 100 if total_count > 0 else 0,
            'average_email_length': int(self.df['text'].str.len().mean()) if total_count > 0 else 0,
            'patterns_extracted': len(self.patterns) if self.patterns else 0,
            'dataset_file': str(self.dataset_path)
        }
        
        return stats
    
    def get_pattern_summary(self) -> str:
        """Get a summary of extracted patterns for display."""
        if not self.patterns:
            return "No patterns extracted yet."
        
        summary = []
        for pattern_type, patterns in self.patterns.items():
            if isinstance(patterns, list) and patterns:
                summary.append(f"• {pattern_type.replace('_', ' ').title()}: {len(patterns)} patterns")
            elif isinstance(patterns, dict):
                summary.append(f"• {pattern_type.replace('_', ' ').title()}: Analyzed")
        
        return "\n".join(summary)

    def get_learned_patterns(self) -> Dict:
        """Get extracted patterns for AI enhancement."""
        if not self.loaded:
            return {}
        
        if not self.patterns:
            self.extract_phishing_patterns()
        
        # Convert to the format expected by AI analyzer
        learned_patterns = {
            'urgent_words': self.patterns.get('urgent_words', []),
            'suspicious_phrases': self.patterns.get('suspicious_phrases', []),
            'suspicious_domains': self.patterns.get('suspicious_domains', []),
            'subject_patterns': self.patterns.get('subject_patterns', []),
            'cta_patterns': self.patterns.get('call_to_action', []),
            'impersonation_patterns': self.patterns.get('impersonation_patterns', []),
            'total_samples': len(self.df) if self.df is not None else 0
        }
        
        return learned_patterns