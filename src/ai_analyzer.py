"""
AI Analysis Module using OpenAI

This module provides AI-powered analysis of email headers for phishing detection
using OpenAI's GPT models.
"""

import json
import logging
import re
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import threading
import openai
from openai import OpenAI
from dataset_manager import PhishingDatasetManager


class AIPhishingAnalyzer:
    """AI-powered phishing analysis using OpenAI."""

    _dataset_cache: Dict[str, PhishingDatasetManager] = {}
    _dataset_cache_lock = threading.Lock()

    def __init__(self, api_key: str, model: str = "gpt-4o-mini", dataset_path: Optional[str] = None):
        """
        Initialize the AI analyzer.
        
        Args:
            api_key: OpenAI API key
            model: OpenAI model to use for analysis
            dataset_path: Optional path to phishing dataset CSV file
        """
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.logger = logging.getLogger(__name__)
        
        # Initialize dataset manager if dataset path is provided
        self.dataset_manager = None
        if dataset_path:
            self.dataset_manager = self._get_cached_dataset_manager(dataset_path)
            if self.dataset_manager:
                self.logger.info("Phishing dataset loaded from cache")
            else:
                self.logger.warning("Could not load phishing dataset; proceeding without pattern enhancements")

    @classmethod
    def _get_cached_dataset_manager(cls, dataset_path: str) -> Optional[PhishingDatasetManager]:
        """Return a cached dataset manager instance, loading it if necessary."""
        try:
            normalized_path = str(Path(dataset_path).expanduser().resolve())
        except Exception:
            normalized_path = dataset_path

        with cls._dataset_cache_lock:
            manager = cls._dataset_cache.get(normalized_path)
            if manager and getattr(manager, 'loaded', False):
                return manager

            manager = PhishingDatasetManager(normalized_path)
            if manager.load_dataset():
                # Precompute patterns to avoid repeated extraction later
                try:
                    manager.get_learned_patterns()
                except Exception:
                    cls._dataset_cache[normalized_path] = manager
                    return manager

                cls._dataset_cache[normalized_path] = manager
                return manager

            return None
    
    def analyze_email_headers(self, parsed_data: Dict) -> Dict:
        """
        Analyze parsed email data for phishing indicators using AI.
        
        Args:
            parsed_data: Dictionary containing parsed email header information
            
        Returns:
            Dictionary containing AI analysis results
        """
        try:
            # Prepare the analysis prompt
            analysis_prompt = self._create_analysis_prompt(parsed_data)
            
            # Get AI analysis
            # Prepare API parameters - use model defaults for GPT-5
            api_params = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user", 
                        "content": analysis_prompt
                    }
                ]
            }
            
            # Only add parameters for older models (GPT-5 uses defaults)
            if "gpt-5" not in self.model.lower():
                api_params["temperature"] = 0.1  # Low temperature for consistent analysis
                api_params["max_tokens"] = 2000
            
            response = self.client.chat.completions.create(**api_params)
            
            # Parse the response
            ai_response = response.choices[0].message.content
            analysis_result = self._parse_ai_response(ai_response)
            
            # Combine with existing parsed data
            final_result = self._merge_analysis_results(parsed_data, analysis_result)
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {str(e)}")
            return self._create_fallback_analysis(parsed_data, str(e))
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the AI model."""
        base_prompt = """You are an expert cybersecurity analyst specializing in email security and phishing detection. 

Your task is to analyze email header information and provide a detailed assessment of whether the email is likely to be a phishing attempt.

You should:
1. Analyze all provided email header data thoroughly
2. Look for indicators of phishing, spoofing, and malicious intent
3. Consider authentication results (SPF, DKIM, DMARC)
4. Evaluate sender legitimacy and domain reputation
5. Analyze content for social engineering tactics
6. Assess for known malicious indicators (e.g., blacklisted URLs, phishing kits)
7. Check if the email content contains urgent language or threats
8. Check if there is gibberish or unusual formatting in the email body
9. Check if there is base64 encoded content in the email body and consider potential implications
10. Verify the IP addresses against known blacklists or threat intelligence sources like VirusTotal
11. Assess routing anomalies and suspicious patterns
12. Provide a confidence score (0-100) where higher scores indicate higher likelihood of phishing
13. Explain your reasoning clearly and professionally"""

        # Add dataset-learned patterns if available
        if self.dataset_manager:
            patterns = self.dataset_manager.get_learned_patterns()
            if patterns:
                base_prompt += f"""

LEARNED PHISHING PATTERNS FROM DATASET:
Based on analysis of {patterns.get('total_samples', 0)} email samples, pay special attention to:

URGENT WORDS: {', '.join(patterns.get('urgent_words', [])[:10])}
SUSPICIOUS PHRASES: {', '.join(patterns.get('suspicious_phrases', [])[:10])}
COMMON PHISHING DOMAINS: {', '.join(patterns.get('suspicious_domains', [])[:10])}
TYPICAL SUBJECT PATTERNS: {', '.join(patterns.get('subject_patterns', [])[:5])}
COMMON CALL-TO-ACTIONS: {', '.join(patterns.get('cta_patterns', [])[:5])}
IMPERSONATION INDICATORS: {', '.join(patterns.get('impersonation_patterns', [])[:5])}

Use these patterns to enhance your analysis accuracy."""

        base_prompt += """

Return your analysis in JSON format with the following structure:
{
    "confidence_score": <0-100 integer>,
    "risk_level": "<low|medium|high|critical>",
    "summary": "<brief summary of findings>",
    "detailed_analysis": "<detailed explanation of your analysis>",
    "key_indicators": [
        {
            "indicator": "<indicator name>",
            "severity": "<low|medium|high>",
            "description": "<explanation>",
            "evidence": "<specific evidence from headers>"
        }
    ],
    "recommendations": [
        "<actionable recommendation 1>",
        "<actionable recommendation 2>"
    ]
}

Be thorough but concise. Focus on actionable insights for IT security professionals."""
        
        return base_prompt

    def _create_analysis_prompt(self, parsed_data: Dict) -> str:
        """Create the analysis prompt with email data."""
        prompt = f"""Please analyze the following email header information for phishing indicators:

EMAIL HEADER ANALYSIS DATA:

=== SENDER INFORMATION ===
From Address: {parsed_data['sender_info'].get('from_address', 'N/A')}
Display Name: {parsed_data['sender_info'].get('display_name', 'N/A')}
Reply-To: {parsed_data['sender_info'].get('reply_to', 'N/A')}
Return-Path: {parsed_data['sender_info'].get('return_path', 'N/A')}
Domain: {parsed_data['sender_info'].get('domain', 'N/A')}
Valid Email Format: {parsed_data['sender_info'].get('is_valid_email', False)}

=== AUTHENTICATION RESULTS ===
SPF Status: {parsed_data['authentication']['spf'].get('status', 'N/A')}
DKIM Status: {parsed_data['authentication']['dkim'].get('status', 'N/A')}
DMARC Status: {parsed_data['authentication']['dmarc'].get('status', 'N/A')}
Overall Auth Status: {parsed_data['authentication'].get('overall_auth_status', 'N/A')}

=== ROUTING INFORMATION ===
Message ID: {parsed_data['routing_info'].get('message_id', 'N/A')}
Originating IP: {parsed_data['routing_info'].get('x_originating_ip', 'N/A')}
Hop Count: {parsed_data['routing_info'].get('hop_count', 0)}

Received Headers:
"""

        # Add received headers information
        for hop in parsed_data['routing_info'].get('received_headers', []):
            prompt += f"  Hop {hop.get('hop_number', 0)}: From {hop.get('from_server', 'unknown')} by {hop.get('by_server', 'unknown')}"
            if hop.get('ip_address'):
                prompt += f" [{hop['ip_address']}]"
            prompt += f" at {hop.get('timestamp', 'unknown')}\n"

        prompt += f"""
=== SUSPICIOUS INDICATORS DETECTED ===
"""
        
        # Add pre-detected suspicious indicators
        if parsed_data.get('suspicious_indicators'):
            for indicator in parsed_data['suspicious_indicators']:
                prompt += f"- {indicator.get('type', 'unknown')}: {indicator.get('description', 'N/A')} (Severity: {indicator.get('severity', 'unknown')})\n"
                if indicator.get('details'):
                    prompt += f"  Details: {indicator['details']}\n"
        else:
            prompt += "None detected by initial parsing\n"

        prompt += f"""
=== CONFIDENCE FACTORS ===
Authentication Score: {parsed_data['confidence_factors'].get('authentication_score', 0)}/100
Sender Legitimacy: {parsed_data['confidence_factors'].get('sender_legitimacy', 0)}/100
Domain Reputation: {parsed_data['confidence_factors'].get('domain_reputation', 0)}/100
Initial Risk Score: {parsed_data['confidence_factors'].get('overall_risk_score', 0)}/100

=== ORIGINAL HEADERS (SAMPLE) ===
"""
        
        # Add a sample of original headers for context
        headers_sample = dict(list(parsed_data.get('headers', {}).items())[:10])
        for header, value in headers_sample.items():
            # Truncate long header values
            display_value = value[:100] + "..." if len(str(value)) > 100 else value
            prompt += f"{header}: {display_value}\n"

        prompt += "\nPlease provide your detailed analysis in the specified JSON format."
        
        return prompt

    def _parse_ai_response(self, response: str) -> Dict:
        """Parse the AI response into structured data."""
        try:
            # Try to extract JSON from the response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end]
                analysis_result = json.loads(json_str)
                
                # Validate required fields
                required_fields = ['confidence_score', 'risk_level', 'summary', 'detailed_analysis']
                for field in required_fields:
                    if field not in analysis_result:
                        analysis_result[field] = 'N/A'
                
                # Ensure confidence score is in valid range
                if isinstance(analysis_result.get('confidence_score'), (int, float)):
                    analysis_result['confidence_score'] = max(0, min(100, int(analysis_result['confidence_score'])))
                else:
                    analysis_result['confidence_score'] = 50
                
                # Ensure risk level is valid
                valid_risk_levels = ['low', 'medium', 'high', 'critical']
                if analysis_result.get('risk_level') not in valid_risk_levels:
                    # Map confidence score to risk level
                    confidence = analysis_result['confidence_score']
                    if confidence >= 80:
                        analysis_result['risk_level'] = 'critical'
                    elif confidence >= 60:
                        analysis_result['risk_level'] = 'high'
                    elif confidence >= 30:
                        analysis_result['risk_level'] = 'medium'
                    else:
                        analysis_result['risk_level'] = 'low'
                
                return analysis_result
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse AI response as JSON: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing AI response: {e}")
        
        # Fallback parsing if JSON extraction fails
        return self._extract_fallback_analysis(response)

    def _extract_fallback_analysis(self, response: str) -> Dict:
        """Extract analysis information from non-JSON response."""
        # Basic pattern matching for key information
        confidence_score = 50  # Default
        risk_level = 'medium'  # Default
        
        # Try to extract confidence score
        confidence_patterns = [
            r'confidence[:\s]+(\d+)',
            r'score[:\s]+(\d+)',
            r'(\d+)%',
            r'(\d+)/100'
        ]
        
        for pattern in confidence_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                confidence_score = max(0, min(100, int(match.group(1))))
                break
        
        # Try to extract risk level
        risk_patterns = [
            r'risk[:\s]+(low|medium|high|critical)',
            r'level[:\s]+(low|medium|high|critical)',
            r'(low|medium|high|critical)\s+risk'
        ]
        
        for pattern in risk_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                risk_level = match.group(1).lower()
                break
        
        return {
            'confidence_score': confidence_score,
            'risk_level': risk_level,
            'summary': response[:200] + "..." if len(response) > 200 else response,
            'detailed_analysis': response,
            'key_indicators': [],
            'recommendations': ['Review email manually for additional indicators'],
            'parsing_note': 'Fallback parsing used - JSON response not properly formatted'
        }

    def _merge_analysis_results(self, parsed_data: Dict, ai_analysis: Dict) -> Dict:
        """Merge AI analysis with existing parsed data."""
        # Create the final result structure
        result = {
            'timestamp': datetime.now().isoformat(),
            'email_data': parsed_data,
            'ai_analysis': ai_analysis,
            'final_assessment': {
                'confidence_score': ai_analysis.get('confidence_score', 50),
                'risk_level': ai_analysis.get('risk_level', 'medium'),
                'is_likely_phishing': ai_analysis.get('confidence_score', 50) >= 70,
                'summary': ai_analysis.get('summary', 'Analysis completed'),
                'total_indicators': len(parsed_data.get('suspicious_indicators', [])) + len(ai_analysis.get('key_indicators', []))
            },
            'recommendations': ai_analysis.get('recommendations', []),
            'technical_details': {
                'model_used': self.model,
                'parsing_version': '1.0',
                'analysis_components': ['header_parsing', 'pattern_detection', 'ai_analysis']
            }
        }
        
        return result

    def _create_fallback_analysis(self, parsed_data: Dict, error_message: str) -> Dict:
        """Create a fallback analysis when AI analysis fails."""
        # Use the confidence factors from parsed data
        confidence_factors = parsed_data.get('confidence_factors', {})
        risk_score = confidence_factors.get('overall_risk_score', 50)
        
        # Determine risk level based on parsed indicators
        suspicious_count = len(parsed_data.get('suspicious_indicators', []))
        high_severity_count = len([ind for ind in parsed_data.get('suspicious_indicators', []) 
                                 if ind.get('severity') == 'high'])
        
        if high_severity_count > 0 or risk_score >= 80:
            risk_level = 'high'
        elif suspicious_count > 2 or risk_score >= 60:
            risk_level = 'medium'
        elif suspicious_count > 0 or risk_score >= 30:
            risk_level = 'low'
        else:
            risk_level = 'low'
        
        return {
            'timestamp': datetime.now().isoformat(),
            'email_data': parsed_data,
            'ai_analysis': {
                'confidence_score': min(100, max(0, risk_score)),
                'risk_level': risk_level,
                'summary': f'Analysis completed using fallback method. {suspicious_count} suspicious indicators detected.',
                'detailed_analysis': f'AI analysis unavailable ({error_message}). Analysis based on header parsing and pattern detection only.',
                'key_indicators': parsed_data.get('suspicious_indicators', []),
                'recommendations': [
                    'Verify sender authenticity through alternative means',
                    'Check for similar phishing campaigns',
                    'Consider blocking sender domain if highly suspicious'
                ],
                'fallback_mode': True,
                'error': error_message
            },
            'final_assessment': {
                'confidence_score': min(100, max(0, risk_score)),
                'risk_level': risk_level,
                'is_likely_phishing': risk_score >= 70,
                'summary': f'Fallback analysis: {suspicious_count} suspicious indicators found',
                'total_indicators': suspicious_count
            },
            'recommendations': [
                'Manual review recommended due to AI analysis failure',
                'Verify sender through alternative communication channels'
            ],
            'technical_details': {
                'model_used': 'fallback',
                'parsing_version': '1.0',
                'analysis_components': ['header_parsing', 'pattern_detection'],
                'ai_error': error_message
            }
        }

    def test_connection(self) -> bool:
        """Test the OpenAI API connection."""
        try:
            # Prepare API parameters - use model defaults for GPT-5
            api_params = {
                "model": self.model,
                "messages": [{"role": "user", "content": "Test connection"}]
            }
            
            # Only add token limit for older models (GPT-5 uses defaults)
            if "gpt-5" not in self.model.lower():
                api_params["max_tokens"] = 10
            
            response = self.client.chat.completions.create(**api_params)
            return True
        except Exception as e:
            self.logger.error(f"OpenAI connection test failed: {e}")
            return False