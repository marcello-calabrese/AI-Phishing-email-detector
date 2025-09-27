"""
Security Analysis Module

This module provides functionality to check URLs and IP addresses
against external security services like VirusTotal and IP reputation APIs.
"""

import re
import time
import requests
import base64
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, unquote, parse_qs

# Optional import for VirusTotal
try:
    import vt
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False
    vt = None


class SecurityAnalyzer:
    """Analyze URLs and IP addresses against security databases."""
    
    def __init__(self, virustotal_api_key: Optional[str] = None, 
                 abuseipdb_api_key: Optional[str] = None):
        """
        Initialize SecurityAnalyzer with API keys.
        
        Args:
            virustotal_api_key: VirusTotal API key
            abuseipdb_api_key: AbuseIPDB API key
        """
        self.logger = logging.getLogger(__name__)
        self.vt_api_key = virustotal_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.vt_client = None
        self.url_cache: Dict[str, Dict[str, Any]] = {}
        self.url_cache_ttl = 15 * 60  # 15 minutes cache window
        self.ip_cache: Dict[str, Dict[str, Any]] = {}
        self.ip_cache_ttl = 60 * 60  # 1 hour cache window
        self.max_cache_entries = 256
        self.url_submission_history: Dict[str, float] = {}
        self.url_submission_cooldown = 15 * 60  # 15 minutes between submissions
        
        if self.vt_api_key and VT_AVAILABLE and vt:
            try:
                self.vt_client = vt.Client(self.vt_api_key)
            except Exception:
                self.vt_client = None

    def _get_cached_entry(self, cache: Dict[str, Dict[str, Any]], key: str, ttl: float) -> Optional[Dict[str, Any]]:
        """Return a cached result if it exists and is fresh."""
        entry = cache.get(key)
        if not entry:
            return None

        now = time.time()
        if now - entry['timestamp'] >= ttl:
            cache.pop(key, None)
            return None

        return dict(entry['result'])

    def _store_cache_entry(self, cache: Dict[str, Dict[str, Any]], key: str, value: Dict[str, Any]) -> None:
        """Store a result in the cache while enforcing size limits."""
        while len(cache) >= self.max_cache_entries:
            oldest_key = next(iter(cache))
            cache.pop(oldest_key, None)

        sanitized_value = dict(value)
        sanitized_value.pop('cache_hit', None)

        cache[key] = {
            'timestamp': time.time(),
            'result': sanitized_value
        }

    def _trim_submission_history(self) -> None:
        """Ensure the submission history does not grow without bound."""
        if len(self.url_submission_history) <= self.max_cache_entries:
            return

        excess = len(self.url_submission_history) - self.max_cache_entries
        oldest_entries = sorted(
            self.url_submission_history.items(),
            key=lambda item: item[1]
        )[:excess]

        for url, _ in oldest_entries:
            self.url_submission_history.pop(url, None)

    def _should_submit_url(self, url: str) -> bool:
        """Determine whether a URL should be re-submitted to VirusTotal."""
        if self.url_submission_cooldown <= 0:
            return True

        now = time.time()
        last_submission = self.url_submission_history.get(url)

        if last_submission and now - last_submission < self.url_submission_cooldown:
            return False

        self.url_submission_history[url] = now
        self._trim_submission_history()
        return True

    def extract_safelinks_urls(self, email_content: str) -> List[Dict[str, str]]:
        """
        Extract original URLs from Microsoft SafeLinks wrappers.
        
        Args:
            email_content: Raw email content
            
        Returns:
            List of dictionaries with 'original' and 'safelinks' URL pairs
        """
        safelinks_results = []
        
        # Pattern for SafeLinks URLs - matches various regional domains
        safelinks_pattern = re.compile(
            r'https?://[a-zA-Z0-9]+\.safelinks\.protection\.outlook\.com/\?url=([^&\s]+)',
            re.IGNORECASE
        )
        
        matches = safelinks_pattern.findall(email_content)
        
        for encoded_url in matches:
            try:
                # URL decode the extracted parameter
                decoded_url = unquote(encoded_url)
                
                # Find the full SafeLinks URL for reference
                safelinks_url_pattern = re.compile(
                    rf'https?://[a-zA-Z0-9]+\.safelinks\.protection\.outlook\.com/\?url={re.escape(encoded_url)}[^"\'\s]*',
                    re.IGNORECASE
                )
                
                safelinks_match = safelinks_url_pattern.search(email_content)
                safelinks_url = safelinks_match.group(0) if safelinks_match else f"SafeLinks wrapper for {decoded_url}"
                
                safelinks_results.append({
                    'original': decoded_url,
                    'safelinks': safelinks_url,
                    'type': 'safelinks'
                })
                
            except Exception as e:
                # If decoding fails, log but continue
                self.logger.warning(f"Failed to decode SafeLinks URL {encoded_url}: {e}")
                continue
        
        return safelinks_results
    
    def extract_urls_from_email(self, email_content: str) -> List[str]:
        """
        Extract URLs from email content.
        
        Args:
            email_content: Raw email content
            
        Returns:
            List of URLs found in the email
        """
        # Regex pattern for URLs
        url_pattern = re.compile(
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            re.IGNORECASE
        )
        
        # Also look for URLs in email headers
        header_url_pattern = re.compile(
            r'(?:href=|url=|link=)["\']?(https?://[^"\'\s>]+)["\']?',
            re.IGNORECASE
        )
        
        urls = []
        
        # First, extract SafeLinks URLs and get the original URLs
        safelinks_results = self.extract_safelinks_urls(email_content)
        original_urls = [result['original'] for result in safelinks_results]
        urls.extend(original_urls)
        
        # Extract standard URLs (excluding SafeLinks wrappers)
        standard_urls = url_pattern.findall(email_content)
        # Filter out SafeLinks URLs from standard extraction
        filtered_standard_urls = [
            url for url in standard_urls 
            if 'safelinks.protection.outlook.com' not in url
        ]
        urls.extend(filtered_standard_urls)
        
        # Extract URLs from HTML attributes (excluding SafeLinks)
        header_urls = header_url_pattern.findall(email_content)
        filtered_header_urls = [
            url for url in header_urls 
            if 'safelinks.protection.outlook.com' not in url
        ]
        urls.extend(filtered_header_urls)
        
        # Remove duplicates and return
        return list(set(urls))
    
    def extract_ips_from_email(self, email_content: str) -> List[str]:
        """
        Extract IP addresses from email content and headers.
        
        Args:
            email_content: Raw email content
            
        Returns:
            List of IP addresses found in the email
        """
        # IPv4 pattern
        ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        ips = []
        
        # Extract from various header fields
        received_pattern = re.compile(r'Received:.*?\[(\d+\.\d+\.\d+\.\d+)\]', re.IGNORECASE | re.MULTILINE)
        originating_ip_pattern = re.compile(r'X-Originating-IP:\s*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
        real_ip_pattern = re.compile(r'X-Real-IP:\s*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE)
        
        # Extract IPs from different sources
        ips.extend(ipv4_pattern.findall(email_content))
        ips.extend(received_pattern.findall(email_content))
        ips.extend(originating_ip_pattern.findall(email_content))
        ips.extend(real_ip_pattern.findall(email_content))
        
        # Filter out private/local IPs
        filtered_ips = []
        for ip in set(ips):
            if self._is_public_ip(ip):
                filtered_ips.append(ip)
        
        return filtered_ips
    
    def _is_public_ip(self, ip: str) -> bool:
        """Check if IP address is public (not private/local)."""
        try:
            parts = [int(part) for part in ip.split('.')]
            
            # Private IP ranges
            if parts[0] == 10:
                return False
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return False
            if parts[0] == 192 and parts[1] == 168:
                return False
            if parts[0] == 127:  # Loopback
                return False
            if parts[0] == 169 and parts[1] == 254:  # Link-local
                return False
            
            return True
        except:
            return False
    
    async def check_url_virustotal(self, url: str) -> Dict:
        """
        Check URL against VirusTotal.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with VirusTotal analysis results
        """
        if not self.vt_client or not VT_AVAILABLE or not vt:
            return {
                'error': 'VirusTotal API not available or not configured',
                'url': url,
                'malicious': False,
                'suspicious': False,
                'detections': 0,
                'total_scans': 0
            }
        
        try:
            # Get URL analysis using vt-py library
            if not vt:
                raise Exception("vt module not available")
                
            url_id = vt.url_id(url)
            url_obj = await self.vt_client.get_object_async(f"/urls/{url_id}")
            
            # Extract relevant information
            stats = url_obj.last_analysis_stats
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0
            
            return {
                'url': url,
                'malicious': malicious > 0,
                'suspicious': suspicious > 0,
                'detections': malicious + suspicious,
                'total_scans': total,
                'malicious_count': malicious,
                'suspicious_count': suspicious,
                'clean_count': stats.get('clean', 0),
                'undetected_count': stats.get('undetected', 0),
                'scan_date': url_obj.last_analysis_date.isoformat() if url_obj.last_analysis_date else None,
                'permalink': f"https://www.virustotal.com/gui/url/{url_id}/detection"
            }
            
        except Exception as e:
            return {
                'error': f'VirusTotal API error: {str(e)}',
                'url': url,
                'malicious': False,
                'suspicious': False,
                'detections': 0,
                'total_scans': 0
            }
    
    def check_url_virustotal_sync(self, url: str) -> Dict:
        """
        Synchronous version of VirusTotal URL check.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with VirusTotal analysis results
        """
        if not self.vt_api_key:
            return {
                'error': 'VirusTotal API key not configured',
                'url': url,
                'malicious': False,
                'suspicious': False,
                'detections': 0,
                'total_scans': 0
            }
        
        try:
            cached_result = self._get_cached_entry(self.url_cache, url, self.url_cache_ttl)
            if cached_result:
                cached_result['cache_hit'] = True
                return cached_result

            now = time.time()

            # Use VirusTotal API v3 with requests for synchronous call
            if not vt:
                # Fallback to direct API calls if vt-py not available
                result = self._check_url_with_requests_api(url)
                result['cache_hit'] = False
                if result.get('status') != 'submission_failed':
                    self._store_cache_entry(self.url_cache, url, result)
                return result

            client = self.vt_client
            created_client = False
            if client is None:
                client = vt.Client(self.vt_api_key)
                created_client = True

            try:
                url_id = vt.url_id(url)
                try:
                    url_obj = client.get_object(f"/urls/{url_id}")

                    # Extract relevant information
                    stats = url_obj.last_analysis_stats or {}
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values()) if stats else 0

                    result = {
                        'url': url,
                        'malicious': malicious > 0,
                        'suspicious': suspicious > 0,
                        'detections': malicious + suspicious,
                        'total_scans': total,
                        'malicious_count': malicious,
                        'suspicious_count': suspicious,
                        'clean_count': stats.get('clean', 0),
                        'undetected_count': stats.get('undetected', 0),
                        'scan_date': url_obj.last_analysis_date.isoformat() if url_obj.last_analysis_date else None,
                        'permalink': f"https://www.virustotal.com/gui/url/{url_id}/detection",
                        'cache_hit': False
                    }

                    self._store_cache_entry(self.url_cache, url, result)
                    return result

                except vt.APIError as e:
                    if e.code == "NotFoundError":
                        # URL not in database, submit for scanning if allowed
                        status = 'submitted_for_scanning'
                        message = 'URL submitted for scanning, check again later'

                        if self._should_submit_url(url):
                            try:
                                client.scan_url(url)
                            except Exception as submit_error:
                                status = 'submission_failed'
                                message = f'URL submission failed: {submit_error}'
                                self.logger.warning(
                                    "VirusTotal submission failed for %s: %s",
                                    url,
                                    submit_error
                                )
                        else:
                            status = 'recently_submitted'
                            message = 'URL recently submitted, skipping duplicate submission'

                        result = {
                            'url': url,
                            'malicious': False,
                            'suspicious': False,
                            'detections': 0,
                            'total_scans': 0,
                            'status': status,
                            'message': message,
                            'cache_hit': False
                        }

                        if status != 'submission_failed':
                            self._store_cache_entry(self.url_cache, url, result)

                        return result
                    else:
                        raise e
            finally:
                if created_client and client:
                    client.close()

            return {
                'error': 'Unable to get VirusTotal report',
                'url': url,
                'malicious': False,
                'suspicious': False,
                'detections': 0,
                'total_scans': 0,
                'cache_hit': False
            }
            
        except Exception as e:
            return {
                'error': f'VirusTotal API error: {str(e)}',
                'url': url,
                'malicious': False,
                'suspicious': False,
                'detections': 0,
                'total_scans': 0,
                'cache_hit': False
            }
    
    def _check_url_with_requests_api(self, url: str) -> Dict:
        """Fallback method using direct API calls when vt-py is not available."""
        try:
            headers = {'x-apikey': self.vt_api_key}
            
            # Use VirusTotal API v3
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = sum(stats.values()) if stats else 0
                
                return {
                    'url': url,
                    'malicious': malicious > 0,
                    'suspicious': suspicious > 0,
                    'detections': malicious + suspicious,
                    'total_scans': total,
                    'malicious_count': malicious,
                    'suspicious_count': suspicious,
                    'clean_count': stats.get('clean', 0),
                    'undetected_count': stats.get('undetected', 0)
                }
            elif response.status_code == 404:
                # URL not found, submit for scanning if not recently submitted
                if not self._should_submit_url(url):
                    return {
                        'url': url,
                        'malicious': False,
                        'suspicious': False,
                        'detections': 0,
                        'total_scans': 0,
                        'status': 'recently_submitted',
                        'message': 'URL recently submitted, skipping duplicate submission'
                    }

                scan_url = 'https://www.virustotal.com/api/v3/urls'
                scan_data = {'url': url}
                scan_response = requests.post(scan_url, headers=headers, data=scan_data, timeout=10)

                if scan_response.status_code not in (200, 202):
                    return {
                        'url': url,
                        'malicious': False,
                        'suspicious': False,
                        'detections': 0,
                        'total_scans': 0,
                        'status': 'submission_failed',
                        'message': f'URL submission returned status {scan_response.status_code}'
                    }
                
                return {
                    'url': url,
                    'malicious': False,
                    'suspicious': False,
                    'detections': 0,
                    'total_scans': 0,
                    'status': 'submitted_for_scanning',
                    'message': 'URL submitted for scanning, check again later'
                }
            else:
                return {
                    'error': f'VirusTotal API returned status {response.status_code}',
                    'url': url,
                    'malicious': False,
                    'suspicious': False,
                    'detections': 0,
                    'total_scans': 0
                }
        except Exception as e:
            return {
                'error': f'Direct API call failed: {str(e)}',
                'url': url,
                'malicious': False,
                'suspicious': False,
                'detections': 0,
                'total_scans': 0
            }
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """
        Check IP address reputation using multiple sources.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with IP reputation analysis results
        """
        cached_result = self._get_cached_entry(self.ip_cache, ip, self.ip_cache_ttl)
        if cached_result:
            cached_result['cache_hit'] = True
            return cached_result

        results = {
            'ip': ip,
            'malicious': False,
            'suspicious': False,
            'reputation_score': 0,
            'sources': {}
        }
        
        # Check AbuseIPDB if API key available
        if self.abuseipdb_api_key:
            abuseipdb_result = self._check_abuseipdb(ip)
            results['sources']['abuseipdb'] = abuseipdb_result
            
            if abuseipdb_result.get('abuse_confidence', 0) > 75:
                results['malicious'] = True
            elif abuseipdb_result.get('abuse_confidence', 0) > 25:
                results['suspicious'] = True
        
        # Check additional free sources
        results['sources']['ipqualityscore'] = self._check_ipqualityscore_free(ip)
        results['sources']['talos'] = self._check_talos_reputation(ip)
        
        # Calculate overall reputation score
        scores = []
        for source, data in results['sources'].items():
            if 'score' in data:
                scores.append(data['score'])
        
        if scores:
            results['reputation_score'] = sum(scores) / len(scores)
            results['malicious'] = results['reputation_score'] > 75
            results['suspicious'] = results['reputation_score'] > 25
        
        results['cache_hit'] = False
        self._store_cache_entry(self.ip_cache, ip, results)
        return results
    
    def _check_abuseipdb(self, ip: str) -> Dict:
        """Check IP against AbuseIPDB."""
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'service': 'AbuseIPDB',
                    'abuse_confidence': data['data'].get('abuseConfidencePercentage', 0),
                    'total_reports': data['data'].get('totalReports', 0),
                    'is_whitelisted': data['data'].get('isWhitelisted', False),
                    'country_code': data['data'].get('countryCode', ''),
                    'score': data['data'].get('abuseConfidencePercentage', 0)
                }
        except Exception as e:
            pass
        
        return {'service': 'AbuseIPDB', 'error': 'API call failed', 'score': 0}
    
    def _check_ipqualityscore_free(self, ip: str) -> Dict:
        """Check IP against IPQualityScore free tier."""
        try:
            # This is a basic check using their free service
            # For production, you'd want to use their paid API
            url = f'https://ipqualityscore.com/api/json/ip/free/{ip}'
            
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                fraud_score = data.get('fraud_score', 0)
                
                return {
                    'service': 'IPQualityScore',
                    'fraud_score': fraud_score,
                    'vpn': data.get('vpn', False),
                    'tor': data.get('tor', False),
                    'proxy': data.get('proxy', False),
                    'score': fraud_score
                }
        except Exception as e:
            pass
        
        return {'service': 'IPQualityScore', 'error': 'API call failed', 'score': 0}
    
    def _check_talos_reputation(self, ip: str) -> Dict:
        """Check IP against Cisco Talos reputation (basic check)."""
        try:
            # This is a basic implementation
            # Talos doesn't have a simple REST API, so this is a placeholder
            # In practice, you might scrape their web interface or use another service
            
            return {
                'service': 'Cisco Talos',
                'status': 'neutral',
                'score': 50  # Neutral score
            }
        except Exception as e:
            pass
        
        return {'service': 'Cisco Talos', 'error': 'Check failed', 'score': 50}
    
    def analyze_email_security(self, email_content: str) -> Dict:
        """
        Perform comprehensive security analysis of email content.
        
        Args:
            email_content: Raw email content
            
        Returns:
            Dictionary with complete security analysis
        """
        results = {
            'urls': [],
            'ips': [],
            'url_analysis': [],
            'ip_analysis': [],
            'safelinks_analysis': [],
            'overall_threat_level': 'low',
            'security_summary': {
                'malicious_urls': 0,
                'suspicious_urls': 0,
                'malicious_ips': 0,
                'suspicious_ips': 0,
                'safelinks_found': 0,
                'total_threats': 0
            }
        }
        
        # Extract SafeLinks URLs first
        safelinks_results = self.extract_safelinks_urls(email_content)
        results['safelinks_analysis'] = safelinks_results
        results['security_summary']['safelinks_found'] = len(safelinks_results)
        
        # Extract URLs and IPs
        urls = self.extract_urls_from_email(email_content)
        ips = self.extract_ips_from_email(email_content)
        
        results['urls'] = urls
        results['ips'] = ips
        
        # Analyze URLs
        for url in urls[:5]:  # Limit to 5 URLs to avoid API limits
            url_result = self.check_url_virustotal_sync(url)
            results['url_analysis'].append(url_result)
            
            if url_result.get('malicious'):
                results['security_summary']['malicious_urls'] += 1
            elif url_result.get('suspicious'):
                results['security_summary']['suspicious_urls'] += 1
        
        # Analyze SafeLinks extracted URLs (enhance the safelinks_analysis with VT results)
        for safelinks_item in results['safelinks_analysis']:
            original_url = safelinks_item['original']
            vt_result = self.check_url_virustotal_sync(original_url)
            
            # Add VirusTotal analysis to the SafeLinks item
            safelinks_item['virustotal_analysis'] = vt_result
            safelinks_item['threat_level'] = 'clean'
            
            if vt_result.get('malicious'):
                results['security_summary']['malicious_urls'] += 1
                safelinks_item['threat_level'] = 'malicious'
            elif vt_result.get('suspicious'):
                results['security_summary']['suspicious_urls'] += 1
                safelinks_item['threat_level'] = 'suspicious'
        
        # Analyze IPs
        for ip in ips[:5]:  # Limit to 5 IPs to avoid API limits
            ip_result = self.check_ip_reputation(ip)
            results['ip_analysis'].append(ip_result)
            
            if ip_result.get('malicious'):
                results['security_summary']['malicious_ips'] += 1
            elif ip_result.get('suspicious'):
                results['security_summary']['suspicious_ips'] += 1
        
        # Calculate overall threat level
        total_malicious = (results['security_summary']['malicious_urls'] + 
                          results['security_summary']['malicious_ips'])
        total_suspicious = (results['security_summary']['suspicious_urls'] + 
                           results['security_summary']['suspicious_ips'])
        
        results['security_summary']['total_threats'] = total_malicious + total_suspicious
        
        if total_malicious > 0:
            results['overall_threat_level'] = 'high'
        elif total_suspicious > 0:
            results['overall_threat_level'] = 'medium'
        else:
            results['overall_threat_level'] = 'low'
        
        return results
    
    def __del__(self):
        """Cleanup VirusTotal client."""
        if hasattr(self, 'vt_client') and self.vt_client and VT_AVAILABLE and vt:
            try:
                self.vt_client.close()
            except Exception:
                pass