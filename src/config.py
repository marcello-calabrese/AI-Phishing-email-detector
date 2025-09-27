"""
Configuration Management Module

This module handles configuration loading, validation, and management
for the AI Phishing Email Detector application.
"""

import json

import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
from datetime import datetime


class ConfigManager:
    """Manage application configuration and settings."""
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = Path(config_path)
        self.config = {}
        self.logger = logging.getLogger(__name__)
        
        # Default configuration
        self.default_config = {
            "openai_api_key": "",
            "confidence_thresholds": {
                "low": 30,
                "medium": 60,
                "high": 80
            },
            "report_settings": {
                "default_format": "pdf",
                "include_technical_details": True,
                "company_name": "Security Analysis Team"
            },
            "ai_settings": {
                "model": "gpt-4o-mini",
                "temperature": 0.1,
                "max_tokens": 2000
            },
            "dataset_settings": {
                "phishing_dataset_path": "data/phishing_email.csv",
                "enable_dataset_learning": True
            },
            "security_api_keys": {
                "virustotal_api_key": "",
                "abuseipdb_api_key": "",
                "security_analysis_enabled": True
            },
            "storage_settings": {
                "history_enabled": True,
                "max_history_entries": 1000,
                "auto_cleanup_days": 30
            },
            "ui_settings": {
                "page_title": "AI Phishing Email Detector",
                "page_icon": "🔒",
                "layout": "wide",
                "theme": "auto"
            }
        }
        
        self.load_config()
    
    def load_config(self) -> bool:
        """
        Load configuration from file.
        
        Returns:
            True if configuration loaded successfully, False otherwise
        """
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                
                # Merge with default config
                self.config = self._merge_configs(self.default_config, file_config)
                self.logger.info(f"Configuration loaded from {self.config_path}")
                
                # Validate configuration
                if not self._validate_config():
                    self.logger.warning("Configuration validation failed, using defaults where necessary")
                
                return True
            else:
                self.logger.warning(f"Configuration file {self.config_path} not found, using defaults")
                self.config = self.default_config.copy()
                return False
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in configuration file: {e}")
            self.config = self.default_config.copy()
            return False
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            self.config = self.default_config.copy()
            return False
    
    def save_config(self) -> bool:
        """
        Save current configuration to file.
        
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Create directory if it doesn't exist
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Configuration saved to {self.config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False
    
    def _merge_configs(self, default: Dict, override: Dict) -> Dict:
        """
        Recursively merge configuration dictionaries.
        
        Args:
            default: Default configuration
            override: Override configuration
            
        Returns:
            Merged configuration
        """
        merged = default.copy()
        
        for key, value in override.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
        
        return merged
    
    def _validate_config(self) -> bool:
        """
        Validate the current configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Check required fields
            if not self.config.get('openai_api_key'):
                self.logger.warning("OpenAI API key not configured")
            
            # Validate confidence thresholds
            thresholds = self.config.get('confidence_thresholds', {})
            if not all(isinstance(thresholds.get(level), (int, float)) and 0 <= thresholds.get(level) <= 100 
                      for level in ['low', 'medium', 'high']):
                self.logger.warning("Invalid confidence thresholds, using defaults")
                self.config['confidence_thresholds'] = self.default_config['confidence_thresholds']
            
            # Validate AI model settings
            ai_settings = self.config.get('ai_settings', {})
            if not isinstance(ai_settings.get('temperature'), (int, float)) or not 0 <= ai_settings.get('temperature') <= 2:
                self.config['ai_settings']['temperature'] = self.default_config['ai_settings']['temperature']
            
            if not isinstance(ai_settings.get('max_tokens'), int) or ai_settings.get('max_tokens') <= 0:
                self.config['ai_settings']['max_tokens'] = self.default_config['ai_settings']['max_tokens']
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation error: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation for nested keys)
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        try:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            
            return value
            
        except Exception:
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """
        Set configuration value by key.
        
        Args:
            key: Configuration key (supports dot notation for nested keys)
            value: Value to set
            
        Returns:
            True if set successfully, False otherwise
        """
        try:
            keys = key.split('.')
            config_ref = self.config
            
            # Navigate to parent of target key
            for k in keys[:-1]:
                if k not in config_ref:
                    config_ref[k] = {}
                config_ref = config_ref[k]
            
            # Set the final key
            config_ref[keys[-1]] = value
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting configuration key {key}: {e}")
            return False
    
    def get_openai_config(self) -> Dict[str, Any]:
        """Get OpenAI-specific configuration."""
        return {
            'api_key': self.get('openai_api_key'),
            'model': self.get('ai_settings.model'),
            'temperature': self.get('ai_settings.temperature'),
            'max_tokens': self.get('ai_settings.max_tokens')
        }
    
    def get_confidence_thresholds(self) -> Dict[str, int]:
        """Get confidence threshold settings."""
        return self.get('confidence_thresholds', self.default_config['confidence_thresholds'])
    
    def get_report_settings(self) -> Dict[str, Any]:
        """Get report generation settings."""
        return self.get('report_settings', self.default_config['report_settings'])
    
    def get_ui_settings(self) -> Dict[str, Any]:
        """Get UI settings."""
        return self.get('ui_settings', self.default_config['ui_settings'])
    
    def get_security_api_keys(self) -> Dict[str, Any]:
        """Get security API keys configuration."""
        return self.get('security_api_keys', self.default_config['security_api_keys'])
    
    def get_virustotal_api_key(self) -> str:
        """Get VirusTotal API key."""
        return self.get('security_api_keys.virustotal_api_key', '')
    
    def get_abuseipdb_api_key(self) -> str:
        """Get AbuseIPDB API key."""
        return self.get('security_api_keys.abuseipdb_api_key', '')
    
    def get_dataset_settings(self) -> Dict[str, Any]:
        """Get dataset settings."""
        return self.get('dataset_settings', {})
    
    def get_dataset_path(self) -> Optional[str]:
        """Get phishing dataset path."""
        if not self.get('dataset_settings.enable_dataset_learning', True):
            return None
        
        path = self.get('dataset_settings.phishing_dataset_path', '')
        if path and Path(path).exists():
            return path
        return None
    
    def is_security_analysis_enabled(self) -> bool:
        """Check if security analysis is enabled."""
        return self.get('security_api_keys.security_analysis_enabled', True)
    
    def is_configured(self) -> bool:
        """Check if the application is properly configured."""
        return bool(self.get('openai_api_key'))
    
    def create_template_config(self) -> bool:
        """Create a template configuration file."""
        try:
            template_path = self.config_path.parent / f"{self.config_path.stem}.template{self.config_path.suffix}"
            
            with open(template_path, 'w', encoding='utf-8') as f:
                json.dump(self.default_config, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Template configuration created at {template_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error creating template configuration: {e}")
            return False


class HistoryManager:
    """Manage analysis history storage and retrieval."""
    
    def __init__(self, data_dir: str = "data"):
        """
        Initialize history manager.
        
        Args:
            data_dir: Directory for storing history data
        """
        self.data_dir = Path(data_dir)
        self.history_file = self.data_dir / "analysis_history.json"
        self.logger = logging.getLogger(__name__)
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def save_analysis(self, analysis_result: Dict) -> bool:
        """
        Save an analysis result to history.
        
        Args:
            analysis_result: Complete analysis result dictionary
            
        Returns:
            True if saved successfully, False otherwise
        """
        try:
            # Load existing history
            history = self._load_history()
            
            # Add new analysis with unique ID
            analysis_id = f"analysis_{len(history) + 1}_{int(datetime.now().timestamp())}"
            history[analysis_id] = {
                'timestamp': analysis_result.get('timestamp'),
                'sender': analysis_result.get('email_data', {}).get('sender_info', {}).get('from_address', 'Unknown'),
                'confidence_score': analysis_result.get('final_assessment', {}).get('confidence_score', 0),
                'risk_level': analysis_result.get('final_assessment', {}).get('risk_level', 'unknown'),
                'is_likely_phishing': analysis_result.get('final_assessment', {}).get('is_likely_phishing', False),
                'summary': analysis_result.get('ai_analysis', {}).get('summary', 'No summary available'),
                'full_result': analysis_result
            }
            
            # Save updated history
            return self._save_history(history)
            
        except Exception as e:
            self.logger.error(f"Error saving analysis to history: {e}")
            return False
    
    def get_history(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Get analysis history.
        
        Args:
            limit: Maximum number of entries to return (most recent first)
            
        Returns:
            List of analysis history entries
        """
        try:
            history = self._load_history()
            
            # Convert to list and sort by timestamp (most recent first)
            history_list = []
            for analysis_id, data in history.items():
                entry = data.copy()
                entry['id'] = analysis_id
                history_list.append(entry)
            
            # Sort by timestamp (newest first)
            history_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            if limit:
                history_list = history_list[:limit]
            
            return history_list
            
        except Exception as e:
            self.logger.error(f"Error retrieving history: {e}")
            return []
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """
        Get a specific analysis by ID.
        
        Args:
            analysis_id: Analysis ID
            
        Returns:
            Analysis result or None if not found
        """
        try:
            history = self._load_history()
            entry = history.get(analysis_id)
            
            if entry:
                return entry.get('full_result')
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error retrieving analysis {analysis_id}: {e}")
            return None
    
    def delete_analysis(self, analysis_id: str) -> bool:
        """
        Delete a specific analysis.
        
        Args:
            analysis_id: Analysis ID to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            history = self._load_history()
            
            if analysis_id in history:
                del history[analysis_id]
                return self._save_history(history)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error deleting analysis {analysis_id}: {e}")
            return False
    
    def cleanup_old_entries(self, days: int = 30) -> int:
        """
        Clean up old history entries.
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of entries removed
        """
        try:
            from datetime import datetime, timedelta
            
            cutoff_date = datetime.now() - timedelta(days=days)
            history = self._load_history()
            
            entries_to_remove = []
            for analysis_id, data in history.items():
                timestamp_str = data.get('timestamp', '')
                try:
                    entry_date = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    if entry_date < cutoff_date:
                        entries_to_remove.append(analysis_id)
                except ValueError:
                    # Remove entries with invalid timestamps
                    entries_to_remove.append(analysis_id)
            
            # Remove old entries
            for analysis_id in entries_to_remove:
                del history[analysis_id]
            
            if entries_to_remove:
                self._save_history(history)
            
            return len(entries_to_remove)
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old entries: {e}")
            return 0
    
    def _load_history(self) -> Dict:
        """Load history from file."""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                return {}
        except Exception as e:
            self.logger.error(f"Error loading history: {e}")
            return {}
    
    def _save_history(self, history: Dict) -> bool:
        """Save history to file."""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            self.logger.error(f"Error saving history: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics."""
        try:
            history_list = self.get_history()
            
            total_analyses = len(history_list)
            phishing_detected = sum(1 for entry in history_list if entry.get('is_likely_phishing', False))
            
            # Risk level distribution
            risk_distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            for entry in history_list:
                risk_level = entry.get('risk_level', 'unknown')
                if risk_level in risk_distribution:
                    risk_distribution[risk_level] += 1
            
            # Average confidence score
            confidence_scores = [entry.get('confidence_score', 0) for entry in history_list]
            avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
            
            return {
                'total_analyses': total_analyses,
                'phishing_detected': phishing_detected,
                'clean_emails': total_analyses - phishing_detected,
                'phishing_rate': (phishing_detected / total_analyses * 100) if total_analyses > 0 else 0,
                'risk_distribution': risk_distribution,
                'average_confidence': round(avg_confidence, 1)
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating statistics: {e}")
            return {
                'total_analyses': 0,
                'phishing_detected': 0,
                'clean_emails': 0,
                'phishing_rate': 0,
                'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                'average_confidence': 0
            }