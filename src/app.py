"""
Streamlit Web Application

Main web interface for the AI Phishing Email Detector.
Provides a VirusTotal-inspired UI for email analysis.
"""

import streamlit as st
import pandas as pd

# Optional imports with fallbacks
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    px = None
    go = None

from datetime import datetime, timedelta
import hashlib

import logging
from pathlib import Path
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import ConfigManager, HistoryManager
from email_parser import EmailHeaderParser
from ai_analyzer import AIPhishingAnalyzer
from report_generator import ReportGenerator
from security_analyzer import SecurityAnalyzer


class PhishingDetectorApp:
    """Main Streamlit application class."""
    
    def __init__(self):
        """Initialize the application."""
        self.setup_logging()
        self.config_manager = ConfigManager()
        self.history_manager = HistoryManager()
        self.report_generator = ReportGenerator()
        
        # Initialize session state
        if 'analysis_result' not in st.session_state:
            st.session_state.analysis_result = None
        if 'config_loaded' not in st.session_state:
            st.session_state.config_loaded = False
    
    def setup_logging(self):
        """Set up logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def run(self):
        """Run the Streamlit application."""
        # Configure page
        ui_settings = self.config_manager.get_ui_settings()
        st.set_page_config(
            page_title=ui_settings.get('page_title', 'AI Phishing Email Detector'),
            page_icon=ui_settings.get('page_icon', '🔒'),
            layout=ui_settings.get('layout', 'wide'),
            initial_sidebar_state='expanded'
        )
        
        # Custom CSS for VirusTotal-inspired styling
        self.apply_custom_css()
        
        # Main header
        self.render_header()
        
        # Sidebar
        self.render_sidebar()
        
        # Main content area
        if not self.config_manager.is_configured():
            self.render_configuration_page()
        else:
            # Main navigation
            selected_tab = st.selectbox(
                "Navigate to:",
                ["🔍 Email Analysis", "📊 Dashboard", "📋 History", "⚙️ Settings"],
                key="main_navigation"
            )
            
            if selected_tab == "🔍 Email Analysis":
                self.render_analysis_page()
            elif selected_tab == "📊 Dashboard":
                self.render_dashboard_page()
            elif selected_tab == "📋 History":
                self.render_history_page()
            elif selected_tab == "⚙️ Settings":
                self.render_settings_page()
    
    def apply_custom_css(self):
        """Apply custom CSS for VirusTotal-inspired styling."""
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
            padding: 2rem 1rem;
            border-radius: 10px;
            color: white;
            text-align: center;
            margin-bottom: 2rem;
        }
        
        /* Enhanced button styling */
        .stButton > button[kind="primary"] {
            background: linear-gradient(45deg, #ff6b6b, #ff8e8e) !important;
            border: none !important;
            border-radius: 12px !important;
            font-size: 18px !important;
            font-weight: bold !important;
            padding: 0.75rem 2rem !important;
            box-shadow: 0 4px 15px rgba(255, 107, 107, 0.3) !important;
            transition: all 0.3s ease !important;
            text-transform: uppercase !important;
            letter-spacing: 1px !important;
        }
        
        .stButton > button[kind="primary"]:hover {
            background: linear-gradient(45deg, #ff5252, #ff7979) !important;
            box-shadow: 0 6px 20px rgba(255, 107, 107, 0.4) !important;
            transform: translateY(-2px) !important;
        }
        
        .stButton > button[kind="primary"]:active {
            transform: translateY(0px) !important;
            box-shadow: 0 2px 10px rgba(255, 107, 107, 0.3) !important;
        }
        
        /* Disabled button styling */
        .stButton > button:disabled {
            background: linear-gradient(45deg, #e9ecef, #f8f9fa) !important;
            color: #6c757d !important;
            border: 2px dashed #dee2e6 !important;
            border-radius: 12px !important;
            font-size: 16px !important;
            padding: 0.75rem 2rem !important;
            cursor: not-allowed !important;
        }
        
        .risk-high {
            background-color: #ff4444;
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        .risk-medium {
            background-color: #ffaa00;
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        .risk-low {
            background-color: #44aa44;
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
        }
        .risk-critical {
            background-color: #cc0000;
            color: white;
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            font-weight: bold;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        .metric-card {
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #2a5298;
        }
        .indicator-card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 6px;
            border-left: 3px solid #dc3545;
            margin: 0.5rem 0;
        }
        .success-card {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 1rem;
            border-radius: 6px;
            color: #155724;
        }
        .warning-card {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 1rem;
            border-radius: 6px;
            color: #856404;
        }
        .info-card {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            padding: 1rem;
            border-radius: 6px;
            color: #0c5460;
        }
        .stTabs > div > div > div > div {
            padding: 1rem;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def render_header(self):
        """Render the main application header."""
        st.markdown("""
        <div class="main-header">
            <h1>🔒 AI Phishing Email Detector</h1>
            <p>Advanced email security analysis powered by artificial intelligence</p>
        </div>
        """, unsafe_allow_html=True)
    
    def render_sidebar(self):
        """Render the sidebar with quick info and controls."""
        with st.sidebar:
            st.title("Quick Info")
            
            # Configuration status
            if self.config_manager.is_configured():
                st.success("✅ Configuration loaded")
            else:
                st.error("❌ Configuration required")
            
            # Statistics
            try:
                stats = self.history_manager.get_statistics()
                st.subheader("Analysis Statistics")
                st.metric("Total Analyses", stats['total_analyses'])
                st.metric("Phishing Detected", stats['phishing_detected'])
                if stats['total_analyses'] > 0:
                    st.metric("Detection Rate", f"{stats['phishing_rate']:.1f}%")
            except Exception as e:
                st.warning("Could not load statistics")
            
            # Quick actions
            st.subheader("Quick Actions")
            if st.button("🧹 Clear Session", help="Clear current analysis"):
                st.session_state.analysis_result = None
                st.rerun()
            
            if st.button("� Clear Security Cache", help="Clear VirusTotal/IP reputation cache"):
                if hasattr(st.session_state, 'security_analyzer_cache'):
                    # Clear the cached security analyzers to force fresh API calls
                    for analyzer in st.session_state.security_analyzer_cache.values():
                        if hasattr(analyzer, 'url_cache'):
                            analyzer.url_cache.clear()
                        if hasattr(analyzer, 'ip_cache'):
                            analyzer.ip_cache.clear()
                        if hasattr(analyzer, 'url_submission_history'):
                            analyzer.url_submission_history.clear()
                    st.success("🔄 Security cache cleared! Fresh API calls will be made.")
                    st.rerun()
                else:
                    st.info("No security cache to clear")
            
            if st.button("�📁 Open Reports Folder", help="Open reports directory"):
                reports_path = Path("reports").resolve()
                st.info(f"Reports saved to: {reports_path}")
    
    def render_configuration_page(self):
        """Render the configuration setup page."""
        st.title("⚙️ Initial Configuration")
        st.info("Please configure the application before proceeding with email analysis.")
        
        with st.form("config_form"):
            st.subheader("OpenAI Configuration")
            api_key = st.text_input(
                "OpenAI API Key",
                type="password",
                help="Enter your OpenAI API key for AI analysis"
            )
            
            model = st.selectbox(
                "AI Model",
                ["gpt-4o-mini", "gpt-4o", "gpt-5", "gpt-3.5-turbo"],
                help="Select the OpenAI model to use for analysis"
            )
            
            st.subheader("Report Settings")
            company_name = st.text_input(
                "Organization Name",
                value="Security Analysis Team",
                help="Your organization name for reports"
            )
            
            col1, col2 = st.columns(2)
            with col1:
                default_format = st.selectbox("Default Report Format", ["pdf", "html"])
            with col2:
                include_technical = st.checkbox("Include Technical Details", value=True)
            
            submitted = st.form_submit_button("Save Configuration")
            
            if submitted and api_key:
                # Update configuration
                self.config_manager.set('openai_api_key', api_key)
                self.config_manager.set('ai_settings.model', model)
                self.config_manager.set('report_settings.company_name', company_name)
                self.config_manager.set('report_settings.default_format', default_format)
                self.config_manager.set('report_settings.include_technical_details', include_technical)
                
                # Save configuration
                if self.config_manager.save_config():
                    st.success("✅ Configuration saved successfully!")
                    st.info("Please refresh the page to continue.")
                else:
                    st.error("❌ Failed to save configuration")
            elif submitted:
                st.error("Please enter your OpenAI API key")
    
    def render_analysis_page(self):
        """Render the main email analysis page."""
        st.title("🔍 Email Security Analysis")
        
        # Enhanced input section with better styling
        st.markdown("""
        <div style="background: linear-gradient(90deg, #f8f9fa 0%, #e9ecef 100%); 
                    padding: 20px; border-radius: 10px; margin: 15px 0; border-left: 5px solid #007bff;">
            <h3 style="color: #495057; margin-top: 0;">📧 Step 1: Provide Email Content</h3>
            <p style="color: #6c757d; margin-bottom: 0;">
                Choose your preferred method to input the email you want to analyze
            </p>
        </div>
        """, unsafe_allow_html=True)
        
        input_method = st.radio(
            "Choose input method:",
            ["📝 Paste Headers", "📄 Upload File"],
            horizontal=True
        )
        
        email_content = ""
        
        if input_method == "📝 Paste Headers":
            st.markdown("**Email Headers or Content:**")
            email_content = st.text_area(
                "Email Headers",
                height=200,
                placeholder="Paste email headers or full email content here...\n\nExample:\nFrom: sender@example.com\nTo: recipient@company.com\nSubject: Important Message\nReceived: from mail.example.com...\n\nOr paste the entire email including body content for comprehensive analysis.",
                label_visibility="collapsed"
            )
            
            if email_content:
                # Show a preview of what was entered
                st.markdown(f"""
                <div style="background: #e8f5e8; padding: 10px; border-radius: 5px; border-left: 3px solid #28a745;">
                    <small><strong>✅ Content loaded:</strong> {len(email_content)} characters, {len(email_content.splitlines())} lines</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("**Upload Email File:**")
            uploaded_file = st.file_uploader(
                "Upload Email File",
                type=['eml', 'txt', 'msg'],
                help="Upload an email file or text file containing headers"
            )
            
            if uploaded_file:
                try:
                    email_content = uploaded_file.read().decode('utf-8')
                    st.success(f"✅ File uploaded: {uploaded_file.name}")
                except Exception as e:
                    st.error(f"❌ Error reading file: {str(e)}")
        
        # Analysis button with improved UI
        st.markdown("---")  # Add a separator line
        
        # Create a more visually appealing button area
        button_col1, button_col2, button_col3 = st.columns([1, 3, 1])
        
        with button_col2:
            # Check if content is available
            has_content = bool(email_content.strip())
            
            if has_content:
                # Create an eye-catching analyze button
                if st.button(
                    "🔍 **ANALYZE EMAIL**",
                    type="primary",
                    use_container_width=True,
                    help="Click to start comprehensive email security analysis"
                ):
                    analyze_button = True
                else:
                    analyze_button = False
                
                # Add status indicator below button
                st.markdown("""
                <div style="text-align: center; margin-top: 10px; color: #28a745; font-size: 14px;">
                    ✅ Ready for analysis
                </div>
                """, unsafe_allow_html=True)
                
            else:
                # Disabled state with helpful message
                st.button(
                    "📝 Enter Email Content First",
                    disabled=True,
                    use_container_width=True,
                    help="Please paste email headers or upload a file before analyzing"
                )
                
                # Add guidance message
                st.markdown("""
                <div style="text-align: center; margin-top: 10px; color: #6c757d; font-size: 14px;">
                    ℹ️ Paste email headers above or upload a file to begin
                </div>
                """, unsafe_allow_html=True)
                
                analyze_button = False
        
        # Analysis progress and features preview
        if has_content and not analyze_button:
            st.markdown("---")
            
            # Show what the analysis will include
            st.markdown("""
            <div style="background: linear-gradient(90deg, #e3f2fd 0%, #f3e5f5 100%); 
                        padding: 20px; border-radius: 10px; margin: 20px 0;">
                <h4 style="text-align: center; margin-bottom: 15px; color: #1565c0;">
                    🎯 Comprehensive Analysis Features
                </h4>
                <div style="display: flex; flex-wrap: wrap; justify-content: space-around; gap: 15px;">
                    <div style="text-align: center; min-width: 150px;">
                        <div style="font-size: 24px; margin-bottom: 5px;">🤖</div>
                        <strong>AI Analysis</strong><br>
                        <small>GPT-powered phishing detection</small>
                    </div>
                    <div style="text-align: center; min-width: 150px;">
                        <div style="font-size: 24px; margin-bottom: 5px;">🔗</div>
                        <strong>URL Scanning</strong><br>
                        <small>VirusTotal security checks</small>
                    </div>
                    <div style="text-align: center; min-width: 150px;">
                        <div style="font-size: 24px; margin-bottom: 5px;">🌐</div>
                        <strong>IP Reputation</strong><br>
                        <small>AbuseIPDB threat analysis</small>
                    </div>
                    <div style="text-align: center; min-width: 150px;">
                        <div style="font-size: 24px; margin-bottom: 5px;">🔒</div>
                        <strong>SafeLinks</strong><br>
                        <small>Microsoft URL unwrapping</small>
                    </div>
                    <div style="text-align: center; min-width: 150px;">
                        <div style="font-size: 24px; margin-bottom: 5px;">📊</div>
                        <strong>Risk Scoring</strong><br>
                        <small>Confidence-based assessment</small>
                    </div>
                    <div style="text-align: center; min-width: 150px;">
                        <div style="font-size: 24px; margin-bottom: 5px;">📄</div>
                        <strong>Reports</strong><br>
                        <small>PDF & HTML generation</small>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # Perform analysis
        if analyze_button and email_content.strip():
            # Create a more engaging progress display
            progress_container = st.container()
            
            with progress_container:
                # Analysis header
                st.markdown("""
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                            padding: 20px; border-radius: 15px; color: white; text-align: center; margin: 20px 0;">
                    <h2 style="margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">
                        🔍 Email Security Analysis in Progress
                    </h2>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">
                        Analyzing your email with advanced AI and security databases...
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                # Progress steps
                progress_col1, progress_col2, progress_col3, progress_col4 = st.columns(4)
                
                with progress_col1:
                    st.markdown("**🔄 Step 1:** Parsing Email Headers", unsafe_allow_html=True)
                    step1_placeholder = st.empty()
                
                with progress_col2:
                    st.markdown("**🔍 Step 2:** Security Analysis", unsafe_allow_html=True) 
                    step2_placeholder = st.empty()
                
                with progress_col3:
                    st.markdown("**🤖 Step 3:** AI Analysis", unsafe_allow_html=True)
                    step3_placeholder = st.empty()
                
                with progress_col4:
                    st.markdown("**📊 Step 4:** Generating Results", unsafe_allow_html=True)
                    step4_placeholder = st.empty()
            
            try:
                # Step 1: Parse email headers
                step1_placeholder.success("✅ Complete")
                
                # Initialize security analyzer if enabled
                security_analyzer = None
                if self.config_manager.is_security_analysis_enabled():
                    vt_key = self.config_manager.get_virustotal_api_key()
                    abuse_key = self.config_manager.get_abuseipdb_api_key()

                    if vt_key or abuse_key:  # Only create if at least one API key is available
                        cache_bucket = st.session_state.setdefault('security_analyzer_cache', {})
                        vt_digest = hashlib.sha256(vt_key.encode()).hexdigest() if vt_key else "no-vt"
                        abuse_digest = hashlib.sha256(abuse_key.encode()).hexdigest() if abuse_key else "no-abuse"
                        cache_key = f"{vt_digest}:{abuse_digest}"

                        security_analyzer = cache_bucket.get(cache_key)
                        if security_analyzer is None:
                            security_analyzer = SecurityAnalyzer(
                                virustotal_api_key=vt_key if vt_key else None,
                                abuseipdb_api_key=abuse_key if abuse_key else None
                            )
                            cache_bucket[cache_key] = security_analyzer
                
                # Parse email headers
                parser = EmailHeaderParser(security_analyzer=security_analyzer)
                parsed_data = parser.parse_headers(email_content)
                
                if 'error' in parsed_data:
                    step1_placeholder.error("❌ Error")
                    st.error(f"❌ Parsing error: {parsed_data['error']}")
                    return
                
                # Step 2: Security analysis
                step2_placeholder.success("✅ Complete")
                
                # Step 3: AI analysis
                step3_placeholder.info("🔄 Processing...")
                openai_config = self.config_manager.get_openai_config()
                dataset_path = self.config_manager.get_dataset_path()
                
                analyzer = AIPhishingAnalyzer(
                    api_key=openai_config['api_key'],
                    model=openai_config['model'],
                    dataset_path=dataset_path
                )
                
                analysis_result = analyzer.analyze_email_headers(parsed_data)
                step3_placeholder.success("✅ Complete")
                
                # Step 4: Generate results
                step4_placeholder.info("🔄 Finalizing...")
                
                # Save to session state and history
                st.session_state.analysis_result = analysis_result
                self.history_manager.save_analysis(analysis_result)
                
                step4_placeholder.success("✅ Complete")
                
                # Success message
                st.markdown("""
                <div style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); 
                            padding: 20px; border-radius: 15px; color: white; text-align: center; margin: 20px 0;">
                    <h3 style="margin: 0; text-shadow: 0 2px 4px rgba(0,0,0,0.3);">
                        🎉 Analysis Complete!
                    </h3>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">
                        Your email has been thoroughly analyzed. Results are displayed below.
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
            except Exception as e:
                # Update progress indicators with error
                for placeholder in [step1_placeholder, step2_placeholder, step3_placeholder, step4_placeholder]:
                    try:
                        placeholder.error("❌ Error")
                    except:
                        pass
                
                st.error(f"❌ Analysis failed: {str(e)}")
                self.logger.error(f"Analysis error: {e}")
        
        # Display results
        if st.session_state.analysis_result:
            self.render_analysis_results(st.session_state.analysis_result)
    
    def render_analysis_results(self, analysis_result):
        """Render the analysis results."""
        st.subheader("📊 Analysis Results")
        
        final_assessment = analysis_result.get('final_assessment', {})
        ai_analysis = analysis_result.get('ai_analysis', {})
        email_data = analysis_result.get('email_data', {})
        
        # Risk level indicator
        risk_level = final_assessment.get('risk_level', 'unknown')
        confidence_score = final_assessment.get('confidence_score', 0)
        
        risk_class = f"risk-{risk_level}"
        st.markdown(f"""
        <div class="{risk_class}">
            🚨 RISK LEVEL: {risk_level.upper()} | CONFIDENCE: {confidence_score}%
        </div>
        """, unsafe_allow_html=True)
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Confidence Score",
                f"{confidence_score}%",
                delta=None,
                help="AI confidence in phishing detection"
            )
        
        with col2:
            st.metric(
                "Risk Level",
                risk_level.title(),
                delta=None,
                help="Overall risk classification"
            )
        
        with col3:
            phishing_status = "YES" if final_assessment.get('is_likely_phishing', False) else "NO"
            st.metric(
                "Likely Phishing",
                phishing_status,
                delta=None,
                help="Is this email likely a phishing attempt?"
            )
        
        with col4:
            st.metric(
                "Indicators Found",
                final_assessment.get('total_indicators', 0),
                delta=None,
                help="Number of suspicious indicators detected"
            )
        
        # Tabs for detailed information
        tab1, tab2, tab3, tab4, tab5 = st.tabs(["📋 Summary", "🔍 Details", "🛡️ Indicators", "🔗 Security Analysis", "📄 Reports"])
        
        with tab1:
            # Executive summary
            st.subheader("Executive Summary")
            summary = ai_analysis.get('summary', 'No summary available.')
            st.markdown(f"<div class='info-card'>{summary}</div>", unsafe_allow_html=True)
            
            # Sender information
            st.subheader("Sender Information")
            sender_info = email_data.get('sender_info', {})
            
            col1, col2 = st.columns(2)
            with col1:
                st.write("**From Address:**", sender_info.get('from_address', 'N/A'))
                st.write("**Display Name:**", sender_info.get('display_name', 'N/A'))
                st.write("**Domain:**", sender_info.get('domain', 'N/A'))
            
            with col2:
                st.write("**Reply-To:**", sender_info.get('reply_to', 'N/A'))
                st.write("**Return-Path:**", sender_info.get('return_path', 'N/A'))
                st.write("**Valid Format:**", "✅" if sender_info.get('is_valid_email', False) else "❌")
        
        with tab2:
            # Detailed analysis
            st.subheader("Detailed Analysis")
            detailed_analysis = ai_analysis.get('detailed_analysis', 'No detailed analysis available.')
            st.markdown(detailed_analysis)
            
            # Authentication results
            st.subheader("Authentication Results")
            auth_info = email_data.get('authentication', {})
            
            auth_df = pd.DataFrame([
                {"Method": "SPF", "Status": auth_info.get('spf', {}).get('status', 'N/A')},
                {"Method": "DKIM", "Status": auth_info.get('dkim', {}).get('status', 'N/A')},
                {"Method": "DMARC", "Status": auth_info.get('dmarc', {}).get('status', 'N/A')},
                {"Method": "Overall", "Status": auth_info.get('overall_auth_status', 'N/A')}
            ])
            
            st.dataframe(auth_df, use_container_width=True)
        
        with tab3:
            # Security indicators
            st.subheader("Security Indicators")
            
            # AI indicators
            ai_indicators = ai_analysis.get('key_indicators', [])
            parsed_indicators = email_data.get('suspicious_indicators', [])
            
            all_indicators = ai_indicators + parsed_indicators
            
            if all_indicators:
                for indicator in all_indicators:
                    severity = indicator.get('severity', 'unknown')
                    icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                    
                    st.markdown(f"""
                    <div class="indicator-card">
                        {icon} <strong>{indicator.get('indicator', indicator.get('type', 'Unknown'))}</strong>
                        <span style="float: right; background: {'#dc3545' if severity == 'high' else '#ffc107' if severity == 'medium' else '#28a745'}; 
                              color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em;">
                            {severity.upper()}
                        </span>
                        <br>
                        {indicator.get('description', 'No description available.')}
                        {f'<br><em>Evidence: {indicator.get("evidence", indicator.get("details", ""))}</em>' if indicator.get('evidence') or indicator.get('details') else ''}
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("<div class='success-card'>✅ No significant security indicators detected.</div>", unsafe_allow_html=True)
        
        with tab4:
            # Security Analysis (URLs & IPs)
            st.subheader("Security Analysis")
            
            security_analysis = email_data.get('security_analysis', {})
            
            if security_analysis and not security_analysis.get('error'):
                # Overall threat level
                threat_level = security_analysis.get('overall_threat_level', 'unknown')
                threat_colors = {
                    'high': '#dc3545',
                    'medium': '#ffc107', 
                    'low': '#28a745',
                    'unknown': '#6c757d'
                }
                
                st.markdown(f"""
                <div style="padding: 15px; border-radius: 8px; background-color: {threat_colors.get(threat_level, '#6c757d')}; 
                            color: white; text-align: center; font-weight: bold; margin-bottom: 20px;">
                    🔍 Overall Threat Level: {threat_level.upper()}
                </div>
                """, unsafe_allow_html=True)
                
                # Security summary
                security_summary = security_analysis.get('security_summary', {})
                
                col1, col2, col3, col4, col5 = st.columns(5)
                
                with col1:
                    st.metric(
                        label="Malicious URLs",
                        value=security_summary.get('malicious_urls', 0),
                        delta="High Risk" if security_summary.get('malicious_urls', 0) > 0 else None,
                        delta_color="inverse"
                    )
                
                with col2:
                    st.metric(
                        label="Suspicious URLs", 
                        value=security_summary.get('suspicious_urls', 0),
                        delta="Medium Risk" if security_summary.get('suspicious_urls', 0) > 0 else None,
                        delta_color="inverse"
                    )
                
                with col3:
                    st.metric(
                        label="Malicious IPs",
                        value=security_summary.get('malicious_ips', 0),
                        delta="High Risk" if security_summary.get('malicious_ips', 0) > 0 else None,
                        delta_color="inverse"
                    )
                
                with col4:
                    st.metric(
                        label="Suspicious IPs",
                        value=security_summary.get('suspicious_ips', 0), 
                        delta="Medium Risk" if security_summary.get('suspicious_ips', 0) > 0 else None,
                        delta_color="inverse"
                    )
                
                with col5:
                    safelinks_count = security_summary.get('safelinks_found', 0)
                    st.metric(
                        label="SafeLinks Found",
                        value=safelinks_count,
                        delta="Detected" if safelinks_count > 0 else None,
                        delta_color="normal"
                    )
                
                # URL Analysis
                url_analysis = security_analysis.get('url_analysis', [])
                if url_analysis:
                    st.subheader("🔗 URL Analysis Results")
                    
                    url_data = []
                    for url_result in url_analysis:
                        status_icon = "🔴" if url_result.get('malicious') else "🟡" if url_result.get('suspicious') else "🟢"
                        cache_indicator = " 💾" if url_result.get('cache_hit') else " 🔄"
                        url_data.append({
                            "Status": status_icon,
                            "URL": url_result.get('url', 'N/A')[:45] + "..." if len(url_result.get('url', '')) > 45 else url_result.get('url', 'N/A'),
                            "VirusTotal": f"{url_result.get('detections', 0)}/{url_result.get('total_scans', 0)}",
                            "Risk": "HIGH" if url_result.get('malicious') else "MEDIUM" if url_result.get('suspicious') else "LOW",
                            "Source": "Cache" + cache_indicator if url_result.get('cache_hit') else "API" + cache_indicator
                        })
                    
                    if url_data:
                        st.dataframe(url_data, use_container_width=True)
                        st.caption("💾 = Cached result, 🔄 = Fresh API call")
                
                # SafeLinks Analysis
                safelinks_analysis = security_analysis.get('safelinks_analysis', [])
                if safelinks_analysis:
                    st.subheader("🔗 Microsoft SafeLinks Analysis")
                    st.info("⚠️ SafeLinks URLs detected - analyzing the actual destination URLs")
                    
                    for safelink_item in safelinks_analysis:
                        original_url = safelink_item.get('original', 'N/A')
                        safelinks_url = safelink_item.get('safelinks', 'N/A')
                        threat_level = safelink_item.get('threat_level', 'unknown')
                        vt_analysis = safelink_item.get('virustotal_analysis', {})
                        
                        # Determine status icon and color
                        if threat_level == 'malicious':
                            status_icon = "🔴"
                            status_color = "#dc3545"
                            risk_text = "HIGH RISK"
                        elif threat_level == 'suspicious':
                            status_icon = "🟡"
                            status_color = "#ffc107"
                            risk_text = "MEDIUM RISK"
                        else:
                            status_icon = "🟢"
                            status_color = "#28a745"
                            risk_text = "LOW RISK"
                        
                        # Display SafeLinks info in an expandable section
                        with st.expander(f"{status_icon} SafeLinks URL Analysis - {risk_text}", expanded=(threat_level in ['malicious', 'suspicious'])):
                            col1, col2 = st.columns([1, 1])
                            
                            with col1:
                                st.write("**SafeLinks Wrapper:**")
                                st.code(safelinks_url[:100] + "..." if len(safelinks_url) > 100 else safelinks_url, language="text")
                                
                            with col2:
                                st.write("**Actual Destination URL (Analyzed):**")
                                st.code(original_url, language="text")
                            
                            # VirusTotal results
                            if vt_analysis and not vt_analysis.get('error'):
                                detections = vt_analysis.get('detections', 0)
                                total_scans = vt_analysis.get('total_scans', 0)
                                
                                col3, col4, col5 = st.columns(3)
                                with col3:
                                    st.metric("VirusTotal Score", f"{detections}/{total_scans}")
                                with col4:
                                    st.metric("Risk Level", risk_text)
                                with col5:
                                    st.metric("Status", f"{status_icon} {threat_level.upper()}")
                            
                            elif vt_analysis and vt_analysis.get('error'):
                                st.warning(f"⚠️ VirusTotal check failed: {vt_analysis.get('error')}")
                            else:
                                st.info("ℹ️ VirusTotal analysis not available")
                
                # IP Analysis
                ip_analysis = security_analysis.get('ip_analysis', [])
                if ip_analysis:
                    st.subheader("🌐 IP Address Analysis Results")
                    
                    for ip_result in ip_analysis:
                        status_icon = "🔴" if ip_result.get('malicious') else "🟡" if ip_result.get('suspicious') else "🟢"
                        risk_level = "HIGH" if ip_result.get('malicious') else "MEDIUM" if ip_result.get('suspicious') else "LOW"
                        cache_status = " 💾 (Cached)" if ip_result.get('cache_hit') else " 🔄 (Fresh API)"
                        
                        # Main IP info
                        col1, col2, col3, col4, col5 = st.columns(5)
                        with col1:
                            st.metric("IP Address", ip_result.get('ip', 'N/A'))
                        with col2:
                            st.metric("Status", f"{status_icon} {risk_level}")
                        with col3:
                            st.metric("Reputation Score", f"{ip_result.get('reputation_score', 0):.1f}/100")
                        with col4:
                            st.metric("Risk Level", risk_level)
                        with col5:
                            st.metric("Data Source", "Cache 💾" if ip_result.get('cache_hit') else "API 🔄")
                        
                        # Detailed source analysis
                        sources = ip_result.get('sources', {})
                        if sources:
                            st.write("**Security Source Details:**")
                            
                            source_cols = st.columns(len(sources))
                            for idx, (source_name, source_data) in enumerate(sources.items()):
                                with source_cols[idx]:
                                    st.write(f"**{source_data.get('service', source_name)}**")
                                    
                                    if source_name == 'abuseipdb' and 'abuse_confidence' in source_data:
                                        st.write(f"• Abuse Confidence: {source_data.get('abuse_confidence', 0)}%")
                                        st.write(f"• Total Reports: {source_data.get('total_reports', 0)}")
                                        st.write(f"• Whitelisted: {'Yes' if source_data.get('is_whitelisted') else 'No'}")
                                        st.write(f"• Country: {source_data.get('country_code', 'Unknown')}")
                                    elif source_name == 'ipqualityscore' and 'fraud_score' in source_data:
                                        st.write(f"• Fraud Score: {source_data.get('fraud_score', 0)}")
                                        st.write(f"• VPN: {'Yes' if source_data.get('vpn') else 'No'}")
                                        st.write(f"• Tor: {'Yes' if source_data.get('tor') else 'No'}")
                                        st.write(f"• Proxy: {'Yes' if source_data.get('proxy') else 'No'}")
                                    elif source_name == 'talos':
                                        st.write(f"• Status: {source_data.get('status', 'Unknown')}")
                                    
                                    if 'error' in source_data:
                                        st.write(f"⚠️ {source_data['error']}")
                        
                        st.divider()
                else:
                    st.info("No IP addresses found for analysis.")
                
                # Display found URLs and IPs
                urls = security_analysis.get('urls', [])
                ips = security_analysis.get('ips', [])
                
                if urls or ips:
                    st.subheader("📋 Extracted URLs and IPs")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if urls:
                            st.write("**URLs Found:**")
                            for url in urls:
                                st.write(f"• {url}")
                        else:
                            st.write("**URLs Found:** None")
                    
                    with col2:
                        if ips:
                            st.write("**IP Addresses Found:**")
                            for ip in ips:
                                st.write(f"• {ip}")
                        else:
                            st.write("**IP Addresses Found:** None")
            
            elif security_analysis and security_analysis.get('error'):
                st.warning(f"⚠️ Security analysis failed: {security_analysis.get('error')}")
                st.info("💡 This may be due to missing API keys. Configure VirusTotal and/or AbuseIPDB API keys in Settings for full security analysis.")
            
            else:
                st.info("🔧 Security analysis not performed. Enable and configure API keys in Settings to analyze URLs and IP addresses.")
        
        with tab5:
            # Report generation
            st.subheader("Generate Reports")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("📄 Generate PDF Report", type="primary", use_container_width=True):
                    with st.spinner("Generating PDF report..."):
                        try:
                            report_settings = self.config_manager.get_report_settings()
                            pdf_path = self.report_generator.generate_pdf_report(
                                analysis_result,
                                report_settings.get('company_name', 'Security Team')
                            )
                            st.success(f"✅ PDF report generated: {Path(pdf_path).name}")
                            
                            # Provide download link
                            with open(pdf_path, 'rb') as f:
                                st.download_button(
                                    "⬇️ Download PDF",
                                    f,
                                    file_name=Path(pdf_path).name,
                                    mime='application/pdf'
                                )
                        except Exception as e:
                            st.error(f"❌ Failed to generate PDF: {str(e)}")
            
            with col2:
                if st.button("🌐 Generate HTML Report", type="secondary", use_container_width=True):
                    with st.spinner("Generating HTML report..."):
                        try:
                            report_settings = self.config_manager.get_report_settings()
                            html_path = self.report_generator.generate_html_report(
                                analysis_result,
                                report_settings.get('company_name', 'Security Team')
                            )
                            st.success(f"✅ HTML report generated: {Path(html_path).name}")
                            
                            # Provide download link
                            with open(html_path, 'r', encoding='utf-8') as f:
                                st.download_button(
                                    "⬇️ Download HTML",
                                    f,
                                    file_name=Path(html_path).name,
                                    mime='text/html'
                                )
                        except Exception as e:
                            st.error(f"❌ Failed to generate HTML: {str(e)}")
            
            # Recommendations
            st.subheader("Recommendations")
            recommendations = analysis_result.get('recommendations', [])
            if not recommendations:
                recommendations = ai_analysis.get('recommendations', [])
            
            if recommendations:
                for i, rec in enumerate(recommendations, 1):
                    st.write(f"{i}. {rec}")
            else:
                st.info("No specific recommendations available.")
    
    def render_dashboard_page(self):
        """Render the analytics dashboard."""
        st.title("📊 Analytics Dashboard")
        
        try:
            stats = self.history_manager.get_statistics()
            history = self.history_manager.get_history(limit=100)
            
            if not history:
                st.info("No analysis data available yet. Perform some email analyses to see statistics.")
                return
            
            # Key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Total Analyses", stats['total_analyses'])
            with col2:
                st.metric("Phishing Detected", stats['phishing_detected'])
            with col3:
                st.metric("Clean Emails", stats['clean_emails'])
            with col4:
                st.metric("Average Confidence", f"{stats['average_confidence']}%")
            
            # Charts
            col1, col2 = st.columns(2)
            
            with col1:
                # Risk level distribution
                st.subheader("Risk Level Distribution")
                risk_data = stats['risk_distribution']
                
                if sum(risk_data.values()) > 0:
                    if PLOTLY_AVAILABLE:
                        fig_pie = px.pie(
                            values=list(risk_data.values()),
                            names=list(risk_data.keys()),
                            color_discrete_map={
                                'low': '#28a745',
                                'medium': '#ffc107',
                                'high': '#fd7e14',
                                'critical': '#dc3545'
                            }
                        )
                        st.plotly_chart(fig_pie, use_container_width=True)
                    else:
                        # Fallback to simple bar chart
                        st.bar_chart(risk_data)
                else:
                    st.info("No data available for chart")
            
            with col2:
                # Confidence score distribution
                st.subheader("Confidence Score Distribution")
                confidence_scores = [entry.get('confidence_score', 0) for entry in history]
                
                if confidence_scores:
                    if PLOTLY_AVAILABLE:
                        fig_hist = px.histogram(
                            x=confidence_scores,
                            nbins=20,
                            title="Distribution of Confidence Scores"
                        )
                        fig_hist.update_layout(
                            xaxis_title="Confidence Score (%)",
                            yaxis_title="Number of Analyses"
                        )
                        st.plotly_chart(fig_hist, use_container_width=True)
                    else:
                        # Fallback to simple histogram
                        hist_df = pd.DataFrame({'Confidence Score': confidence_scores})
                        st.bar_chart(hist_df['Confidence Score'].value_counts().sort_index())
                else:
                    st.info("No data available for chart")
            
            # Timeline analysis
            st.subheader("Analysis Timeline")
            if len(history) > 1:
                # Convert timestamps and create timeline
                timeline_data = []
                for entry in history:
                    try:
                        timestamp = datetime.fromisoformat(entry.get('timestamp', '').replace('Z', '+00:00'))
                        timeline_data.append({
                            'date': timestamp.date(),
                            'confidence': entry.get('confidence_score', 0),
                            'is_phishing': entry.get('is_likely_phishing', False)
                        })
                    except ValueError:
                        continue
                
                if timeline_data:
                    df_timeline = pd.DataFrame(timeline_data)
                    
                    # Group by date and calculate daily statistics
                    daily_stats = df_timeline.groupby('date').agg({
                        'confidence': 'mean',
                        'is_phishing': 'sum'
                    }).reset_index()
                    daily_stats['total_analyses'] = df_timeline.groupby('date').size().values
                    
                    if PLOTLY_AVAILABLE:
                        fig_timeline = go.Figure()
                        
                        # Add confidence score line
                        fig_timeline.add_trace(go.Scatter(
                            x=daily_stats['date'],
                            y=daily_stats['confidence'],
                            mode='lines+markers',
                            name='Avg Confidence Score',
                            line=dict(color='blue', width=2)
                        ))
                        
                        # Add phishing detection bars
                        fig_timeline.add_trace(go.Bar(
                            x=daily_stats['date'],
                            y=daily_stats['is_phishing'],
                            name='Phishing Detected',
                            yaxis='y2',
                            opacity=0.7,
                            marker_color='red'
                        ))
                        
                        fig_timeline.update_layout(
                            title="Daily Analysis Trends",
                            xaxis_title="Date",
                            yaxis=dict(title="Confidence Score (%)", side="left"),
                            yaxis2=dict(title="Phishing Count", side="right", overlaying="y"),
                            hovermode="x unified"
                        )
                        
                        st.plotly_chart(fig_timeline, use_container_width=True)
                    else:
                        # Fallback to simple charts
                        col1, col2 = st.columns(2)
                        with col1:
                            st.subheader("Daily Confidence Scores")
                            chart_data = daily_stats.set_index('date')['confidence']
                            st.line_chart(chart_data)
                        
                        with col2:
                            st.subheader("Daily Phishing Detections")
                            chart_data = daily_stats.set_index('date')['is_phishing']
                            st.bar_chart(chart_data)
                else:
                    st.info("Insufficient data for timeline analysis")
            else:
                st.info("Need more data points for timeline analysis")
                
        except Exception as e:
            st.error(f"Error loading dashboard data: {str(e)}")
    
    def render_history_page(self):
        """Render the analysis history page."""
        st.title("📋 Analysis History")
        
        try:
            history = self.history_manager.get_history()
            
            if not history:
                st.info("No analysis history available.")
                return
            
            # Controls
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                search_term = st.text_input("🔍 Search by sender email", placeholder="Enter email address...")
            
            with col2:
                risk_filter = st.selectbox("Filter by risk", ["All", "Critical", "High", "Medium", "Low"])
            
            with col3:
                limit = st.selectbox("Show entries", [10, 25, 50, 100], index=1)
            
            # Filter history
            filtered_history = history[:limit]
            
            if search_term:
                filtered_history = [
                    entry for entry in filtered_history 
                    if search_term.lower() in entry.get('sender', '').lower()
                ]
            
            if risk_filter != "All":
                filtered_history = [
                    entry for entry in filtered_history
                    if entry.get('risk_level', '').lower() == risk_filter.lower()
                ]
            
            # Display history
            st.subheader(f"Recent Analyses ({len(filtered_history)} entries)")
            
            for entry in filtered_history:
                with st.expander(
                    f"📧 {entry.get('sender', 'Unknown')} - "
                    f"{entry.get('risk_level', 'unknown').upper()} "
                    f"({entry.get('confidence_score', 0)}%)"
                ):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.write("**Timestamp:**", entry.get('timestamp', 'N/A'))
                        st.write("**Summary:**", entry.get('summary', 'N/A'))
                        st.write("**Phishing:**", "✅ Yes" if entry.get('is_likely_phishing', False) else "❌ No")
                    
                    with col2:
                        if st.button(f"View Details", key=f"view_{entry.get('id')}"):
                            full_result = self.history_manager.get_analysis(entry.get('id'))
                            if full_result:
                                st.session_state.analysis_result = full_result
                                st.rerun()
                        
                        if st.button(f"Delete", key=f"delete_{entry.get('id')}", type="secondary"):
                            if self.history_manager.delete_analysis(entry.get('id')):
                                st.success("Entry deleted")
                                st.rerun()
            
            # Cleanup option
            st.subheader("🧹 Cleanup")
            col1, col2 = st.columns(2)
            
            with col1:
                cleanup_days = st.number_input("Delete entries older than (days):", min_value=1, value=30)
            
            with col2:
                if st.button("Delete Old Entries", type="secondary"):
                    deleted_count = self.history_manager.cleanup_old_entries(cleanup_days)
                    if deleted_count > 0:
                        st.success(f"Deleted {deleted_count} old entries")
                    else:
                        st.info("No old entries to delete")
                        
        except Exception as e:
            st.error(f"Error loading history: {str(e)}")
    
    def render_settings_page(self):
        """Render the settings page."""
        st.title("⚙️ Settings")
        
        # OpenAI Settings
        st.subheader("🤖 AI Configuration")
        
        with st.form("ai_settings"):
            current_model = self.config_manager.get('ai_settings.model', 'gpt-4o-mini')
            model_options = ["gpt-4o-mini", "gpt-4o", "gpt-5", "gpt-3.5-turbo"]
            model = st.selectbox(
                "AI Model",
                model_options,
                index=model_options.index(current_model) if current_model in model_options else 0
            )
            
            temperature = st.slider(
                "Temperature",
                0.0, 2.0,
                self.config_manager.get('ai_settings.temperature', 0.1),
                0.1,
                help="Lower values make the output more focused and deterministic"
            )
            
            max_tokens = st.number_input(
                "Max Tokens",
                100, 4000,
                self.config_manager.get('ai_settings.max_tokens', 2000),
                help="Maximum number of tokens for AI response"
            )
            
            if st.form_submit_button("Save AI Settings"):
                self.config_manager.set('ai_settings.model', model)
                self.config_manager.set('ai_settings.temperature', temperature)
                self.config_manager.set('ai_settings.max_tokens', max_tokens)
                
                if self.config_manager.save_config():
                    st.success("✅ AI settings saved")
                else:
                    st.error("❌ Failed to save settings")
        
        # Report Settings
        st.subheader("📄 Report Configuration")
        
        with st.form("report_settings"):
            company_name = st.text_input(
                "Organization Name",
                self.config_manager.get('report_settings.company_name', 'Security Team')
            )
            
            default_format = st.selectbox(
                "Default Format",
                ["pdf", "html"],
                index=0 if self.config_manager.get('report_settings.default_format', 'pdf') == 'pdf' else 1
            )
            
            include_technical = st.checkbox(
                "Include Technical Details",
                self.config_manager.get('report_settings.include_technical_details', True)
            )
            
            if st.form_submit_button("Save Report Settings"):
                self.config_manager.set('report_settings.company_name', company_name)
                self.config_manager.set('report_settings.default_format', default_format)
                self.config_manager.set('report_settings.include_technical_details', include_technical)
                
                if self.config_manager.save_config():
                    st.success("✅ Report settings saved")
                else:
                    st.error("❌ Failed to save settings")
        
        # Security API Settings
        st.subheader("🔐 Security API Configuration")
        
        with st.form("security_api_settings"):
            st.markdown("Configure API keys for enhanced security analysis of URLs and IP addresses.")
            
            # Security analysis enabled toggle
            security_enabled = st.checkbox(
                "Enable Security Analysis",
                self.config_manager.is_security_analysis_enabled(),
                help="Enable URL and IP reputation checking"
            )
            
            # VirusTotal API key
            vt_api_key = st.text_input(
                "VirusTotal API Key",
                value=self.config_manager.get_virustotal_api_key(),
                type="password",
                help="Get your free API key from https://www.virustotal.com/gui/join-us"
            )
            
            # AbuseIPDB API key
            abuse_api_key = st.text_input(
                "AbuseIPDB API Key", 
                value=self.config_manager.get_abuseipdb_api_key(),
                type="password",
                help="Get your free API key from https://www.abuseipdb.com/"
            )
            
            st.info("📝 **Note:** API keys are optional but enable enhanced security analysis. "
                   "VirusTotal checks URLs for malicious content, and AbuseIPDB checks IP reputation.")
            
            if st.form_submit_button("Save Security Settings"):
                self.config_manager.set('security_api_keys.security_analysis_enabled', security_enabled)
                self.config_manager.set('security_api_keys.virustotal_api_key', vt_api_key)
                self.config_manager.set('security_api_keys.abuseipdb_api_key', abuse_api_key)
                
                if self.config_manager.save_config():
                    st.success("✅ Security settings saved")
                else:
                    st.error("❌ Failed to save settings")
        
        # Confidence Thresholds
        st.subheader("🎯 Confidence Thresholds")
        
        with st.form("threshold_settings"):
            thresholds = self.config_manager.get_confidence_thresholds()
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                low_threshold = st.number_input("Low Risk Threshold", 0, 100, thresholds['low'])
            with col2:
                medium_threshold = st.number_input("Medium Risk Threshold", 0, 100, thresholds['medium'])
            with col3:
                high_threshold = st.number_input("High Risk Threshold", 0, 100, thresholds['high'])
            
            if st.form_submit_button("Save Thresholds"):
                self.config_manager.set('confidence_thresholds.low', low_threshold)
                self.config_manager.set('confidence_thresholds.medium', medium_threshold)
                self.config_manager.set('confidence_thresholds.high', high_threshold)
                
                if self.config_manager.save_config():
                    st.success("✅ Thresholds saved")
                else:
                    st.error("❌ Failed to save thresholds")
        
        # System Info
        st.subheader("ℹ️ System Information")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.info("**Configuration Status**")
            st.write("✅ OpenAI API:" if self.config_manager.is_configured() else "❌ OpenAI API:", 
                    "Configured" if self.config_manager.is_configured() else "Not configured")
            
            # Security API status
            vt_configured = bool(self.config_manager.get_virustotal_api_key())
            abuse_configured = bool(self.config_manager.get_abuseipdb_api_key())
            security_enabled = self.config_manager.is_security_analysis_enabled()
            
            st.write("🔍 Security Analysis:", 
                    "Enabled" if security_enabled else "Disabled")
            st.write("🦠 VirusTotal API:", 
                    "✅ Configured" if vt_configured else "❌ Not configured")
            st.write("🛡️ AbuseIPDB API:", 
                    "✅ Configured" if abuse_configured else "❌ Not configured")
            
            st.write("📁 Reports Directory:", Path("reports").resolve())
            st.write("💾 Data Directory:", Path("data").resolve())
        
        with col2:
            st.info("**Application Info**")
            st.write("🔧 Version:", "1.0.0")
            st.write("🐍 Python:", sys.version.split()[0])
            st.write("🚀 Streamlit:", st.__version__)
        
        # Test Connection
        if st.button("🔌 Test OpenAI Connection"):
            if self.config_manager.is_configured():
                try:
                    with st.spinner("Testing connection..."):
                        openai_config = self.config_manager.get_openai_config()
                        dataset_path = self.config_manager.get_dataset_path()
                        analyzer = AIPhishingAnalyzer(
                            api_key=openai_config['api_key'],
                            model=openai_config['model'],
                            dataset_path=dataset_path
                        )
                        
                        if analyzer.test_connection():
                            st.success("✅ OpenAI connection successful!")
                        else:
                            st.error("❌ OpenAI connection failed!")
                except Exception as e:
                    st.error(f"❌ Connection test failed: {str(e)}")
            else:
                st.error("❌ OpenAI API key not configured")


def main():
    """Main entry point for the Streamlit application."""
    app = PhishingDetectorApp()
    app.run()


if __name__ == "__main__":
    main()