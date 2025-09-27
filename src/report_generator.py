"""
Report Generation Module

This module provides functionality to generate professional reports
from email analysis results in various formats (PDF, HTML).
"""

import os
import io
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import Color, black, red, orange, yellow, green
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY


class ReportGenerator:
    """Generate professional analysis reports in various formats."""
    
    def __init__(self, report_dir: str = "reports"):
        """
        Initialize report generator.
        
        Args:
            report_dir: Directory to save generated reports
        """
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        # Risk level colors
        self.risk_colors = {
            'low': Color(0.2, 0.8, 0.2),      # Green
            'medium': Color(1.0, 0.8, 0.2),   # Yellow
            'high': Color(1.0, 0.5, 0.2),     # Orange
            'critical': Color(1.0, 0.2, 0.2)  # Red
        }
    
    def _setup_custom_styles(self):
        """Set up custom paragraph styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=20,
            textColor=Color(0.1, 0.1, 0.4),
            alignment=TA_CENTER
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=Color(0.2, 0.2, 0.6),
            borderWidth=1,
            borderColor=Color(0.2, 0.2, 0.6),
            borderPadding=5
        ))
        
        # Subsection header style
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            textColor=Color(0.3, 0.3, 0.7)
        ))
        
        # Risk assessment style
        self.styles.add(ParagraphStyle(
            name='RiskAssessment',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceAfter=10,
            borderWidth=2,
            borderPadding=10
        ))
        
        # Technical details style
        self.styles.add(ParagraphStyle(
            name='TechnicalDetails',
            parent=self.styles['Normal'],
            fontSize=10,
            fontName='Courier',
            leftIndent=20,
            spaceAfter=6
        ))
    
    def generate_pdf_report(self, analysis_result: Dict, company_name: str = "Security Analysis Team") -> str:
        """
        Generate a comprehensive PDF report.
        
        Args:
            analysis_result: Complete analysis result dictionary
            company_name: Name of the organization
            
        Returns:
            Path to the generated PDF file
        """
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sender = self._safe_filename(analysis_result.get('email_data', {}).get('sender_info', {}).get('from_address', 'unknown'))
        filename = f"phishing_analysis_{sender}_{timestamp}.pdf"
        filepath = self.report_dir / filename
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Build report content
        story = self._build_pdf_content(analysis_result, company_name)
        
        # Generate PDF
        doc.build(story)
        
        return str(filepath)
    
    def _build_pdf_content(self, analysis_result: Dict, company_name: str) -> List:
        """Build the content for PDF report."""
        story = []
        
        # Title page
        story.extend(self._create_title_page(analysis_result, company_name))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(analysis_result))
        story.append(Spacer(1, 20))
        
        # Risk assessment
        story.extend(self._create_risk_assessment(analysis_result))
        story.append(Spacer(1, 20))
        
        # Detailed analysis
        story.extend(self._create_detailed_analysis(analysis_result))
        story.append(Spacer(1, 20))
        
        # Security analysis (URLs and IPs)
        story.extend(self._create_security_analysis(analysis_result))
        story.append(Spacer(1, 20))
        
        # Technical details
        story.extend(self._create_technical_details(analysis_result))
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.extend(self._create_recommendations(analysis_result))
        story.append(Spacer(1, 20))
        
        # Appendix
        story.extend(self._create_appendix(analysis_result))
        
        return story
    
    def _create_title_page(self, analysis_result: Dict, company_name: str) -> List:
        """Create the title page content."""
        content = []
        
        # Title
        content.append(Paragraph("Email Security Analysis Report", self.styles['CustomTitle']))
        content.append(Spacer(1, 40))
        
        # Analysis info table
        email_data = analysis_result.get('email_data', {})
        sender_info = email_data.get('sender_info', {})
        final_assessment = analysis_result.get('final_assessment', {})
        
        info_data = [
            ['Analysis Date:', datetime.now().strftime("%B %d, %Y at %H:%M")],
            ['Analyzed By:', company_name],
            ['Email From:', sender_info.get('from_address', 'N/A')],
            ['Risk Level:', final_assessment.get('risk_level', 'unknown').upper()],
            ['Confidence Score:', f"{final_assessment.get('confidence_score', 0)}%"],
            ['Phishing Likelihood:', 'HIGH' if final_assessment.get('is_likely_phishing', False) else 'LOW']
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 3*inch])
        info_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [Color(0.95, 0.95, 0.95), None])
        ]))
        
        content.append(info_table)
        content.append(Spacer(1, 40))
        
        # Risk indicator
        risk_level = final_assessment.get('risk_level', 'unknown')
        risk_color = self.risk_colors.get(risk_level, black)
        
        risk_style = ParagraphStyle(
            name='RiskIndicator',
            parent=self.styles['Normal'],
            fontSize=18,
            textColor=risk_color,
            alignment=TA_CENTER,
            borderWidth=3,
            borderColor=risk_color,
            borderPadding=15
        )
        
        content.append(Paragraph(f"RISK LEVEL: {risk_level.upper()}", risk_style))
        
        return content
    
    def _create_executive_summary(self, analysis_result: Dict) -> List:
        """Create executive summary section."""
        content = []
        
        content.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        ai_analysis = analysis_result.get('ai_analysis', {})
        final_assessment = analysis_result.get('final_assessment', {})
        
        summary_text = ai_analysis.get('summary', 'No summary available.')
        content.append(Paragraph(summary_text, self.styles['Normal']))
        content.append(Spacer(1, 12))
        
        # Key findings
        content.append(Paragraph("Key Findings:", self.styles['SubsectionHeader']))
        
        findings = [
            f"Confidence Score: {final_assessment.get('confidence_score', 0)}%",
            f"Risk Classification: {final_assessment.get('risk_level', 'unknown').title()}",
            f"Phishing Likelihood: {'High' if final_assessment.get('is_likely_phishing', False) else 'Low'}",
            f"Suspicious Indicators: {final_assessment.get('total_indicators', 0)} detected"
        ]
        
        for finding in findings:
            content.append(Paragraph(f"• {finding}", self.styles['Normal']))
        
        return content
    
    def _create_risk_assessment(self, analysis_result: Dict) -> List:
        """Create risk assessment section."""
        content = []
        
        content.append(Paragraph("Risk Assessment", self.styles['SectionHeader']))
        
        final_assessment = analysis_result.get('final_assessment', {})
        confidence_score = final_assessment.get('confidence_score', 0)
        risk_level = final_assessment.get('risk_level', 'unknown')
        
        # Risk level explanation
        risk_explanations = {
            'low': 'The email shows minimal signs of phishing activity. Standard email security measures should be sufficient.',
            'medium': 'The email contains some suspicious indicators that warrant caution and additional verification.',
            'high': 'The email exhibits multiple phishing characteristics and should be treated as potentially malicious.',
            'critical': 'The email displays strong indicators of phishing activity and should be considered dangerous.'
        }
        
        explanation = risk_explanations.get(risk_level, 'Risk level could not be determined.')
        
        risk_style = ParagraphStyle(
            name='RiskExplanation',
            parent=self.styles['Normal'],
            borderWidth=2,
            borderColor=self.risk_colors.get(risk_level, black),
            borderPadding=10,
            backColor=Color(0.98, 0.98, 0.98)
        )
        
        content.append(Paragraph(explanation, risk_style))
        content.append(Spacer(1, 12))
        
        # Confidence breakdown
        confidence_factors = analysis_result.get('email_data', {}).get('confidence_factors', {})
        if confidence_factors:
            content.append(Paragraph("Confidence Factors:", self.styles['SubsectionHeader']))
            
            factor_data = [['Factor', 'Score', 'Assessment']]
            for factor, score in confidence_factors.items():
                if factor != 'overall_risk_score':
                    assessment = 'Good' if score >= 70 else 'Poor' if score < 40 else 'Fair'
                    factor_data.append([factor.replace('_', ' ').title(), f"{score}/100", assessment])
            
            factor_table = Table(factor_data, colWidths=[2.5*inch, 1*inch, 1*inch])
            factor_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), Color(0.7, 0.7, 0.7)),
                ('TEXTCOLOR', (0, 0), (-1, 0), black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, black)
            ]))
            
            content.append(factor_table)
        
        return content
    
    def _create_detailed_analysis(self, analysis_result: Dict) -> List:
        """Create detailed analysis section."""
        content = []
        
        content.append(Paragraph("Detailed Analysis", self.styles['SectionHeader']))
        
        ai_analysis = analysis_result.get('ai_analysis', {})
        detailed_analysis = ai_analysis.get('detailed_analysis', 'No detailed analysis available.')
        
        content.append(Paragraph(detailed_analysis, self.styles['Normal']))
        content.append(Spacer(1, 12))
        
        # Key indicators
        key_indicators = ai_analysis.get('key_indicators', [])
        if key_indicators:
            content.append(Paragraph("Security Indicators:", self.styles['SubsectionHeader']))
            
            indicator_data = [['Indicator', 'Severity', 'Description']]
            for indicator in key_indicators:
                indicator_data.append([
                    indicator.get('indicator', 'Unknown'),
                    indicator.get('severity', 'unknown').title(),
                    indicator.get('description', 'No description')
                ])
            
            indicator_table = Table(indicator_data, colWidths=[2*inch, 1*inch, 2.5*inch])
            indicator_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), Color(0.7, 0.7, 0.7)),
                ('TEXTCOLOR', (0, 0), (-1, 0), black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            content.append(indicator_table)
        
        return content
    
    def _create_security_analysis(self, analysis_result: Dict) -> List:
        """Create security analysis section for URLs and IPs."""
        content = []
        
        content.append(Paragraph("Security Analysis", self.styles['SectionHeader']))
        
        email_data = analysis_result.get('email_data', {})
        security_analysis = email_data.get('security_analysis', {})
        
        if not security_analysis or security_analysis.get('error'):
            content.append(Paragraph("Security analysis not available or failed to complete.", self.styles['Normal']))
            return content
        
        # Overall threat assessment
        threat_level = security_analysis.get('overall_threat_level', 'unknown')
        threat_color = self._get_threat_color(threat_level)
        
        threat_style = ParagraphStyle(
            name='ThreatLevel',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=threat_color,
            fontName='Helvetica-Bold',
            spaceAfter=12
        )
        
        content.append(Paragraph(f"Overall Threat Level: {threat_level.upper()}", threat_style))
        
        # Security summary
        security_summary = security_analysis.get('security_summary', {})
        
        summary_data = [
            ['Security Metric', 'Count', 'Status'],
            ['Malicious URLs', str(security_summary.get('malicious_urls', 0)), 
             '⚠️ HIGH RISK' if security_summary.get('malicious_urls', 0) > 0 else '✓ Safe'],
            ['Suspicious URLs', str(security_summary.get('suspicious_urls', 0)), 
             '⚠️ MEDIUM RISK' if security_summary.get('suspicious_urls', 0) > 0 else '✓ Safe'],
            ['Malicious IPs', str(security_summary.get('malicious_ips', 0)), 
             '⚠️ HIGH RISK' if security_summary.get('malicious_ips', 0) > 0 else '✓ Safe'],
            ['Suspicious IPs', str(security_summary.get('suspicious_ips', 0)), 
             '⚠️ MEDIUM RISK' if security_summary.get('suspicious_ips', 0) > 0 else '✓ Safe'],
            ['Total Threats', str(security_summary.get('total_threats', 0)), 
             '⚠️ ATTENTION REQUIRED' if security_summary.get('total_threats', 0) > 0 else '✓ No Threats']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), Color(0.7, 0.7, 0.7)),
            ('TEXTCOLOR', (0, 0), (-1, 0), black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        
        content.append(summary_table)
        content.append(Spacer(1, 12))
        
        # URL Analysis Details
        url_analysis = security_analysis.get('url_analysis', [])
        if url_analysis:
            content.append(Paragraph("URL Analysis Results:", self.styles['SubsectionHeader']))
            
            url_data = [['URL', 'VirusTotal Status', 'Detections', 'Risk Level']]
            for url_result in url_analysis:
                url = url_result.get('url', 'N/A')
                # Truncate long URLs
                if len(url) > 50:
                    url = url[:47] + "..."
                
                detections = f"{url_result.get('detections', 0)}/{url_result.get('total_scans', 0)}"
                
                if url_result.get('error'):
                    status = 'Error'
                    risk_level = 'Unknown'
                elif url_result.get('malicious'):
                    status = 'Malicious'
                    risk_level = 'HIGH'
                elif url_result.get('suspicious'):
                    status = 'Suspicious'
                    risk_level = 'MEDIUM'
                else:
                    status = 'Clean'
                    risk_level = 'LOW'
                
                url_data.append([url, status, detections, risk_level])
            
            url_table = Table(url_data, colWidths=[2.5*inch, 1*inch, 0.8*inch, 0.8*inch])
            url_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), Color(0.7, 0.7, 0.7)),
                ('TEXTCOLOR', (0, 0), (-1, 0), black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            content.append(url_table)
            content.append(Spacer(1, 12))
        
        # IP Analysis Details
        ip_analysis = security_analysis.get('ip_analysis', [])
        if ip_analysis:
            content.append(Paragraph("IP Address Analysis Results:", self.styles['SubsectionHeader']))
            
            ip_data = [['IP Address', 'Reputation Score', 'Status', 'Risk Level']]
            for ip_result in ip_analysis:
                ip = ip_result.get('ip', 'N/A')
                reputation_score = ip_result.get('reputation_score', 0)
                
                if ip_result.get('malicious'):
                    status = 'Malicious'
                    risk_level = 'HIGH'
                elif ip_result.get('suspicious'):
                    status = 'Suspicious'
                    risk_level = 'MEDIUM'
                else:
                    status = 'Clean'
                    risk_level = 'LOW'
                
                ip_data.append([ip, f"{reputation_score:.1f}/100", status, risk_level])
            
            ip_table = Table(ip_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), Color(0.7, 0.7, 0.7)),
                ('TEXTCOLOR', (0, 0), (-1, 0), black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            
            content.append(ip_table)
        
        return content
    
    def _get_threat_color(self, threat_level: str) -> Color:
        """Get color based on threat level."""
        threat_colors = {
            'high': red,
            'medium': orange,
            'low': green,
            'unknown': black
        }
        return threat_colors.get(threat_level.lower(), black)
    
    def _create_technical_details(self, analysis_result: Dict) -> List:
        """Create technical details section."""
        content = []
        
        content.append(Paragraph("Technical Details", self.styles['SectionHeader']))
        
        email_data = analysis_result.get('email_data', {})
        
        # Sender information
        content.append(Paragraph("Sender Information:", self.styles['SubsectionHeader']))
        sender_info = email_data.get('sender_info', {})
        
        sender_details = [
            f"From Address: {sender_info.get('from_address', 'N/A')}",
            f"Display Name: {sender_info.get('display_name', 'N/A')}",
            f"Reply-To: {sender_info.get('reply_to', 'N/A')}",
            f"Return-Path: {sender_info.get('return_path', 'N/A')}",
            f"Domain: {sender_info.get('domain', 'N/A')}",
            f"Valid Email Format: {sender_info.get('is_valid_email', False)}"
        ]
        
        for detail in sender_details:
            content.append(Paragraph(detail, self.styles['TechnicalDetails']))
        
        content.append(Spacer(1, 10))
        
        # Authentication results
        content.append(Paragraph("Authentication Results:", self.styles['SubsectionHeader']))
        auth_info = email_data.get('authentication', {})
        
        auth_details = [
            f"SPF: {auth_info.get('spf', {}).get('status', 'N/A')}",
            f"DKIM: {auth_info.get('dkim', {}).get('status', 'N/A')}",
            f"DMARC: {auth_info.get('dmarc', {}).get('status', 'N/A')}",
            f"Overall Status: {auth_info.get('overall_auth_status', 'N/A')}"
        ]
        
        for detail in auth_details:
            content.append(Paragraph(detail, self.styles['TechnicalDetails']))
        
        return content
    
    def _create_recommendations(self, analysis_result: Dict) -> List:
        """Create recommendations section."""
        content = []
        
        content.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        
        recommendations = analysis_result.get('recommendations', [])
        if not recommendations:
            recommendations = analysis_result.get('ai_analysis', {}).get('recommendations', [])
        
        if recommendations:
            for i, recommendation in enumerate(recommendations, 1):
                content.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
        else:
            content.append(Paragraph("No specific recommendations generated.", self.styles['Normal']))
        
        return content
    
    def _create_appendix(self, analysis_result: Dict) -> List:
        """Create appendix with technical data."""
        content = []
        
        content.append(Paragraph("Appendix: Technical Data", self.styles['SectionHeader']))
        
        # Analysis metadata
        technical_details = analysis_result.get('technical_details', {})
        
        metadata = [
            f"Analysis Timestamp: {analysis_result.get('timestamp', 'N/A')}",
            f"AI Model Used: {technical_details.get('model_used', 'N/A')}",
            f"Parsing Version: {technical_details.get('parsing_version', 'N/A')}",
            f"Analysis Components: {', '.join(technical_details.get('analysis_components', []))}"
        ]
        
        for item in metadata:
            content.append(Paragraph(item, self.styles['TechnicalDetails']))
        
        return content
    
    def generate_html_report(self, analysis_result: Dict, company_name: str = "Security Analysis Team") -> str:
        """
        Generate an HTML report.
        
        Args:
            analysis_result: Complete analysis result dictionary
            company_name: Name of the organization
            
        Returns:
            Path to the generated HTML file
        """
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sender = self._safe_filename(analysis_result.get('email_data', {}).get('sender_info', {}).get('from_address', 'unknown'))
        filename = f"phishing_analysis_{sender}_{timestamp}.html"
        filepath = self.report_dir / filename
        
        # Generate HTML content
        html_content = self._build_html_content(analysis_result, company_name)
        
        # Write HTML file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _build_html_content(self, analysis_result: Dict, company_name: str) -> str:
        """Build HTML content for the report."""
        email_data = analysis_result.get('email_data', {})
        ai_analysis = analysis_result.get('ai_analysis', {})
        final_assessment = analysis_result.get('final_assessment', {})
        sender_info = email_data.get('sender_info', {})
        
        risk_level = final_assessment.get('risk_level', 'unknown')
        confidence_score = final_assessment.get('confidence_score', 0)
        
        # Risk level colors for CSS
        risk_colors_css = {
            'low': '#4CAF50',
            'medium': '#FF9800',
            'high': '#FF5722',
            'critical': '#F44336'
        }
        
        risk_color = risk_colors_css.get(risk_level, '#9E9E9E')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Security Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }}
        .risk-indicator {{
            background-color: {risk_color};
            color: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            font-size: 1.2em;
            font-weight: bold;
            margin: 20px 0;
        }}
        .section {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #4a5568;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 10px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .info-card {{
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }}
        .indicator {{
            background: #fff5f5;
            border: 1px solid #fed7d7;
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .indicator.high {{ border-left: 4px solid #e53e3e; }}
        .indicator.medium {{ border-left: 4px solid #dd6b20; }}
        .indicator.low {{ border-left: 4px solid #38a169; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background-color: #667eea;
            color: white;
        }}
        .technical {{
            font-family: 'Courier New', monospace;
            background: #f7fafc;
            padding: 15px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .timestamp {{
            text-align: center;
            color: #718096;
            font-size: 0.9em;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Email Security Analysis Report</h1>
        <p>Generated by {company_name}</p>
        <p>{datetime.now().strftime("%B %d, %Y at %H:%M")}</p>
    </div>

    <div class="risk-indicator">
        RISK LEVEL: {risk_level.upper()} | CONFIDENCE: {confidence_score}%
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>{ai_analysis.get('summary', 'No summary available.')}</p>
        
        <div class="info-grid">
            <div class="info-card">
                <strong>Email From:</strong><br>
                {sender_info.get('from_address', 'N/A')}
            </div>
            <div class="info-card">
                <strong>Risk Classification:</strong><br>
                {risk_level.title()}
            </div>
            <div class="info-card">
                <strong>Phishing Likelihood:</strong><br>
                {'High' if final_assessment.get('is_likely_phishing', False) else 'Low'}
            </div>
            <div class="info-card">
                <strong>Indicators Found:</strong><br>
                {final_assessment.get('total_indicators', 0)}
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Detailed Analysis</h2>
        <p>{ai_analysis.get('detailed_analysis', 'No detailed analysis available.')}</p>
    </div>
"""

        # Add security analysis section
        security_analysis = email_data.get('security_analysis', {})
        if security_analysis and not security_analysis.get('error'):
            threat_level = security_analysis.get('overall_threat_level', 'unknown')
            security_summary = security_analysis.get('security_summary', {})
            
            threat_color_map = {
                'high': '#FF5722',
                'medium': '#FF9800', 
                'low': '#4CAF50',
                'unknown': '#9E9E9E'
            }
            
            html += f"""
    <div class="section">
        <h2>Security Analysis (URLs & IPs)</h2>
        
        <div class="risk-indicator" style="background-color: {threat_color_map.get(threat_level, '#9E9E9E')}">
            THREAT LEVEL: {threat_level.upper()}
        </div>
        
        <div class="info-grid">
            <div class="info-card">
                <strong>Malicious URLs:</strong><br>
                {security_summary.get('malicious_urls', 0)}
            </div>
            <div class="info-card">
                <strong>Suspicious URLs:</strong><br>
                {security_summary.get('suspicious_urls', 0)}
            </div>
            <div class="info-card">
                <strong>Malicious IPs:</strong><br>
                {security_summary.get('malicious_ips', 0)}
            </div>
            <div class="info-card">
                <strong>Suspicious IPs:</strong><br>
                {security_summary.get('suspicious_ips', 0)}
            </div>
        </div>
"""
            
            # URL Analysis table
            url_analysis = security_analysis.get('url_analysis', [])
            if url_analysis:
                html += """
        <h3>URL Analysis Results</h3>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>VirusTotal Status</th>
                    <th>Detections</th>
                    <th>Risk Level</th>
                </tr>
            </thead>
            <tbody>
"""
                for url_result in url_analysis:
                    url = url_result.get('url', 'N/A')
                    if len(url) > 60:
                        url = url[:57] + "..."
                    
                    detections = f"{url_result.get('detections', 0)}/{url_result.get('total_scans', 0)}"
                    
                    if url_result.get('error'):
                        status = 'Error'
                        risk_level = 'Unknown'
                        risk_color = '#9E9E9E'
                    elif url_result.get('malicious'):
                        status = 'Malicious'
                        risk_level = 'HIGH'
                        risk_color = '#FF5722'
                    elif url_result.get('suspicious'):
                        status = 'Suspicious'
                        risk_level = 'MEDIUM'
                        risk_color = '#FF9800'
                    else:
                        status = 'Clean'
                        risk_level = 'LOW'
                        risk_color = '#4CAF50'
                    
                    html += f"""
                <tr>
                    <td style="word-break: break-all;">{url}</td>
                    <td>{status}</td>
                    <td>{detections}</td>
                    <td style="color: {risk_color}; font-weight: bold;">{risk_level}</td>
                </tr>
"""
                html += """
            </tbody>
        </table>
"""
            
            # IP Analysis table
            ip_analysis = security_analysis.get('ip_analysis', [])
            if ip_analysis:
                html += """
        <h3>IP Address Analysis Results</h3>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Reputation Score</th>
                    <th>Status</th>
                    <th>Risk Level</th>
                </tr>
            </thead>
            <tbody>
"""
                for ip_result in ip_analysis:
                    ip = ip_result.get('ip', 'N/A')
                    reputation_score = ip_result.get('reputation_score', 0)
                    
                    if ip_result.get('malicious'):
                        status = 'Malicious'
                        risk_level = 'HIGH'
                        risk_color = '#FF5722'
                    elif ip_result.get('suspicious'):
                        status = 'Suspicious'
                        risk_level = 'MEDIUM'
                        risk_color = '#FF9800'
                    else:
                        status = 'Clean'
                        risk_level = 'LOW'
                        risk_color = '#4CAF50'
                    
                    html += f"""
                <tr>
                    <td>{ip}</td>
                    <td>{reputation_score:.1f}/100</td>
                    <td>{status}</td>
                    <td style="color: {risk_color}; font-weight: bold;">{risk_level}</td>
                </tr>
"""
                html += """
            </tbody>
        </table>
"""
            html += "    </div>"
        
        elif security_analysis and security_analysis.get('error'):
            html += f"""
    <div class="section">
        <h2>Security Analysis (URLs & IPs)</h2>
        <p style="color: #FF9800; font-weight: bold;">Security analysis failed: {security_analysis.get('error', 'Unknown error')}</p>
    </div>
"""

        html += """
"""

        # Add indicators section if available
        key_indicators = ai_analysis.get('key_indicators', [])
        if key_indicators:
            html += """
    <div class="section">
        <h2>Security Indicators</h2>
"""
            for indicator in key_indicators:
                severity = indicator.get('severity', 'unknown')
                html += f"""
        <div class="indicator {severity}">
            <strong>{indicator.get('indicator', 'Unknown Indicator')}</strong> 
            <span style="float: right; background: {risk_colors_css.get(severity, '#9E9E9E')}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em;">
                {severity.upper()}
            </span>
            <br>
            {indicator.get('description', 'No description available.')}
            {f'<br><em>Evidence: {indicator["evidence"]}</em>' if indicator.get('evidence') else ''}
        </div>
"""
            html += "    </div>"

        # Technical details section
        html += f"""
    <div class="section">
        <h2>Technical Details</h2>
        <h3>Sender Information</h3>
        <div class="technical">
From Address: {sender_info.get('from_address', 'N/A')}<br>
Display Name: {sender_info.get('display_name', 'N/A')}<br>
Reply-To: {sender_info.get('reply_to', 'N/A')}<br>
Return-Path: {sender_info.get('return_path', 'N/A')}<br>
Domain: {sender_info.get('domain', 'N/A')}<br>
Valid Email Format: {sender_info.get('is_valid_email', False)}
        </div>

        <h3>Authentication Results</h3>
        <div class="technical">
SPF: {email_data.get('authentication', {}).get('spf', {}).get('status', 'N/A')}<br>
DKIM: {email_data.get('authentication', {}).get('dkim', {}).get('status', 'N/A')}<br>
DMARC: {email_data.get('authentication', {}).get('dmarc', {}).get('status', 'N/A')}<br>
Overall Status: {email_data.get('authentication', {}).get('overall_auth_status', 'N/A')}
        </div>
    </div>
"""

        # Recommendations section
        recommendations = analysis_result.get('recommendations', [])
        if not recommendations:
            recommendations = ai_analysis.get('recommendations', [])
        
        if recommendations:
            html += """
    <div class="section">
        <h2>Recommendations</h2>
        <ol>
"""
            for recommendation in recommendations:
                html += f"            <li>{recommendation}</li>\n"
            html += """
        </ol>
    </div>
"""

        # Footer
        html += f"""
    <div class="timestamp">
        Report generated on {datetime.now().strftime("%B %d, %Y at %H:%M")} | 
        Analysis ID: {analysis_result.get('timestamp', 'N/A')}
    </div>
</body>
</html>
"""
        
        return html
    
    def _safe_filename(self, text: str) -> str:
        """Convert text to a safe filename."""
        # Remove or replace unsafe characters
        safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
        safe_text = ''.join(char if char in safe_chars else '_' for char in text)
        
        # Limit length and remove consecutive underscores
        safe_text = safe_text[:50]
        while '__' in safe_text:
            safe_text = safe_text.replace('__', '_')
        
        return safe_text.strip('_')
    
    def get_report_list(self) -> List[Dict]:
        """Get list of generated reports."""
        reports = []
        
        for file_path in self.report_dir.glob("*"):
            if file_path.is_file() and file_path.suffix.lower() in ['.pdf', '.html']:
                reports.append({
                    'filename': file_path.name,
                    'path': str(file_path),
                    'size': file_path.stat().st_size,
                    'created': datetime.fromtimestamp(file_path.stat().st_ctime),
                    'format': file_path.suffix.lower()[1:]  # Remove the dot
                })
        
        # Sort by creation time (newest first)
        reports.sort(key=lambda x: x['created'], reverse=True)
        
        return reports