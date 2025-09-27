# AI Phishing Email Detector

A sophisticated web application for analyzing email headers to detect phishing attempts using AI-powered analysis. Built with Streamlit and OpenAI, featuring a VirusTotal-inspired interface for IT security professionals.

## 🚀 Features

- **AI-Powered Analysis**: Uses OpenAI GPT models for intelligent phishing detection
- **Professional Interface**: VirusTotal-inspired UI for security professionals
- **URL & IP Security Analysis**: Check URLs against VirusTotal and IP addresses against reputation databases
- **Comprehensive Reports**: Generate PDF and HTML reports with security analysis included
- **Email Header Parsing**: Advanced parsing of email headers and authentication records
- **Risk Assessment**: Confidence scoring with detailed explanations
- **Analysis History**: Track and analyze patterns over time
- **Dashboard Analytics**: Visual insights into detection trends

## 📋 Requirements

- Python 3.12+
- OpenAI API key (paid account recommended for better performance)
- VirusTotal API key (optional, for URL analysis)
- AbuseIPDB API key (optional, for IP reputation checking)
- Modern web browser

## 🛠️ Installation

1. **Clone or navigate to the project directory**

2. **Install dependencies using uv** (already done if you have the environment set up):

   ```bash

   uv sync
   ```

3. **Configure the application**:
   - Copy the configuration template:
   -

     ```bash

     copy config.json.template config.json
     ```

   - Edit `config.json` and add your OpenAI API key and preferences

## ▶️ Running the Application

### Method 1: Using the main script

```bash
uv run python main.py
```

### Method 2: Direct Streamlit execution

```bash
uv run streamlit run src/app.py
```

The application will open in your browser at `http://localhost:8501`

## 🔧 Initial Setup

1. **Configure OpenAI API**: On first run, you'll be prompted to enter your OpenAI API key
2. **Set Organization Details**: Configure your organization name for reports
3. **Adjust Settings**: Customize confidence thresholds and report preferences

## 📖 Usage Guide

### Analyzing an Email

1. **Navigate to "Email Analysis"** tab
2. **Input email headers** using one of two methods:
   - **Paste Headers**: Copy and paste email headers directly
   - **Upload File**: Upload .eml, .txt, or .msg files
3. **Click "Analyze Email"** to start the analysis
4. **Review Results** in the comprehensive results interface

### Understanding Results

- **Risk Level**: Critical, High, Medium, or Low based on analysis
- **Confidence Score**: AI confidence percentage (0-100%)
- **Security Indicators**: Detailed list of suspicious patterns found
- **Authentication Status**: SPF, DKIM, DMARC validation results

### Generating Reports

1. Go to the **"Reports"** tab in the analysis results
2. Choose between **PDF** or **HTML** format
3. **Download** the professional report for documentation

### Dashboard Analytics

- View analysis **statistics** and **trends**
- **Risk level distribution** charts
- **Timeline analysis** of detection patterns
- **Performance metrics** for your security operations

## 📁 Project Structure

```

├── src/
│   ├── app.py              # Main Streamlit application
│   ├── config.py           # Configuration management
│   ├── email_parser.py     # Email header parsing
│   ├── ai_analyzer.py      # OpenAI integration
│   └── report_generator.py # Report generation
├── data/                   # Analysis history storage
├── reports/               # Generated reports
├── config.json.template   # Configuration template
├── config.json           # Your configuration (create this)
├── main.py               # Application entry point
└── README.md            # This file
```

## 🔐 Security Indicators Detected

The system analyzes multiple security indicators including:

- **Authentication Failures**: SPF, DKIM, DMARC validation
- **Display Name Spoofing**: Mismatched display names and domains
- **Domain Reputation**: Suspicious TLDs and domain characteristics
- **Email Format Issues**: Invalid email addresses and formatting
- **Routing Anomalies**: Suspicious email routing patterns
- **Reply-To Mismatches**: Different reply-to and from addresses

## ⚙️ Configuration Options

### AI Settings

- **Model Selection**: Choose between GPT models
- **Temperature**: Control AI response creativity (0.0-2.0)
- **Max Tokens**: Maximum response length

### Security API Settings

- **VirusTotal API Key**: For URL malicious content checking (get free key at <https://www.virustotal.com/gui/join-us>)
- **AbuseIPDB API Key**: For IP reputation checking (get free key at <https://www.abuseipdb.com/>)
- **Security Analysis**: Enable/disable URL and IP checking

### Report Settings

- **Organization Name**: Your company name for reports
- **Default Format**: PDF or HTML
- **Technical Details**: Include/exclude technical information

### Confidence Thresholds

- **Low Risk**: Below X% confidence
- **Medium Risk**: X% to Y% confidence  
- **High Risk**: Above Y% confidence

## 🚨 Risk Assessment

The system provides four risk levels:

- **🟢 Low**: Minimal phishing indicators, likely legitimate
- **🟡 Medium**: Some suspicious patterns, requires caution
- **🟠 High**: Multiple phishing indicators, potentially dangerous
- **🔴 Critical**: Strong phishing signals, treat as malicious

## 📊 Analytics & History

- **Analysis History**: Search and filter past analyses
- **Trend Analysis**: Identify patterns in phishing attempts
- **Performance Metrics**: Track detection rates and confidence
- **Data Export**: Generate comprehensive reports

## 🛡️ Best Practices

1. **Regular Updates**: Keep the application and dependencies updated
2. **API Key Security**: Store your OpenAI API key securely
3. **Report Archival**: Regularly backup generated reports
4. **Threshold Tuning**: Adjust confidence thresholds based on your environment
5. **Team Training**: Train team members on interpreting results

## 🔍 Troubleshooting

### Common Issues

**"OpenAI connection failed"**

- Verify your API key is correct
- Check your OpenAI account has sufficient credits
- Ensure internet connectivity

**"Email parsing failed"**

- Verify the email headers are complete
- Check for special characters or encoding issues
- Try uploading as a file instead of pasting

**"Report generation failed"**

- Ensure the reports directory exists and is writable
- Check available disk space
- Verify all dependencies are installed

### Getting Help

1. Check the **Settings** page for system information
2. Review the **application logs** for error details
3. Test the **OpenAI connection** in settings
4. Verify your **configuration file** is valid JSON

## 🤝 Support

For issues and questions:

- Check the troubleshooting section above
- Review the configuration requirements
- Ensure all dependencies are properly installed

## 📝 License

This project is for educational and professional use. Ensure compliance with your organization's security policies when analyzing email data.

---

**⚡ Quick Start**: `uv run python main.py` → Configure API key → Start analyzing emails!
