#!/usr/bin/env python3
"""
AI Phishing Email Detector - Main Entry Point

This script provides a simple entry point to run the Streamlit application.
"""

import sys
import subprocess
from pathlib import Path

def main():
    """Run the Streamlit application."""
    # Get the path to the app.py file
    app_path = Path(__file__).parent / "src" / "app.py"
    
    if not app_path.exists():
        print("❌ Error: app.py not found in src directory")
        sys.exit(1)
    
    print("🚀 Starting AI Phishing Email Detector...")
    print("📁 Application will open in your browser")
    print("🔧 Make sure to configure your OpenAI API key in the settings")
    print("-" * 50)
    
    try:
        # Run streamlit with the app
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", str(app_path),
            "--server.address", "localhost",
            "--server.port", "8501",
            "--browser.gatherUsageStats", "false"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running Streamlit: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
