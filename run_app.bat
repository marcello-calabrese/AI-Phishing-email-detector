@echo off
echo.
echo ================================
echo  AI Phishing Email Detector
echo  Enhanced with Dataset Learning
echo ================================
echo.

REM Change to the application directory
cd /d "c:\Users\marce\Desktop\Python\pythoncheatsheets\python_projects\AI Phishing email detector"

echo Loading phishing dataset (82,000+ samples)...
echo Starting AI analyzer with enhanced detection...
echo.

REM Check if virtual environment exists
if not exist ".venv" (
    echo Virtual environment not found!
    echo Please run: uv sync
    pause
    exit /b 1
)

REM Run the application using UV
echo 🚀 Launching application...
echo 📱 The app will open in your default browser
echo 🌐 URL: http://localhost:8501
echo.
echo 🛑 Press Ctrl+C to stop the application
echo =======================================
echo.

uv run streamlit run main.py

echo.
echo 👋 Application stopped.
pause