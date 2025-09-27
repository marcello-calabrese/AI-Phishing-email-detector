@echo off
echo.
echo ================================
echo  AI Phishing Email Detector
echo      (Direct Python)
echo ================================
echo.

REM Change to the application directory
cd /d "c:\Users\marce\Desktop\Python\pythoncheatsheets\python_projects\AI Phishing email detector"

echo 🔍 Starting AI Phishing Email Detector...
echo.

REM Check if virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo ❌ Virtual environment not found!
    echo Please run: uv sync
    pause
    exit /b 1
)

REM Activate virtual environment and run
echo 🚀 Launching application with virtual environment...
echo 📱 The app will open in your default browser
echo 🌐 URL: http://localhost:8501
echo.
echo 🛑 Press Ctrl+C to stop the application
echo =======================================
echo.

.venv\Scripts\python.exe main.py

echo.
echo 👋 Application stopped.
pause