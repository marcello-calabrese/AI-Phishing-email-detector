@echo off
echo.
echo ========================================
echo  AI Phishing Detector - Troubleshooting
echo ========================================
echo.

cd /d "c:\Users\marce\Desktop\Python\pythoncheatsheets\python_projects\AI Phishing email detector"

echo 🔧 Running diagnostics...
echo.

echo 1. Checking UV installation:
uv --version 2>nul
if errorlevel 1 (
    echo ❌ UV not found
) else (
    echo ✅ UV is available
)
echo.

echo 2. Checking virtual environment:
if exist ".venv\Scripts\python.exe" (
    echo ✅ Virtual environment found
    echo Python version:
    .venv\Scripts\python.exe --version
) else (
    echo ❌ Virtual environment not found
    echo Run: uv sync
)
echo.

echo 3. Checking configuration:
if exist "config.json" (
    echo ✅ Configuration file exists
) else (
    echo ❌ Configuration file missing
    echo Copy config.json.template to config.json
)
echo.

echo 4. Checking dependencies:
echo Testing critical imports...
.venv\Scripts\python.exe -c "
try:
    import streamlit
    print('✅ Streamlit: OK')
except ImportError:
    print('❌ Streamlit: Missing')

try:
    from src.app import PhishingDetectorApp
    print('✅ App modules: OK')
except ImportError as e:
    print(f'❌ App modules: {e}')

try:
    from src.security_analyzer import SecurityAnalyzer
    print('✅ Security analyzer: OK')
except ImportError as e:
    print(f'❌ Security analyzer: {e}')
" 2>nul

echo.
echo 5. Checking ports:
echo Checking if port 8501 is in use...
netstat -an | find "8501" >nul
if errorlevel 1 (
    echo ✅ Port 8501 is available
) else (
    echo ⚠️ Port 8501 is in use - you may need to stop other Streamlit apps
)

echo.
echo ========================================
echo Diagnostic complete!
echo ========================================
pause