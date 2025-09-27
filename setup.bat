@echo off
echo.
echo ================================
echo    Setup AI Phishing Detector
echo ================================
echo.

REM Change to the application directory
cd /d "c:\Users\marce\Desktop\Python\pythoncheatsheets\python_projects\AI Phishing email detector"

echo 🔧 Setting up AI Phishing Email Detector...
echo.

REM Check if UV is installed
uv --version >nul 2>&1
if errorlevel 1 (
    echo ❌ UV is not installed or not in PATH
    echo Please install UV first: https://docs.astral.sh/uv/getting-started/installation/
    pause
    exit /b 1
)

echo ✅ UV is available
echo.

REM Sync dependencies
echo 📦 Installing dependencies...
uv sync

if errorlevel 1 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

echo ✅ Dependencies installed successfully
echo.

REM Check configuration
if not exist "config.json" (
    echo 📋 Creating default configuration...
    copy "config.json.template" "config.json" >nul 2>&1
    if errorlevel 1 (
        echo ⚠️  No config template found. You'll need to configure manually.
    ) else (
        echo ✅ Default configuration created
    )
)

echo.
echo 🎉 Setup complete!
echo.
echo Next steps:
echo 1. Configure your OpenAI API key in the app settings
echo 2. (Optional) Configure VirusTotal and AbuseIPDB API keys
echo 3. Run the app using run_app.bat
echo.
pause