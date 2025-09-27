@echo off
title AI Phishing Email Detector - Launcher
color 0B

:menu
cls
echo.
echo  ████████████████████████████████████████████████████████████
echo  █                                                          █
echo  █          🔒 AI Phishing Email Detector 🔒              █  
echo  █                                                          █
echo  █          Choose an option:                               █
echo  █                                                          █
echo  █   [1] 🚀 Run Application                                █
echo  █   [2] 🔧 Setup/Install Dependencies                     █
echo  █   [3] 🔍 Troubleshoot Issues                            █
echo  █   [4] 📁 Open Project Folder                            █
echo  █   [5] 🌐 Open Browser (if app is running)              █
echo  █   [6] ❌ Exit                                           █
echo  █                                                          █
echo  ████████████████████████████████████████████████████████████
echo.

set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto run_app
if "%choice%"=="2" goto setup
if "%choice%"=="3" goto troubleshoot
if "%choice%"=="4" goto open_folder
if "%choice%"=="5" goto open_browser
if "%choice%"=="6" goto exit
goto invalid

:run_app
cls
echo Starting AI Phishing Email Detector...
call run_app.bat
goto menu

:setup
cls
echo Running setup...
call setup.bat
goto menu

:troubleshoot
cls
call troubleshoot.bat
goto menu

:open_folder
start explorer .
echo Project folder opened in Explorer
pause
goto menu

:open_browser
start http://localhost:8501
echo Browser opened to http://localhost:8501
pause
goto menu

:invalid
cls
echo Invalid choice! Please enter a number between 1-6.
pause
goto menu

:exit
echo.
echo 👋 Thank you for using AI Phishing Email Detector!
echo.
exit