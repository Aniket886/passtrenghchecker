@echo off
title CYBERPUNK SECURITY PROTOCOL v2.0
color 0A

echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                                                              ║
echo ║    🔮 CYBERPUNK SECURITY PROTOCOL v2.0 🔮                  ║
echo ║                                                              ║
echo ║    NEURAL NETWORK PASSWORD ANALYSIS SYSTEM                  ║
echo ║                                                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

echo 🔍 CHECKING PYTHON INSTALLATION...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ PYTHON NOT FOUND! Please install Python 3.8+ first.
    pause
    exit /b 1
)
echo ✅ PYTHON: DETECTED

echo.
echo 🚀 INITIALIZING CYBERPUNK SECURITY PROTOCOL...
echo ✅ NEURAL NETWORK: READY
echo ✅ QUANTUM ENCRYPTION: ACTIVE
echo ✅ SECURITY MATRIX: ONLINE

echo.
echo 🌐 STARTING CYBERPUNK WEB INTERFACE...
echo 🔗 ACCESS URL: http://localhost:5000
echo 🔗 SYSTEM STATUS: http://localhost:5000/system_status
echo.
echo ⚠️  PRESS CTRL+C TO SHUTDOWN SYSTEM
echo ============================================================

python start_cyberpunk.py

echo.
echo 🛑 CYBERPUNK SECURITY PROTOCOL SHUTDOWN COMPLETE
pause
