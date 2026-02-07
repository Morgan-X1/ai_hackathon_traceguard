@echo off
echo ========================================
echo TraceGuard AI - Quick Start
echo ========================================
echo.

echo [1/4] Creating virtual environment...
python -m venv venv
echo.

echo [2/4] Activating virtual environment...
call venv\Scripts\activate.bat
echo.

echo [3/4] Installing dependencies...
pip install -r requirements_traceguard.txt
echo.

echo [4/4] Running setup script...
python setup.py
echo.

echo ========================================
echo Installation Complete!
echo ========================================
echo.
echo To start the server:
echo   1. Activate virtual environment: venv\Scripts\activate
echo   2. Run server: python manage.py runserver
echo   3. Visit: http://127.0.0.1:8000/dashboard/
echo.
pause
