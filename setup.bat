@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   SecuRAG - Automated Environment Setup
echo   Agentic Hybrid GraphRAG for CVE / Threat-Intel Triage
echo ============================================================
echo.

:: 1. Detect Python
echo [1/6] Checking Python installation...
set "PYTHON_CMD="

:: Try py -3.12, py -3.11, python
py -3.12 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=py -3.12"
    goto :python_found
)

py -3.11 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=py -3.11"
    goto :python_found
)

python --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=python"
    goto :python_found
)

echo [ERROR] Python 3.12 or 3.11 not found!
echo Please install Python 3.12 from python.org and add it to PATH.
pause
exit /b 1

:python_found
echo [OK] Using %PYTHON_CMD%
for /f "tokens=*" %%i in ('%PYTHON_CMD% --version') do echo   %%i
echo.

:: 2. Setup Virtual Environment
echo [2/6] Setting up virtual environment in .venv...
if not exist ".venv" (
    echo Creating .venv directory...
    %PYTHON_CMD% -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create venv!
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Existing .venv found.
)
echo.

:: 3. Activate venv
echo [3/6] Activating virtual environment...
if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] .venv\Scripts\activate.bat missing!
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
echo [OK] Activated .venv
echo.

:: 4. Upgrade pip
echo [4/6] Upgrading pip...
python -m pip install --upgrade pip --quiet
echo [OK] Pip upgraded.
echo.

:: 5. Install Dependencies
echo [5/6] Installing PyTorch and dependencies...

:: Check for NVIDIA GPU
nvidia-smi >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo NVIDIA GPU detected. Installing PyTorch with CUDA 12.4 support...
    pip install torch torchvision --index-url https://download.pytorch.org/whl/cu124
) else (
    echo No NVIDIA GPU detected. Installing CPU PyTorch...
    pip install torch torchvision
)

echo Installing requirements from requirements.txt...
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [WARNING] requirements.txt installation had warnings. Trying requirements-loose.txt if available...
    if exist "requirements-loose.txt" (
        pip install -r requirements-loose.txt
    )
)

echo Installing SecuRAG package in editable mode...
pip install -e . --no-deps
echo [OK] Dependencies installed successfully.
echo.

:: 6. Environment configuration (.env)
echo [6/6] Checking configuration (.env)...
if not exist ".env" (
    if exist ".env.example" (
        echo Creating .env from .env.example...
        copy .env.example .env >nul
        echo [IMPORTANT] Created .env file. Please edit .env and configure your LLM, Neo4j, and Pinecone API keys!
    )
) else (
    echo [OK] Existing .env file found.
)
echo.

echo ============================================================
echo   SecuRAG Setup Complete!
echo ============================================================
echo.
echo Next steps:
echo   1. Start Neo4j:
echo      docker compose up -d
echo.
echo   2. Run system healthcheck:
echo      python scripts\healthcheck.py
echo.
echo   3. Launch FastAPI backend:
echo      python -m uvicorn securag.api.main:app --reload
echo.
echo   4. Launch Streamlit UI:
echo      streamlit run src\securag\ui\app.py
echo.
pause
