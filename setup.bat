@echo off
setlocal enabledelayedexpansion

echo ======================================================================
echo    ____                  ____        _    ____ 
echo   / ___|  ___  ___ _   _|  _ \      / \  / ___|
echo   \___ \ / _ \/ __| | | | |_) |____/ _ \| |  _ 
echo    ___) |  __/ (__| |_| |  _ <_____/ ___ \ |_| |
echo   |____/ \___|\___|\__,_|_| \_\   /_/   \_\____|
echo.
echo   SecuRAG - Automated Environment Setup
echo   Agentic Hybrid GraphRAG for CVE / Threat-Intel Triage
echo ======================================================================
echo.

:: 1. Detect Python
echo [1/9] Checking Python installation...
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
echo [2/9] Setting up virtual environment in .venv...
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
echo [3/9] Activating virtual environment...
if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] .venv\Scripts\activate.bat missing!
    pause
    exit /b 1
)
call .venv\Scripts\activate.bat
echo [OK] Activated .venv
echo.

:: 4. Upgrade pip
echo [4/9] Upgrading pip...
python -m pip install --upgrade pip --quiet
echo [OK] Pip upgraded.
echo.

:: 5. Install Dependencies
echo [5/9] Installing PyTorch and project dependencies...

:: Check for NVIDIA GPU
nvidia-smi >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo NVIDIA GPU detected. Installing PyTorch with CUDA support...
    pip install torch torchvision --index-url https://download.pytorch.org/whl/cu124
) else (
    echo No NVIDIA GPU detected. Installing CPU PyTorch...
    pip install torch torchvision
)

echo Installing requirements from requirements.txt...
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [WARNING] requirements.txt installation had warnings. Trying requirements-loose.txt...
    if exist "requirements-loose.txt" (
        pip install -r requirements-loose.txt
    )
)

echo Installing SecuRAG package in editable mode...
pip install -e . --no-deps
echo [OK] Dependencies installed successfully.
echo.

:: 6. Pre-download and Warm ML Models
echo [6/9] Pre-downloading Hugging Face ML models...
echo   1. Dense Embedder: BAAI/bge-m3 (1024-dim)
echo   2. Cross-Encoder:  BAAI/bge-reranker-v2-m3
python scripts\download_models.py
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Model download encountered an issue. Models will download on first query if needed.
)
echo.

:: 7. Raw Security Datasets Check
echo [7/9] Checking security datasets (data\raw)...
if not exist "data\raw\cvelistV5" (
    echo [!] Raw datasets not detected in data\raw.
    echo Downloading public vulnerability datasets (CISA KEV, CVEs 2024-2025, CWE, CAPEC, ATT&CK)...
    powershell -ExecutionPolicy Bypass -File scripts\clone_data.ps1 -Years 2024,2025
) else (
    echo [OK] Security datasets found in data\raw.
)
echo.

:: 8. Environment Configuration (.env)
echo [8/9] Checking configuration (.env)...
if not exist ".env" (
    if exist ".env.example" (
        echo Creating .env from .env.example...
        copy .env.example .env >nul
        echo [IMPORTANT] Created .env file. Please edit .env with your LLM, Neo4j, and Pinecone credentials!
    )
) else (
    echo [OK] Existing .env file found.
)
echo.

:: 9. Generate Technical Documentation PDF
echo [9/9] Generating Technical Documentation PDF...
python scripts\generate_pdf_docs.py
if %ERRORLEVEL% equ 0 (
    echo [OK] Documentation generated: docs\SecuRAG_Documentation.pdf
) else (
    echo [NOTE] Documentation HTML available in docs\SecuRAG_Documentation.html
)
echo.

echo ======================================================================
echo   SecuRAG Setup Complete!
echo ======================================================================
echo.
echo Next steps:
echo   1. Ensure Docker Desktop is running and start Neo4j APOC:
echo      docker compose up -d
echo.
echo   2. Launch the interactive menu:
echo      run.bat
echo.
pause
