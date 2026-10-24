@echo off
setlocal enabledelayedexpansion
title SecuRAG Launcher

:menu
cls
echo ======================================================================
echo    ____                  ____        _    ____ 
echo   / ___|  ___  ___ _   _^|  _ \      / \  / ___^|
echo   \___ \ / _ \/ __^| ^| ^| ^| ^|_) ^|____/ _ \^| ^|  _ 
echo    ___) ^|  __/ (__^| ^|_^| ^|  _ ^<_____/ ___ \ ^|_^| ^|
echo   ^|____/ \___^|\___^|\__,_^|_^| \_\   /_/   \_\____^|
echo.
echo   Agentic Hybrid GraphRAG for CVE / Threat-Intel Triage
echo ======================================================================
echo.

:: Check for virtual environment
if not exist ".venv\Scripts\activate.bat" (
    echo [!] Virtual environment (.venv) not found.
    echo Running automated setup first...
    echo.
    call setup.bat
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Setup failed.
        pause
        exit /b 1
    )
)

echo Select an option to load and run SecuRAG:
echo.
echo   [1] Launch Full Stack (FastAPI API + Streamlit Interactive UI) [RECOMMENDED]
echo   [2] Launch Streamlit UI Dashboard Only
echo   [3] Launch FastAPI Service (Swagger docs at http://127.0.0.1:8000/docs)
echo   [4] Run System Infrastructure Healthcheck
echo   [5] Run Full Ingestion & Graph Loader (Parsers -^> Neo4j -^> Pinecone)
echo   [6] Run Acceptance Test Suite (pytest)
echo   [0] Exit
echo.
set /p CHOICE="Enter choice [0-6] (default=1): "
if "%CHOICE%"=="" set CHOICE=1

if "%CHOICE%"=="1" goto :launch_full
if "%CHOICE%"=="2" goto :launch_ui
if "%CHOICE%"=="3" goto :launch_api
if "%CHOICE%"=="4" goto :healthcheck
if "%CHOICE%"=="5" goto :run_ingest
if "%CHOICE%"=="6" goto :run_tests
if "%CHOICE%"=="0" goto :exit

echo [!] Invalid choice.
pause
goto :menu

:launch_full
echo.
echo [*] Checking Docker and Neo4j...
docker ps >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Starting Neo4j container...
    docker compose up -d
) else (
    echo [!] Docker not detected or not running. Ensure Neo4j is running on bolt://localhost:7687.
)
echo.
echo [*] Starting FastAPI service in background window...
start "SecuRAG FastAPI Service" cmd /c "call .venv\Scripts\activate.bat && python -m uvicorn securag.api.main:app --host 127.0.0.1 --port 8000"
echo [*] Waiting for API startup...
timeout /t 3 /nobreak >nul
echo [*] Launching Streamlit UI in browser...
call .venv\Scripts\activate.bat && streamlit run src\securag\ui\app.py
goto :menu

:launch_ui
echo.
echo [*] Launching Streamlit UI Dashboard...
call .venv\Scripts\activate.bat && streamlit run src\securag\ui\app.py
goto :menu

:launch_api
echo.
echo [*] Launching FastAPI Service at http://127.0.0.1:8000...
echo Interactive Swagger Docs: http://127.0.0.1:8000/docs
echo.
call .venv\Scripts\activate.bat && python -m uvicorn securag.api.main:app --host 127.0.0.1 --port 8000 --reload
pause
goto :menu

:healthcheck
echo.
echo [*] Running SecuRAG Healthcheck...
call .venv\Scripts\activate.bat && python scripts\healthcheck.py
echo.
pause
goto :menu

:run_ingest
echo.
echo ======================================================================
echo   Running Ingestion & Graph Ingestion Pipeline
echo ======================================================================
echo.
call .venv\Scripts\activate.bat
echo [1/4] Parsing raw datasets to JSONL...
python -m securag.ingest.parsers.cve
python -m securag.ingest.parsers.kev
python -m securag.ingest.parsers.cwe
python -m securag.ingest.parsers.capec
python -m securag.ingest.parsers.attack
echo.
echo [2/4] Loading graph topology into Neo4j...
python -m securag.graph.load
echo.
echo [3/4] Creating chunk SQLite docstore and Neo4j chunk nodes...
python -m securag.ingest.chunk
echo.
echo [4/4] Building BM25 sparse indices...
python -m securag.retrieval.bm25
echo.
echo [OK] Ingestion complete.
pause
goto :menu

:run_tests
echo.
echo [*] Running full test suite...
call .venv\Scripts\activate.bat && python -m pytest tests\ -v
echo.
pause
goto :menu

:exit
echo.
echo Exiting SecuRAG. Goodbye!
exit /b 0
