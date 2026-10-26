@echo off
setlocal enabledelayedexpansion
title SecuRAG Launcher

:menu
cls
echo ======================================================================
echo    ____                  ____        _    ____ 
echo   / ___|  ___  ___ _   _|  _ \      / \  / ___|
echo   \___ \ / _ \/ __| | | | |_) |____/ _ \| |  _ 
echo    ___) |  __/ (__| |_| |  _ <_____/ ___ \ |_| |
echo   |____/ \___|\___|\__,_|_| \_\   /_/   \_\____|
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
echo   [1]  Launch Full Stack (FastAPI API + Streamlit Interactive UI) [RECOMMENDED]
echo   [2]  Launch Streamlit UI Dashboard Only (http://localhost:8501)
echo   [3]  Launch FastAPI Service (Swagger docs at http://127.0.0.1:8000/docs)
echo   [4]  Run System Infrastructure Healthcheck (Neo4j, Pinecone, Models, LLM)
echo   [5]  Run Full Ingestion & Graph Loader (Parsers -^> Neo4j -^> Pinecone)
echo   [6]  Pre-download & Cache ML Models (BAAI/bge-m3 & BAAI/bge-reranker-v2-m3)
echo   [7]  Download Raw Security Datasets (CISA KEV, CVEs, CWE, CAPEC, ATT&CK)
echo   [8]  Run Acceptance Test Suite (pytest tests/ -v)
echo   [9]  Recompile Technical Documentation (PDF & HTML)
echo   [10] Open Technical Documentation PDF
echo   [0]  Exit
echo.
set /p CHOICE="Enter choice [0-10] (default=1): "
if "%CHOICE%"=="" set CHOICE=1

if "%CHOICE%"=="1" goto :launch_full
if "%CHOICE%"=="2" goto :launch_ui
if "%CHOICE%"=="3" goto :launch_api
if "%CHOICE%"=="4" goto :healthcheck
if "%CHOICE%"=="5" goto :run_ingest
if "%CHOICE%"=="6" goto :download_models
if "%CHOICE%"=="7" goto :download_data
if "%CHOICE%"=="8" goto :run_tests
if "%CHOICE%"=="9" goto :recompile_docs
if "%CHOICE%"=="10" goto :open_docs
if "%CHOICE%"=="0" goto :exit

echo [!] Invalid choice: %CHOICE%
pause
goto :menu

:launch_full
echo.
echo [*] Checking Docker and Neo4j...
docker ps >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Starting Neo4j container...
    docker compose up -d
) else (
    echo [!] Docker engine not reachable. If Docker Desktop is installed, please ensure it is open.
    echo [!] SecuRAG will attempt to connect to Neo4j at bolt://localhost:7687.
)
echo.
echo [*] Starting FastAPI service in background window...
echo     Swagger Documentation: http://127.0.0.1:8000/docs
start "SecuRAG FastAPI Service" cmd /c "call .venv\Scripts\activate.bat && python -m uvicorn securag.api.main:app --host 127.0.0.1 --port 8000 --reload"
echo [*] Waiting for API startup...
timeout /t 3 /nobreak >nul
echo.
echo [*] Launching Streamlit UI Dashboard at http://localhost:8501...
call .venv\Scripts\activate.bat && streamlit run src\securag\ui\app.py --server.port 8501
goto :menu

:launch_ui
echo.
echo [*] Launching Streamlit UI Dashboard at http://localhost:8501...
call .venv\Scripts\activate.bat && streamlit run src\securag\ui\app.py --server.port 8501
goto :menu

:launch_api
echo.
echo [*] Launching FastAPI Service at http://127.0.0.1:8000...
echo     Interactive Swagger Docs: http://127.0.0.1:8000/docs
echo.
call .venv\Scripts\activate.bat && python -m uvicorn securag.api.main:app --host 127.0.0.1 --port 8000 --reload
pause
goto :menu

:healthcheck
echo.
echo [*] Running SecuRAG System Healthcheck...
call .venv\Scripts\activate.bat && python scripts\healthcheck.py
echo.
pause
goto :menu

:run_ingest
echo.
echo ======================================================================
echo   Running Full Ingestion & Graph Ingestion Pipeline
echo ======================================================================
echo.
call .venv\Scripts\activate.bat
echo [1/5] Parsing raw datasets to JSONL...
python -m securag.ingest.parsers.cve
python -m securag.ingest.parsers.kev
python -m securag.ingest.parsers.cwe
python -m securag.ingest.parsers.capec
python -m securag.ingest.parsers.attack
echo.
echo [2/5] Loading graph topology into Neo4j...
python -m securag.graph.load
echo.
echo [3/5] Creating chunk SQLite docstore and Neo4j chunk nodes...
python -m securag.ingest.chunk
echo.
echo [4/5] Building BM25 sparse indices...
python -m securag.retrieval.bm25
echo.
echo [5/5] Embedding & Indexing into Pinecone...
python -m securag.ingest.embed_index
echo.
echo [OK] Full ingestion pipeline complete.
pause
goto :menu

:download_models
echo.
echo [*] Pre-downloading and validating ML models...
call .venv\Scripts\activate.bat && python scripts\download_models.py
echo.
pause
goto :menu

:download_data
echo.
echo [*] Downloading public security datasets to data\raw...
powershell -ExecutionPolicy Bypass -File scripts\clone_data.ps1 -Years 2024,2025
echo.
pause
goto :menu

:run_tests
echo.
echo [*] Running full test suite...
call .venv\Scripts\activate.bat && python -m pytest tests\ -v
echo.
pause
goto :menu

:recompile_docs
echo.
echo [*] Recompiling Technical Documentation (PDF & HTML)...
call .venv\Scripts\activate.bat && python scripts\generate_pdf_docs.py
echo.
pause
goto :menu

:open_docs
echo.
if exist "docs\SecuRAG_Documentation.pdf" (
    echo [*] Opening docs\SecuRAG_Documentation.pdf in default viewer...
    start docs\SecuRAG_Documentation.pdf
) else (
    echo [!] PDF not found. Recompiling first...
    call .venv\Scripts\activate.bat && python scripts\generate_pdf_docs.py
    if exist "docs\SecuRAG_Documentation.pdf" (
        start docs\SecuRAG_Documentation.pdf
    )
)
goto :menu

:exit
echo.
echo Exiting SecuRAG. Goodbye!
exit /b 0
