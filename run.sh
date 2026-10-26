#!/usr/bin/env bash

# SecuRAG Linux/macOS Launcher

show_menu() {
    clear
    echo "======================================================================"
    echo "   SecuRAG - Interactive Launcher (Linux / macOS)"
    echo "   Agentic Hybrid GraphRAG for CVE / Threat-Intel Triage"
    echo "======================================================================"
    echo ""
    echo "  [1] Launch Full Stack (FastAPI Backend + Streamlit UI)"
    echo "  [2] Launch Streamlit UI Dashboard Only (http://localhost:8501)"
    echo "  [3] Launch FastAPI Service (Swagger docs at http://127.0.0.1:8000/docs)"
    echo "  [4] Run Infrastructure Healthcheck (scripts/healthcheck.py)"
    echo "  [5] Run Full Ingestion & Graph Loader"
    echo "  [6] Pre-download ML Models"
    echo "  [7] Download Raw Security Datasets"
    echo "  [8] Run Acceptance Tests (pytest)"
    echo "  [9] Recompile Technical Documentation (PDF & HTML)"
    echo "  [0] Exit"
    echo ""
}

if [ ! -f ".venv/bin/activate" ]; then
    echo "[!] Virtual environment not found. Running setup.sh..."
    bash setup.sh
fi

source .venv/bin/activate

while true; do
    show_menu
    read -p "Enter choice [0-9] (default=1): " CHOICE
    CHOICE=${CHOICE:-1}

    case "$CHOICE" in
        1)
            echo "Starting Neo4j container..."
            docker compose up -d 2>/dev/null || true
            echo "Starting FastAPI in background..."
            uvicorn securag.api.main:app --host 127.0.0.1 --port 8000 --reload &
            API_PID=$!
            sleep 2
            echo "Launching Streamlit UI..."
            streamlit run src/securag/ui/app.py --server.port 8501
            kill $API_PID 2>/dev/null || true
            ;;
        2)
            streamlit run src/securag/ui/app.py --server.port 8501
            ;;
        3)
            uvicorn securag.api.main:app --host 127.0.0.1 --port 8000 --reload
            ;;
        4)
            python scripts/healthcheck.py
            read -p "Press Enter to continue..."
            ;;
        5)
            python -m securag.ingest.parsers.cve
            python -m securag.ingest.parsers.kev
            python -m securag.ingest.parsers.cwe
            python -m securag.ingest.parsers.capec
            python -m securag.ingest.parsers.attack
            python -m securag.graph.load
            python -m securag.ingest.chunk
            python -m securag.retrieval.bm25
            python -m securag.ingest.embed_index
            read -p "Press Enter to continue..."
            ;;
        6)
            python scripts/download_models.py
            read -p "Press Enter to continue..."
            ;;
        7)
            bash scripts/clone_data.sh 2024,2025
            read -p "Press Enter to continue..."
            ;;
        8)
            pytest tests/ -v
            read -p "Press Enter to continue..."
            ;;
        9)
            python scripts/generate_pdf_docs.py
            read -p "Press Enter to continue..."
            ;;
        0)
            echo "Exiting SecuRAG."
            exit 0
            ;;
        *)
            echo "Invalid choice: $CHOICE"
            sleep 1
            ;;
    esac
done
