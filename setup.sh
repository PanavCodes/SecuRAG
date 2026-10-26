#!/usr/bin/env bash
set -e

echo "======================================================================"
echo "   SecuRAG - Automated Linux / macOS Environment Setup"
echo "   Agentic Hybrid GraphRAG for CVE / Threat-Intel Triage"
echo "======================================================================"
echo ""

# 1. Detect Python
echo "[1/8] Checking Python installation..."
PYTHON_CMD=""
for cmd in python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
        VERSION=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if [[ "$VERSION" == "3.11" || "$VERSION" == "3.12" ]]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "[ERROR] Python 3.12 or 3.11 is required (found none matching)."
    exit 1
fi
echo "[OK] Using $PYTHON_CMD ($($PYTHON_CMD --version))"
echo ""

# 2. Setup Virtual Environment
echo "[2/8] Setting up virtual environment in .venv..."
if [ ! -d ".venv" ]; then
    $PYTHON_CMD -m venv .venv
    echo "[OK] Virtual environment created."
else
    echo "[OK] Existing .venv found."
fi
echo ""

# 3. Activate venv
echo "[3/8] Activating virtual environment..."
source .venv/bin/activate
echo "[OK] Activated .venv"
echo ""

# 4. Upgrade pip
echo "[4/8] Upgrading pip..."
pip install --upgrade pip --quiet
echo "[OK] Pip upgraded."
echo ""

# 5. Install Dependencies
echo "[5/8] Installing dependencies..."
pip install -r requirements.txt || pip install -r requirements-loose.txt
pip install -e . --no-deps
echo "[OK] Dependencies installed."
echo ""

# 6. Pre-download Models
echo "[6/8] Pre-downloading Hugging Face ML models..."
python scripts/download_models.py || echo "[WARNING] Models can be downloaded on first run."
echo ""

# 7. Check Data
echo "[7/8] Checking security datasets (data/raw)..."
if [ ! -d "data/raw/cvelistV5" ]; then
    echo "Cloning raw datasets..."
    bash scripts/clone_data.sh 2024,2025
else
    echo "[OK] Security datasets found in data/raw."
fi
echo ""

# 8. Environment Configuration
echo "[8/8] Checking configuration (.env)..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "[IMPORTANT] Created .env file. Please populate your API keys!"
    fi
else
    echo "[OK] Existing .env file found."
fi
echo ""

echo "======================================================================"
echo "  SecuRAG Setup Complete! Run 'docker compose up -d' then './run.sh'"
echo "======================================================================"
