"""Acceptance tests for Step 14: FastAPI Service and Streamlit UI."""

import py_compile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from securag.api.main import app
from securag.ui.app import format_graph_path


@pytest.fixture(scope="module")
def client():
    """Create FastAPI test client."""
    return TestClient(app)


def test_health_and_config_endpoints(client):
    """Verify /health and /config endpoints return 200 OK and valid schemas."""
    # Health endpoint
    res_health = client.get("/health")
    assert res_health.status_code == 200
    data_health = res_health.json()
    assert data_health["status"] == "healthy"
    assert data_health["neo4j"] is True
    assert "version" in data_health

    # Config endpoint
    res_config = client.get("/config")
    assert res_config.status_code == 200
    data_config = res_config.json()
    expected_flags = [
        "use_bm25",
        "use_cross_encoder",
        "use_graph_retrieval",
        "use_graph_rerank",
        "use_crag_loop",
        "use_router",
        "use_reflection",
        "use_query_expansion",
        "use_hyde",
    ]
    for flag in expected_flags:
        assert flag in data_config, f"Missing expected flag: {flag}"


def test_ask_simple_route(client):
    """Verify POST /ask handles single-hop simple route."""
    req_body = {
        "question": "What is the CVSS score and severity for CVE-2024-23111?",
    }
    response = client.post("/ask", json=req_body)
    assert response.status_code == 200, f"Error {response.status_code}: {response.text}"
    
    data = response.json()
    assert "answer" in data and len(data["answer"]) > 0
    assert "citations" in data
    assert "route" in data
    assert data["route"] == "simple"
    assert "latency_ms" in data and data["latency_ms"] > 0
    assert "rounds" in data


def test_ask_out_of_kb_route(client):
    """Verify POST /ask handles out_of_kb route with fast fallback."""
    req_body = {
        "question": "What is the best recipe for baking sourdough bread?",
    }
    response = client.post("/ask", json=req_body)
    assert response.status_code == 200, f"Error {response.status_code}: {response.text}"

    data = response.json()
    assert "answer" in data
    assert data["route"] == "out_of_kb"
    assert "knowledge base" in data["answer"].lower() or "not found" in data["answer"].lower()


def test_ask_multi_hop_route(client):
    """Verify POST /ask handles multi_hop route with graph traversal."""
    req_body = {
        "question": "Which tactic does ATT&CK technique T1021 belong to?",
    }
    response = client.post("/ask", json=req_body)
    assert response.status_code == 200, f"Error {response.status_code}: {response.text}"

    data = response.json()
    assert "answer" in data and len(data["answer"]) > 0
    assert data["route"] == "multi_hop"
    assert "citations" in data
    assert "graph_paths" in data
    # Verified ground truth: T1021 is Remote Services in Lateral Movement (TA0008)
    assert any("T1021" in c or "TA0008" in c for c in data["citations"]) or "lateral movement" in data["answer"].lower()


def test_streamlit_app_syntax_and_components():
    """Verify Streamlit UI app.py compiles cleanly and helper functions execute."""
    ui_path = Path("src/securag/ui/app.py")
    assert ui_path.exists(), "src/securag/ui/app.py does not exist"

    # Verify python syntax compiles without errors
    py_compile.compile(str(ui_path), doraise=True)

    # Test graph path formatter
    dummy_path = {
        "nodes": [
            {"id": "CVE-2024-22334", "labels": ["CVE"]},
            {"id": "CWE-732", "labels": ["CWE"]},
            {"id": "CAPEC-1", "labels": ["CAPEC"]},
        ],
        "rels": ["HAS_WEAKNESS", "RELATED_ATTACK_PATTERN"],
    }
    formatted = format_graph_path(dummy_path)
    assert "(CVE:CVE-2024-22334)" in formatted
    assert "──[HAS_WEAKNESS]──▶" in formatted
    assert "(CAPEC:CAPEC-1)" in formatted
