"""SecuRAG Interactive Streamlit Dashboard for CVE and Threat-Intel Triage."""

import json
import logging
import time
import uuid
import requests
import streamlit as st

from securag.agent.graph import get_agent
from securag.config import get_settings

logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="SecuRAG — Agentic Hybrid GraphRAG",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for rich cyber-security aesthetic
st.markdown(
    """
    <style>
    /* Global styling */
    .stApp {
        background-color: #0b0f19;
        color: #e6edf3;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Header card */
    .header-box {
        background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    
    .header-title {
        font-size: 2rem;
        font-weight: 700;
        background: linear-gradient(90deg, #60a5fa, #a78bfa, #34d399);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    
    .header-sub {
        color: #9ca3af;
        font-size: 0.95rem;
        margin-top: 6px;
    }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-right: 8px;
    }
    .badge-simple {
        background-color: rgba(16, 185, 129, 0.2);
        color: #34d399;
        border: 1px solid #059669;
    }
    .badge-multihop {
        background-color: rgba(139, 92, 246, 0.2);
        color: #c084fc;
        border: 1px solid #7c3aed;
    }
    .badge-outofkb {
        background-color: rgba(245, 158, 11, 0.2);
        color: #fbbf24;
        border: 1px solid #d97706;
    }
    .badge-metric {
        background-color: rgba(75, 85, 99, 0.3);
        color: #d1d5db;
        border: 1px solid #4b5563;
    }

    /* Answer box */
    .answer-box {
        background: #111827;
        border: 1px solid #1f2937;
        border-left: 4px solid #3b82f6;
        border-radius: 8px;
        padding: 20px;
        margin-top: 16px;
        margin-bottom: 24px;
        line-height: 1.6;
    }

    /* Graph path node */
    .graph-path {
        background: #182234;
        border: 1px solid #2e3d55;
        border-radius: 6px;
        padding: 10px 14px;
        margin-bottom: 8px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.88rem;
        color: #93c5fd;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def format_graph_path(path_dict: dict) -> str:
    """Format Neo4j path dictionary into a readable directed chain."""
    nodes = path_dict.get("nodes", [])
    rels = path_dict.get("rels", [])
    if not nodes:
        raw_path = path_dict.get("path", [])
        if raw_path:
            return " ➔ ".join(str(item) for item in raw_path if item is not None)
        return "Direct Entity Link"

    parts = []
    for i, node in enumerate(nodes):
        node_name = node.get("name") or node.get("id") or "Node"
        node_type = node.get("labels", ["Entity"])[0] if node.get("labels") else "Node"
        parts.append(f"({node_type}:{node_name})")
        if i < len(rels):
            parts.append(f"──[{rels[i]}]──▶")

    return " ".join(parts)


# --- Sidebar: Configuration & Presets ---
with st.sidebar:
    st.markdown("### ⚙️ Pipeline Configuration")
    st.caption("Ablation toggles defined in Section 7 of `build_agent.md`")

    use_bm25 = st.toggle("BM25 Hybrid Fusion", value=True, help="Dense BGE-M3 + BM25 RRF fusion")
    use_cross_encoder = st.toggle("Cross-Encoder Reranker", value=True, help="Neural rerank via bge-reranker-v2-m3")
    use_graph_retrieval = st.toggle("Neo4j Graph Retrieval", value=True, help="Relational graph traversals")
    use_graph_rerank = st.toggle("GraphER Topological Smoothing", value=True, help="arXiv:2603.24925 neighbor smoothing")
    use_crag_loop = st.toggle("CRAG Document Grading & Rewrite", value=True, help="Document quality grading & rewrite loop")
    use_router = st.toggle("Dynamic Query Router", value=True, help="LLM router (simple / multi_hop / out_of_kb)")
    use_reflection = st.toggle("Self-Reflection & Citation Verification", value=True, help="Hallucination check & citation validation")
    use_query_expansion = st.toggle("Query Expansion", value=False, help="LLM sub-query decomposition")
    use_hyde = st.toggle("HyDE", value=False, help="Hypothetical Document Embeddings")

    st.markdown("---")
    execution_mode = st.radio(
        "Backend Execution Mode",
        ["Direct Engine (In-Process)", "FastAPI Service (http://localhost:8000)"],
        index=0,
    )

    st.markdown("---")
    st.markdown("### 🎯 Quick Demo Queries")
    demo_type = st.selectbox(
        "Select benchmark question:",
        [
            "— Choose a demo question —",
            "[Simple] CVE-2024-23111 CVSS & Severity",
            "[Simple] CWE-79 Weakness Description",
            "[Multi-Hop] CVE-2024-22334 Full Attack Chain",
            "[Multi-Hop] T1021 Technique Tactic",
            "[Multi-Hop] CVE-2021-44228 Log4j Weaknesses",
            "[Out-of-KB] Recipe for Sourdough Bread",
            "[Out-of-KB] Fictional CVE-1980-99999",
        ],
    )

    preset_map = {
        "[Simple] CVE-2024-23111 CVSS & Severity": "What is the CVSS score and severity for CVE-2024-23111?",
        "[Simple] CWE-79 Weakness Description": "What weakness is identified by CWE-79?",
        "[Multi-Hop] CVE-2024-22334 Full Attack Chain": "Trace the full attack chain from CVE-2024-22334 to an ATT&CK technique.",
        "[Multi-Hop] T1021 Technique Tactic": "Which tactic does ATT&CK technique T1021 belong to?",
        "[Multi-Hop] CVE-2021-44228 Log4j Weaknesses": "Which weaknesses are associated with CVE-2021-44228?",
        "[Out-of-KB] Recipe for Sourdough Bread": "What is the best recipe for baking sourdough bread?",
        "[Out-of-KB] Fictional CVE-1980-99999": "What are the vulnerability details for CVE-1980-99999?",
    }

# --- Main Layout ---
st.markdown(
    """
    <div class="header-box">
        <h1 class="header-title">SecuRAG Threat-Intel Triage</h1>
        <div class="header-sub">
            Agentic Hybrid GraphRAG for CVE / Threat-Intel Triage • LangGraph + Neo4j + Pinecone + BGE-M3 + GraphER
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Text input
default_query = preset_map.get(demo_type, "")
query = st.text_area(
    "Enter your triage question:",
    value=default_query,
    height=90,
    placeholder="e.g. Trace the full attack chain from CVE-2024-22334 to an ATT&CK technique.",
)

col_btn, col_clear = st.columns([1, 8])
with col_btn:
    submitted = st.button("🚀 Triage Query", type="primary", use_container_width=True)

if submitted and query.strip():
    config_overrides = {
        "use_bm25": use_bm25,
        "use_cross_encoder": use_cross_encoder,
        "use_graph_retrieval": use_graph_retrieval,
        "use_graph_rerank": use_graph_rerank,
        "use_crag_loop": use_crag_loop,
        "use_router": use_router,
        "use_reflection": use_reflection,
        "use_query_expansion": use_query_expansion,
        "use_hyde": use_hyde,
    }

    with st.spinner("Analyzing threat intelligence and traversing graph..."):
        t0 = time.time()
        answer = None
        route = "simple"
        rounds = 0
        citations = []
        graph_paths = []
        context = []
        latency_ms = 0.0

        if execution_mode == "FastAPI Service (http://localhost:8000)":
            try:
                resp = requests.post(
                    "http://localhost:8000/ask",
                    json={"question": query.strip(), "config_overrides": config_overrides},
                    timeout=180,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    answer = data.get("answer")
                    route = data.get("route", "simple")
                    rounds = data.get("rounds", 0)
                    citations = data.get("citations", [])
                    graph_paths = data.get("graph_paths", [])
                    context = data.get("context", [])
                    latency_ms = data.get("latency_ms", (time.time() - t0) * 1000)
                else:
                    st.error(f"API Error ({resp.status_code}): {resp.text}")
            except Exception as exc:
                st.warning(f"Could not connect to FastAPI at http://localhost:8000 ({exc}). Falling back to Direct Engine.")
                execution_mode = "Direct Engine (In-Process)"

        if execution_mode == "Direct Engine (In-Process)":
            agent = get_agent()
            initial_state = {
                "question": query.strip(),
                "config": config_overrides,
                "rewrite_round": 0,
                "queries_tried": [],
                "candidates": [],
                "graph_paths": [],
                "context": [],
                "citations": [],
            }
            thread_id = f"ui_{uuid.uuid4().hex[:10]}"
            out = agent.invoke(
                initial_state,
                config={"configurable": {"thread_id": thread_id}, "recursion_limit": 50},
            )
            latency_ms = (time.time() - t0) * 1000.0
            answer = out.get("answer")
            route = out.get("route", "simple")
            rounds = out.get("rewrite_round", 0)
            citations = out.get("citations", [])
            graph_paths = out.get("graph_paths", [])
            context = out.get("context", [])

    # Display Badges
    route_class = (
        "badge-multihop"
        if route == "multi_hop"
        else ("badge-outofkb" if route == "out_of_kb" else "badge-simple")
    )
    route_label = (
        "🌐 Multi-Hop Route"
        if route == "multi_hop"
        else ("🛡️ Out-of-Domain Route" if route == "out_of_kb" else "⚡ Simple Route")
    )

    st.markdown(
        f"""
        <div style="margin-top: 10px; margin-bottom: 12px;">
            <span class="badge {route_class}">{route_label}</span>
            <span class="badge badge-metric">⏱️ {latency_ms / 1000:.2f}s Latency</span>
            <span class="badge badge-metric">🔄 {rounds} Rewrite Rounds</span>
            <span class="badge badge-metric">📚 {len(citations)} Validated Citations</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Generated Answer Display
    st.markdown("### 📝 Synthesized Triage Response")
    st.markdown(
        f"""
        <div class="answer-box">
            {answer}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Validated Citations
    if citations:
        st.markdown("#### 🔍 Validated Citations")
        citation_tags = " ".join([f"`[{c}]`" for c in citations])
        st.markdown(f"**Referenced Entities in Knowledge Base:** {citation_tags}")

    # Tabs for Inspection
    tab_graph, tab_sources, tab_debug = st.tabs(
        ["🕸️ Knowledge Graph Traversals", "📄 Source Evidence Chunks", "🛠️ Execution State"]
    )

    with tab_graph:
        if graph_paths:
            st.markdown(f"Found **{len(graph_paths)} relational path(s)** in Neo4j:")
            for idx, p in enumerate(graph_paths, 1):
                st.markdown(
                    f"""<div class="graph-path">{idx}. {format_graph_path(p)}</div>""",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No relational graph paths were traversed for this query route.")

    with tab_sources:
        if context:
            st.markdown(f"Top **{len(context)} retrieved & refined passage(s)**:")
            for idx, ctx in enumerate(context, 1):
                with st.expander(
                    f"#{idx} [{ctx.get('source_type', 'doc').upper()}] {ctx.get('source_id', 'Chunk')} (Score: {ctx.get('score', 0.0):.4f})"
                ):
                    st.write(ctx.get("text", "No text"))
                    st.caption(f"Chunk ID: `{ctx.get('chunk_id')}` | Retrieval via: `{ctx.get('via', 'hybrid')}`")
        else:
            st.info("No context chunks were retrieved (e.g. Out-of-Domain fallback).")

    with tab_debug:
        st.json(
            {
                "route": route,
                "rewrite_rounds": rounds,
                "citations": citations,
                "latency_ms": latency_ms,
                "config_flags": config_overrides,
                "graph_path_count": len(graph_paths),
                "context_chunk_count": len(context),
            }
        )
