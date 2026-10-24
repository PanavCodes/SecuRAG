"""Acceptance tests for Step 9: Agent routing, state contracts, and graph execution."""

import pytest
from securag.agent.nodes import route_query_node
from securag.agent.graph import build_agent_graph
from securag.config import get_settings


def test_route_simple():
    """Verify single-fact question routes to simple."""
    q = "What is the description of CVE-2021-44228?"
    state = {"question": q, "config": {"use_router": True}}
    res = route_query_node(state)
    print(f"\nSimple route result: {res['route']}")
    assert res["route"] == "simple", f"Expected 'simple', got '{res['route']}'"


def test_route_multihop():
    """Verify relational attack chain question routes to multi_hop."""
    q = "Trace the attack chain from CVE-2024-22334 to CWE-732 and find the linked ATT&CK technique."
    state = {"question": q, "config": {"use_router": True}}
    res = route_query_node(state)
    print(f"\nMulti-hop route result: {res['route']}")
    assert res["route"] == "multi_hop", f"Expected 'multi_hop', got '{res['route']}'"


def test_route_out_of_kb():
    """Verify unrelated question routes to out_of_kb."""
    q = "What is the weather in Paris today?"
    state = {"question": q, "config": {"use_router": True}}
    res = route_query_node(state)
    print(f"\nOut of KB route result: {res['route']}")
    assert res["route"] == "out_of_kb", f"Expected 'out_of_kb', got '{res['route']}'"


def test_end_to_end_out_of_kb_termination():
    """Verify out_of_kb question executes through graph and returns fallback answer."""
    agent = build_agent_graph()
    initial_state = {
        "question": "What is the capital of Australia?",
        "config": {"use_router": True, "use_crag_loop": True},
        "rewrite_round": 0,
        "queries_tried": [],
        "candidates": [],
        "graph_paths": [],
        "context": [],
        "citations": [],
    }
    config = {"configurable": {"thread_id": "test_thread_out_of_kb"}, "recursion_limit": 50}
    output = agent.invoke(initial_state, config=config)

    print(f"\nOut of KB Output Route: {output.get('route')}")
    print(f"Out of KB Output Answer: {output.get('answer')}")

    assert output.get("route") == "out_of_kb"
    assert "not found in the securag" in output.get("answer", "").lower()


def test_max_rewrite_rounds_termination():
    """Verify graph terminates within MAX_REWRITE_ROUNDS when candidates are unanswerable."""
    agent = build_agent_graph()
    settings = get_settings()

    # Query that returns 0 matching security data
    initial_state = {
        "question": "XYZ999NONEXISTENTVULN123456789",
        "config": {
            "use_router": False,  # Force into retrieval/evaluator loop
            "use_crag_loop": True,
            "max_rewrite_rounds": 2,
        },
        "rewrite_round": 0,
        "queries_tried": [],
        "candidates": [],
        "graph_paths": [],
        "context": [],
        "citations": [],
    }
    config = {"configurable": {"thread_id": "test_thread_termination"}, "recursion_limit": 50}
    output = agent.invoke(initial_state, config=config)

    print(f"\nRewrite rounds executed: {output.get('rewrite_round')}")
    print(f"Final answer: {output.get('answer')}")

    # Must terminate within configured max rewrite rounds (<= 2)
    assert output.get("rewrite_round", 0) <= 2
    assert output.get("answer") is not None
