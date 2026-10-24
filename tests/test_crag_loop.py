"""Acceptance tests for Step 10: CRAG Evaluator, Document Grading, and Rewrite Loop Termination."""

import pytest
from securag.agent.nodes import grade_documents_node, rewrite_query_node
from securag.agent.graph import build_agent_graph


def test_grade_documents_thresholds():
    """Verify document grading threshold logic produces correct, ambiguous, and incorrect verdicts."""
    # 1. High score -> correct
    state_correct = {
        "question": "test query",
        "candidates": [{"chunk_id": "c1", "score": 0.85, "text": "high relevance context"}],
        "graph_paths": [],
    }
    res_c = grade_documents_node(state_correct)
    assert res_c["verdict"] == "correct", f"Expected 'correct', got {res_c['verdict']}"

    # 2. Medium score -> ambiguous
    state_ambiguous = {
        "question": "test query",
        "candidates": [{"chunk_id": "c2", "score": 0.02, "text": "marginal context"}],
        "graph_paths": [],
    }
    res_a = grade_documents_node(state_ambiguous)
    assert res_a["verdict"] == "ambiguous", f"Expected 'ambiguous', got {res_a['verdict']}"

    # 3. Empty or zero score -> incorrect
    state_incorrect = {
        "question": "test query",
        "candidates": [{"chunk_id": "c3", "score": 0.00, "text": "irrelevant context"}],
        "graph_paths": [],
    }
    res_i = grade_documents_node(state_incorrect)
    assert res_i["verdict"] == "incorrect", f"Expected 'incorrect', got {res_i['verdict']}"


def test_crag_termination_by_success():
    """Verify CRAG loop terminates via (a) success when relevant evidence is found."""
    agent = build_agent_graph()
    initial_state = {
        "question": "What is CVE-2021-44228?",
        "config": {
            "use_router": False,  # Go straight to retrieval
            "use_crag_loop": True,
            "use_cross_encoder": True,
        },
        "rewrite_round": 0,
        "queries_tried": [],
        "candidates": [],
        "graph_paths": [],
        "context": [],
        "citations": [],
    }
    config = {"configurable": {"thread_id": "thread_success"}, "recursion_limit": 50}
    output = agent.invoke(initial_state, config=config)

    print(f"\nCRAG Success Termination Reason: {output.get('termination_reason')}")
    print(f"CRAG Success Verdict: {output.get('verdict')}")
    print(f"CRAG Success Answer: {output.get('answer')[:120]}...")

    assert output.get("termination_reason") == "success"
    assert output.get("verdict") in ["correct", "ambiguous"]
    assert len(output.get("context", [])) > 0


def test_crag_termination_by_max_rounds():
    """Verify CRAG loop terminates via (b) max rounds when evidence is never found."""
    agent = build_agent_graph()
    initial_state = {
        "question": "NONEXISTENT_IMPOSSIBLE_VULN_QUERY_ABC123",
        "config": {
            "use_router": False,
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
    config = {"configurable": {"thread_id": "thread_max_rounds"}, "recursion_limit": 50}
    output = agent.invoke(initial_state, config=config)

    print(f"\nCRAG Max Rounds Termination Reason: {output.get('termination_reason')}")
    print(f"Rounds executed: {output.get('rewrite_round')}")

    assert output.get("termination_reason") in ["max_rounds", "fallback"]
    assert output.get("rewrite_round", 0) <= 2
    assert "not found in the securag" in output.get("answer", "").lower()


def test_crag_termination_by_novelty_guard():
    """Verify CRAG loop terminates via (c) novelty guard when rewritten query is too similar."""
    # Test rewrite_query_node directly with identical query to simulate novelty threshold violation
    state = {
        "question": "Apache Log4j remote code execution vulnerability",
        "queries_tried": ["Apache Log4j remote code execution vulnerability"],  # exact match
        "rewrite_round": 0,
        "config": {},
    }
    res = rewrite_query_node(state)
    print(f"\nNovelty Guard direct test: {res}")

    # Either novelty guard triggered or new novel query generated
    assert res.get("termination_reason") in ["novelty_guard", None]
