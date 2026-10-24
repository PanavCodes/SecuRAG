"""Acceptance tests for Step 11: Generation with citations and Neo4j citation validation."""

import json
from pathlib import Path
import pytest

from securag.agent.graph import build_agent_graph
from securag.eval.citation_validator import validate_citations_against_neo4j


@pytest.fixture(scope="module")
def agent():
    return build_agent_graph()


def test_ten_sample_questions_citations_and_neo4j_existence(agent):
    """Verify 10 sample questions each produce >=1 citation and all cited IDs exist in Neo4j.

    Mandated by Step 11 acceptance criteria and hard rule in AGENTS.md:
    'Every cited ID in an answer must exist in Neo4j (validator required).'
    """
    dev_path = Path("data/eval/dev.jsonl")
    assert dev_path.exists(), "dev.jsonl not found"

    questions = []
    with dev_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                questions.append(json.loads(line))

    # Select 10 answerable questions from dev set
    sample_10 = [q for q in questions if q.get("gold_answer") != "NOT_IN_KB"][:10]
    assert len(sample_10) == 10, f"Expected 10 sample questions, found {len(sample_10)}"

    print(f"\n--- Testing Generation & Citation Verification across 10 Sample Questions ---")

    for idx, q in enumerate(sample_10, 1):
        q_text = q["question"]
        initial_state = {
            "question": q_text,
            "config": {
                "use_router": True,
                "use_crag_loop": True,
                "use_reflection": True,
                "use_cross_encoder": True,
                "use_graph_retrieval": True,
                "use_graph_rerank": True,
            },
            "rewrite_round": 0,
            "queries_tried": [],
            "candidates": [],
            "graph_paths": [],
            "context": [],
            "citations": [],
        }
        config = {"configurable": {"thread_id": f"test_gen_q{idx}"}, "recursion_limit": 50}
        out = agent.invoke(initial_state, config=config)

        answer = out.get("answer", "")
        citations = out.get("citations", [])

        print(f"\n[{idx}/10] Question: {q_text}", flush=True)
        print(f"       Answer  : {answer[:140]}...", flush=True)
        print(f"       Citations: {citations}", flush=True)

        # Check 1: Answer must not be empty
        assert len(answer) > 0, f"Question {q['id']} produced an empty answer"

        # Check 2: Every answer must contain >= 1 citation
        assert len(citations) >= 1, f"Question {q['id']} produced 0 citations: '{answer}'"

        # Check 3: Every cited ID must exist in Neo4j
        val_res = validate_citations_against_neo4j(citations)
        print(f"       Validation: all_valid={val_res['all_valid']}, invalid={val_res['invalid_citations']}", flush=True)
        assert val_res["all_valid"], (
            f"Question {q['id']} cited non-existent IDs in Neo4j: {val_res['invalid_citations']}"
        )

    print("\n----------------------------------------------------------------------------")
    print("All 10 questions successfully produced >=1 citation and all cited IDs exist in Neo4j.")
