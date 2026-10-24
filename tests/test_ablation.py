"""Acceptance test for Step 13: Evaluation and Ablation across Configs A through G."""

import csv
import json
from pathlib import Path
import pytest

from securag.eval.run_ablation import run_ablation, CONFIGS


def test_questions_file_has_at_least_60_items():
    """Verify data/eval/questions.jsonl contains >= 60 questions across all tiers.

    Mandated by Step 13: 'finish the question set (Section 8) to >=60 questions.'
    """
    q_path = Path("data/eval/questions.jsonl")
    assert q_path.exists(), "data/eval/questions.jsonl does not exist"

    questions = []
    with q_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                questions.append(json.loads(line))

    assert len(questions) >= 60, f"Expected >= 60 questions, got {len(questions)}"

    # Check tier diversity
    tiers = {q.get("tier") for q in questions}
    assert 1 in tiers, "Tier 1 questions missing"
    assert 2 in tiers, "Tier 2 questions missing"
    assert 3 in tiers, "Tier 3 questions missing"

    # Check out-of-KB presence
    out_of_kb = [q for q in questions if q.get("gold_answer") == "NOT_IN_KB"]
    assert len(out_of_kb) >= 5, f"Expected >= 5 out-of-KB questions, got {len(out_of_kb)}"

    print(f"\nVerified questions.jsonl: {len(questions)} total questions across Tiers 1, 2, 3 and {len(out_of_kb)} out-of-KB items.")


def test_run_ablation_and_verify_outputs():
    """Run ablation study across Configs A-G, verify results/ablation.md and results/failures.md.

    Mandated by Step 13:
    'results/ablation.md table exists with all 7 configs x all metrics. No empty cells.
    Include a Failure analysis file results/failures.md listing >= 10 wrong answers with cause.'
    """
    # Run ablation on representative sample across tiers
    run_ablation(questions_path="data/eval/questions.jsonl", sample_size=8, output_dir="results")

    # 1. Verify results/ablation.csv
    csv_path = Path("results/ablation.csv")
    assert csv_path.exists(), "results/ablation.csv does not exist"

    rows = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)

    assert len(rows) == 7, f"Expected 7 config rows in ablation.csv, got {len(rows)}"

    # 2. Verify results/ablation.md
    md_path = Path("results/ablation.md")
    assert md_path.exists(), "results/ablation.md does not exist"
    md_content = md_path.read_text(encoding="utf-8")

    # Check each config appears in markdown table
    for cfg in CONFIGS.keys():
        assert cfg in md_content, f"Config '{cfg}' missing from ablation.md"

    # Check required metrics columns exist
    metrics_cols = [
        "Context Recall",
        "Context Precision",
        "Faithfulness",
        "Relevancy",
        "Tier 1 Acc",
        "Tier 2 Acc",
        "Tier 3 Acc",
        "Multi-Hop F1",
        "Latency",
    ]
    for col in metrics_cols:
        assert col in md_content, f"Metric column '{col}' missing from ablation.md table"

    # Check no empty cells in table rows
    for line in md_content.splitlines():
        if line.startswith("| **Config"):
            cells = [c.strip() for c in line.split("|")[1:-1]]
            for cell in cells:
                assert len(cell) > 0, f"Found empty table cell in ablation.md row: {line}"

    # 3. Verify results/failures.md (>= 10 failures)
    fail_path = Path("results/failures.md")
    assert fail_path.exists(), "results/failures.md does not exist"
    fail_content = fail_path.read_text(encoding="utf-8")

    # Check at least 10 failure cases
    case_count = len([line for line in fail_content.splitlines() if line.startswith("### Case ")])
    assert case_count >= 10, f"Expected >= 10 failure cases in failures.md, got {case_count}"

    # Check failure causes are documented
    causes = ["retrieval miss", "wrong graph path", "evaluator error", "generation error"]
    found_causes = sum(1 for c in causes if c in fail_content)
    assert found_causes >= 3, f"Expected diverse failure categories in failures.md, found {found_causes}"

    print(f"\nStep 13 Acceptance PASSED: 7 configs x all metrics verified in ablation.md. {case_count} failure cases in failures.md.")
