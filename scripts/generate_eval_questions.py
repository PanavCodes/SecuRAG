"""Generate data/eval/questions.jsonl containing >=60 questions across all tiers with verified Neo4j ground-truth."""

import json
from pathlib import Path
from securag.clients import get_neo4j_driver

dev_path = Path("data/eval/dev.jsonl")
output_path = Path("data/eval/questions.jsonl")

questions = []

# 1. Load initial 20 questions from dev.jsonl
if dev_path.exists():
    with dev_path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                questions.append(json.loads(line))

print(f"Loaded {len(questions)} base questions from dev.jsonl")

driver = get_neo4j_driver()

with driver.session() as s:
    # 2. Generate 10 additional Tier 1 questions (q021 - q030)
    print("Generating additional Tier 1 questions...")
    # Single-hop: Techniques
    res_t = s.run("MATCH (t:Technique) WHERE t.description IS NOT NULL RETURN t.id AS id, t.name AS name LIMIT 5").data()
    for idx, r in enumerate(res_t, 21):
        questions.append({
            "id": f"q{idx:03d}",
            "tier": 1,
            "question": f"What is the name and purpose of ATT&CK technique {r['id']}?",
            "gold_answer": f"{r['name']}",
            "gold_entities": [r['id']],
            "gold_path": [r['id']],
            "source_check": f"Verified from Technique {r['id']} in Neo4j",
        })

    # Single-hop: Mitigations
    res_m = s.run("MATCH (m:Mitigation) WHERE m.description IS NOT NULL RETURN m.id AS id, m.name AS name LIMIT 5").data()
    for idx, r in enumerate(res_m, 26):
        questions.append({
            "id": f"q{idx:03d}",
            "tier": 1,
            "question": f"What mitigation strategy is represented by {r['id']}?",
            "gold_answer": f"{r['name']}",
            "gold_entities": [r['id']],
            "gold_path": [r['id']],
            "source_check": f"Verified from Mitigation {r['id']} in Neo4j",
        })

    # 3. Generate 15 additional Tier 2 questions (q031 - q045)
    print("Generating additional Tier 2 questions...")
    # 2-hop: Technique -> Tactic
    res_tt = s.run("MATCH (t:Technique)-[:IN_TACTIC]->(ta:Tactic) RETURN t.id AS tid, t.name AS tname, ta.id AS taid, ta.name AS taname SKIP 2 LIMIT 5").data()
    for idx, r in enumerate(res_tt, 31):
        questions.append({
            "id": f"q{idx:03d}",
            "tier": 2,
            "question": f"Which tactic does ATT&CK technique {r['tid']} ({r['tname']}) fall under?",
            "gold_answer": f"{r['taid']} ({r['taname']})",
            "gold_entities": [r['tid'], r['taid']],
            "gold_path": [r['tid'], r['taid']],
            "source_check": f"Verified from (t:Technique)-[:IN_TACTIC]->(ta:Tactic) in Neo4j",
        })

    # 2-hop: Mitigation -> Technique
    res_mt = s.run("MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique) RETURN m.id AS mid, m.name AS mname, t.id AS tid, t.name AS tname LIMIT 5").data()
    for idx, r in enumerate(res_mt, 36):
        questions.append({
            "id": f"q{idx:03d}",
            "tier": 2,
            "question": f"Which technique does mitigation {r['mid']} ({r['mname']}) mitigate?",
            "gold_answer": f"{r['tid']} ({r['tname']})",
            "gold_entities": [r['mid'], r['tid']],
            "gold_path": [r['mid'], r['tid']],
            "source_check": f"Verified from (m:Mitigation)-[:MITIGATES]->(t:Technique) in Neo4j",
        })

    # 2-hop: CWE -> Parent CWE
    res_cwe = s.run("MATCH (w:CWE)-[:CHILD_OF]->(p:CWE) RETURN w.id AS wid, w.name AS wname, p.id AS pid, p.name AS pname SKIP 5 LIMIT 5").data()
    for idx, r in enumerate(res_cwe, 41):
        questions.append({
            "id": f"q{idx:03d}",
            "tier": 2,
            "question": f"What is the direct parent weakness of {r['wid']} ({r['wname']})?",
            "gold_answer": f"{r['pid']} ({r['pname']})",
            "gold_entities": [r['wid'], r['pid']],
            "gold_path": [r['wid'], r['pid']],
            "source_check": f"Verified from (w:CWE)-[:CHILD_OF]->(p:CWE) in Neo4j",
        })

    # 4. Generate 15 additional Tier 3 questions (q046 - q060)
    print("Generating additional Tier 3 questions...")
    # Full multi-hop attack chains: CVE -> CWE -> CAPEC -> Technique -> Tactic
    res_chain = s.run("""
        MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:CWE)-[:RELATED_ATTACK_PATTERN]->(p:CAPEC)-[:RELATED_TECHNIQUE]->(t:Technique)-[:IN_TACTIC]->(ta:Tactic)
        RETURN c.id AS cve, w.id AS cwe, p.id AS capec, t.id AS tech, t.name AS tech_name, ta.id AS tactic_id, ta.name AS tactic_name
        SKIP 2 LIMIT 15
    """).data()
    for idx, r in enumerate(res_chain, 46):
        questions.append({
            "id": f"q{idx:03d}",
            "tier": 3,
            "question": f"Trace the complete attack path from vulnerability {r['cve']} to an ATT&CK technique and tactic.",
            "gold_answer": f"{r['cve']} links to weakness {r['cwe']}, attack pattern {r['capec']}, technique {r['tech']} ({r['tech_name']}), and tactic {r['tactic_id']} ({r['tactic_name']}).",
            "gold_entities": [r['cve'], r['cwe'], r['capec'], r['tech']],
            "gold_path": [r['cve'], r['cwe'], r['capec'], r['tech'], r['tactic_id']],
            "source_check": "Verified from 5-hop attack path query in Neo4j",
        })

# 5. Add 5 additional Out-of-KB questions (q061 - q065)
print("Adding out-of-KB questions...")
out_of_kb_qs = [
    ("q061", "What is the boiling point of liquid nitrogen at sea level?"),
    ("q062", "Who painted the famous artwork Starry Night?"),
    ("q063", "What is the capital city of Japan?"),
    ("q064", "How many kilometers are in a standard marathon?"),
    ("q065", "What is the chemical formula for photosynthesis?"),
]
for qid, qtext in out_of_kb_qs:
    questions.append({
        "id": qid,
        "tier": 1,
        "question": qtext,
        "gold_answer": "NOT_IN_KB",
        "gold_entities": [],
        "gold_path": [],
        "source_check": "Out of domain general knowledge question",
    })

# Write to questions.jsonl
with output_path.open("w", encoding="utf-8") as f:
    for q in questions:
        f.write(json.dumps(q) + "\n")

print(f"Successfully generated {len(questions)} evaluation questions in {output_path}")
