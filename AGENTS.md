# AGENTS.md — SecuRAG

Project: agentic hybrid GraphRAG for CVE / threat-intel triage (LangGraph + Neo4j + Pinecone).
This file is read by Claude Code (via CLAUDE.md), Antigravity and other agent tools.

## Read order (do this first, every session)
1. `docs/build.md` — what we build, papers, repo list.
2. `docs/build_agent.md` — the binding spec: DB schemas, field mappings, Steps 0-15 with acceptance tests, state/node contracts, flags.
3. `NOTES.md` — running log of assumptions and blockers (create it in Step 0 if missing).
If `docs/build_agent.md` and `docs/build.md` disagree, `build_agent.md` wins.

## How to work
- Follow Steps 0-15 of `docs/build_agent.md` in order. Do not start step N+1 until step N's acceptance test passes. Print the test output.
- One git commit per step: `step-N: <title>`.
- Read a real sample of each data file before writing its parser. Never invent field names or library APIs; check the installed version.
- Re-implement logic from `third_party/` in `src/securag/` with a header comment (source repo, commit hash, license). Never import from `third_party/`.
- Every pipeline component is behind a config flag (see Section 7 of build_agent.md). Ablation depends on it.
- If a step fails its acceptance test after 3 honest attempts, stop and write the blocker in `NOTES.md`. Do not fake results, stub the test, or hardcode answers.

## Hard rules
- No secrets in code or git. Use `.env` (copy from `.env.example`).
- No RL training in v1. Router is LLM-based. Do not claim features that are not built.
- GraphER has no public code: implement from arXiv 2603.24925 and document every simplification in `NOTES.md`.
- Every Cypher query must have a `LIMIT`.
- Every cited ID in an answer must exist in Neo4j (validator required).
- Do not delete the Pinecone index, Neo4j data, or `data/raw/` without being told.
- Do not run `pip install` of anything outside `requirements.txt` without noting it in `NOTES.md`.

## Environment
- Python venv at `.venv` (3.12 recommended, 3.11 ok, not 3.13). Windows: use the `.ps1` scripts in `scripts/`. macOS/Linux: the `.sh` scripts.
- PyTorch is installed separately before `requirements.txt` (see `SETUP.md`).
- Neo4j: `docker compose up -d`. Pinecone: cloud, key in `.env`.
- Sizing: `DATA_YEARS` and `CVE_MAX` in `.env` limit the CVE slice (default 2024,2025 and 20000).

## Commands
- Start Neo4j: `docker compose up -d`
- Tests: `pytest -q`
- Health check (after Step 1): `python scripts/healthcheck.py`
- API (after Step 14): `uvicorn securag.api.main:app --reload`
- UI (after Step 14): `streamlit run src/securag/ui/app.py`
