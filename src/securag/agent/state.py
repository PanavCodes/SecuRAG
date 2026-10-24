"""Agent state definition for LangGraph SecuRAG triage pipeline."""

from typing import TypedDict, Literal, Any


class AgentState(TypedDict):
    """SecuRAG graph state schema per Section 6 of build_agent.md."""

    question: str
    route: Literal["simple", "multi_hop", "out_of_kb"] | None
    sub_questions: list[str]
    queries_tried: list[str]
    rewrite_round: int
    candidates: list[dict[str, Any]]  # {chunk_id, text, source_id, source_type, score, via}
    graph_paths: list[dict[str, Any]]  # {nodes: [...], rels: [...]}
    graded: list[dict[str, Any]]  # candidate + relevance score
    verdict: Literal["correct", "ambiguous", "incorrect"] | None
    context: list[dict[str, Any]]  # refined passages passed to generation
    answer: str | None
    citations: list[str]
    reflection: dict[str, Any] | None  # {faithful: bool, unsupported_claims: [...]}
    config: dict[str, Any]  # active feature flags
    metrics: dict[str, Any]  # per-node latency, tokens
    termination_reason: str | None  # 'success', 'max_rounds', 'novelty_guard', 'out_of_kb'
