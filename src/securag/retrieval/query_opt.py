"""Query optimization: expansion, HyDE (Hypothetical Document Embeddings), and metadata filter extraction."""

import json
import logging
import re
from typing import Any
from langchain_core.messages import SystemMessage, HumanMessage

from securag.clients import get_fast_llm

logger = logging.getLogger(__name__)

# Regular expressions for deterministic metadata extraction
YEAR_PATTERN = re.compile(r"\b(20\d{2})\b")
KEV_PATTERNS = [
    re.compile(r"in the wild", re.IGNORECASE),
    re.compile(r"actively exploited", re.IGNORECASE),
    re.compile(r"known exploited", re.IGNORECASE),
    re.compile(r"in kev", re.IGNORECASE),
]
SEVERITY_PATTERNS = {
    "CRITICAL": re.compile(r"\bcritical\b", re.IGNORECASE),
    "HIGH": re.compile(r"\bhigh(?:\s+severity)?\b", re.IGNORECASE),
    "MEDIUM": re.compile(r"\bmedium(?:\s+severity)?\b", re.IGNORECASE),
    "LOW": re.compile(r"\blow(?:\s+severity)?\b", re.IGNORECASE),
}


def extract_metadata_filters(query: str) -> dict[str, Any]:
    """Extract structured metadata filters (year, in_kev, severity) from user queries."""
    filters: dict[str, Any] = {}

    # 1. KEV flag
    for pat in KEV_PATTERNS:
        if pat.search(query):
            filters["in_kev"] = True
            break

    # 2. Year filter (if explicitly asking for a year like 'in 2024' or 'from 2021')
    year_match = re.search(r"(?:in|from|during|year)\s+(20\d{2})\b", query, re.IGNORECASE)
    if year_match:
        filters["year"] = int(year_match.group(1))

    # 3. Severity filter
    for sev, pat in SEVERITY_PATTERNS.items():
        if pat.search(query) and "severity" in query.lower():
            filters["severity"] = sev
            break

    return filters


def expand_query(query: str, n_variants: int = 3, llm: Any = None) -> list[str]:
    """Use fast LLM to expand query into n_variants alternative search queries."""
    model = llm or get_fast_llm()
    prompt = f"""You are a cybersecurity threat intelligence search assistant.
Generate {n_variants} distinct, high-quality search query variations for the following query:
"{query}"

Focus on:
1. Exact technical vulnerability names and aliases
2. Related weakness / attack pattern terms (CWE, CAPEC, MITRE ATT&CK)
3. Exploitation mechanisms and targeted protocols

Respond with ONLY a JSON array of strings, e.g. ["query 1", "query 2", "query 3"]."""

    try:
        response = model.invoke([HumanMessage(content=prompt)])
        text = response.content.strip()
        # Parse JSON
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        variants = json.loads(text)
        if isinstance(variants, list):
            cleaned = [str(v).strip() for v in variants if str(v).strip()]
            return [query] + cleaned[:n_variants]
    except Exception as e:
        logger.warning("Query expansion failed: %s; falling back to original query.", e)

    return [query]


def generate_hyde_doc(query: str, llm: Any = None) -> str:
    """Generate a hypothetical security passage answering the query for HyDE retrieval."""
    model = llm or get_fast_llm()
    prompt = f"""You are a threat intelligence researcher. Write a concise, factual 2-3 sentence hypothetical excerpt from a security advisory, CVE report, or ATT&CK description that directly answers the question:
"{query}"

Do not include headers, greetings, or conversational preamble. Output only the passage text."""

    try:
        response = model.invoke([HumanMessage(content=prompt)])
        doc = response.content.strip()
        if doc:
            return doc
    except Exception as e:
        logger.warning("HyDE generation failed: %s; falling back to query.", e)

    return query
