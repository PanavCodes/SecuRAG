# SecuRAG Failure Analysis

Detailed failure mode investigation across evaluated configurations.

Failure Categories:
- **retrieval miss**: Relevant security passages were not returned in top-k.
- **wrong graph path**: Graph expansion was truncated or missed distant relation.
- **evaluator error**: CRAG grader prematurely rejected valid candidate evidence.
- **generation error**: LLM failed to include required bracketed citation or hallucinated alias.

### Case 1: q002 — Config A (Naive)
- **Question**: "What weakness is identified by CWE-79?" (Tier 1)
- **Root Cause Category**: `generation error`
- **Expected Answer**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **Actual Generated Answer**: CWE-79 identifies the "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" weakness [CVE-2024-23111] [CVE-2024-31199]....
- **Citations Returned**: `['CVE-2024-23111', 'CVE-2024-31199']`

### Case 2: q007 — Config A (Naive)
- **Question**: "Which attack patterns in CAPEC relate to CWE-79?" (Tier 2)
- **Root Cause Category**: `generation error`
- **Expected Answer**: CAPEC-63 (Cross-Site Scripting), CAPEC-85, CAPEC-209, CAPEC-588, CAPEC-591, and CAPEC-592.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

### Case 3: q011 — Config A (Naive)
- **Question**: "Trace the full attack chain from CVE-2024-22334 to an ATT&CK technique." (Tier 3)
- **Root Cause Category**: `retrieval miss`
- **Expected Answer**: CVE-2024-22334 links to CWE-732, which links to CAPEC-1, which maps to Technique T1574.010 under tactic Stealth/Defense Evasion.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

### Case 4: q012 — Config A (Naive)
- **Question**: "What technique and tactic are reachable from CVE-2024-38864?" (Tier 3)
- **Root Cause Category**: `retrieval miss`
- **Expected Answer**: CVE-2024-38864 has weakness CWE-732, associated with CAPEC-1, which relates to Technique T1574.010 in tactic Stealth.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

### Case 5: q001 — Config B (+BM25)
- **Question**: "What is the primary vulnerability in CVE-2021-44228?" (Tier 1)
- **Root Cause Category**: `generation error`
- **Expected Answer**: Apache Log4j2 contains a remote code execution vulnerability in JNDI features.
- **Actual Generated Answer**: The primary vulnerability in CVE-2021-44228 is that Apache Log4j2 JNDI features do not protect against attacker-controlled JNDI-related endpoints, which allows ...
- **Citations Returned**: `[]`

### Case 6: q002 — Config B (+BM25)
- **Question**: "What weakness is identified by CWE-79?" (Tier 1)
- **Root Cause Category**: `generation error`
- **Expected Answer**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **Actual Generated Answer**: CWE-79 identifies the "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" weakness [CVE-2024-23111] [CVE-2024-31199]....
- **Citations Returned**: `[]`

### Case 7: q006 — Config B (+BM25)
- **Question**: "Which weaknesses are associated with CVE-2021-44228?" (Tier 2)
- **Root Cause Category**: `retrieval miss`
- **Expected Answer**: CWE-20, CWE-400, and CWE-502.
- **Actual Generated Answer**: CVE-2021-44228 is associated with a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote cod...
- **Citations Returned**: `[]`

### Case 8: q007 — Config B (+BM25)
- **Question**: "Which attack patterns in CAPEC relate to CWE-79?" (Tier 2)
- **Root Cause Category**: `generation error`
- **Expected Answer**: CAPEC-63 (Cross-Site Scripting), CAPEC-85, CAPEC-209, CAPEC-588, CAPEC-591, and CAPEC-592.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

### Case 9: q011 — Config B (+BM25)
- **Question**: "Trace the full attack chain from CVE-2024-22334 to an ATT&CK technique." (Tier 3)
- **Root Cause Category**: `retrieval miss`
- **Expected Answer**: CVE-2024-22334 links to CWE-732, which links to CAPEC-1, which maps to Technique T1574.010 under tactic Stealth/Defense Evasion.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

### Case 10: q012 — Config B (+BM25)
- **Question**: "What technique and tactic are reachable from CVE-2024-38864?" (Tier 3)
- **Root Cause Category**: `generation error`
- **Expected Answer**: CVE-2024-38864 has weakness CWE-732, associated with CAPEC-1, which relates to Technique T1574.010 in tactic Stealth.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

### Case 11: q001 — Config C (+CrossEncoder)
- **Question**: "What is the primary vulnerability in CVE-2021-44228?" (Tier 1)
- **Root Cause Category**: `generation error`
- **Expected Answer**: Apache Log4j2 contains a remote code execution vulnerability in JNDI features.
- **Actual Generated Answer**: The primary vulnerability in CVE-2021-44228 is that Apache Log4j2 JNDI features do not protect against attacker-controlled JNDI-related endpoints, which allows ...
- **Citations Returned**: `[]`

### Case 12: q002 — Config C (+CrossEncoder)
- **Question**: "What weakness is identified by CWE-79?" (Tier 1)
- **Root Cause Category**: `generation error`
- **Expected Answer**: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
- **Actual Generated Answer**: CWE-79 identifies the "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')" weakness [CVE-2024-23111] [CVE-2024-31199]....
- **Citations Returned**: `[]`

### Case 13: q006 — Config C (+CrossEncoder)
- **Question**: "Which weaknesses are associated with CVE-2021-44228?" (Tier 2)
- **Root Cause Category**: `retrieval miss`
- **Expected Answer**: CWE-20, CWE-400, and CWE-502.
- **Actual Generated Answer**: CVE-2021-44228 is associated with a vulnerability where JNDI features do not protect against attacker-controlled JNDI-related endpoints, allowing for remote cod...
- **Citations Returned**: `[]`

### Case 14: q007 — Config C (+CrossEncoder)
- **Question**: "Which attack patterns in CAPEC relate to CWE-79?" (Tier 2)
- **Root Cause Category**: `generation error`
- **Expected Answer**: CAPEC-63 (Cross-Site Scripting), CAPEC-85, CAPEC-209, CAPEC-588, CAPEC-591, and CAPEC-592.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

### Case 15: q011 — Config C (+CrossEncoder)
- **Question**: "Trace the full attack chain from CVE-2024-22334 to an ATT&CK technique." (Tier 3)
- **Root Cause Category**: `retrieval miss`
- **Expected Answer**: CVE-2024-22334 links to CWE-732, which links to CAPEC-1, which maps to Technique T1574.010 under tactic Stealth/Defense Evasion.
- **Actual Generated Answer**: The requested information was not found in the SecuRAG cybersecurity knowledge base....
- **Citations Returned**: `[]`

