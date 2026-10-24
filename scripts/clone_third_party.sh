#!/usr/bin/env bash
# Reference repos (read, then re-implement; do not import from third_party/).
set -euo pipefail
mkdir -p third_party && cd third_party
repos=(
  LHRLAB/Graph-R1
  YucanGuo/RouteRAG
  HuskyInSalt/CRAG
  piyushagni5/langgraph-ai
  Bisma474/Corrective-Rag
  AkariAsai/self-rag
  neo4j/neo4j-graphrag-python
  microsoft/graphrag
  explodinggradients/ragas
)
optional=( neo4j-contrib/ms-graphrag-neo4j langfuse/langfuse )
[ "${1:-}" = "--with-optional" ] && repos+=("${optional[@]}")
: > COMMITS.txt
for r in "${repos[@]}"; do
  d=$(basename "$r")
  [ -d "$d" ] || git clone --depth 1 "https://github.com/$r.git"
  echo "$r $(git -C "$d" rev-parse HEAD)" >> COMMITS.txt
done
echo "Done. Commit hashes in third_party/COMMITS.txt (copy into THIRD_PARTY.md, add licenses)."
