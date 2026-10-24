# Reference repos (read, then re-implement; do not import from third_party\).
param([switch]$WithOptional)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path third_party | Out-Null
Set-Location third_party
$repos = @(
  "LHRLAB/Graph-R1","YucanGuo/RouteRAG","HuskyInSalt/CRAG","piyushagni5/langgraph-ai",
  "Bisma474/Corrective-Rag","AkariAsai/self-rag","neo4j/neo4j-graphrag-python",
  "microsoft/graphrag","explodinggradients/ragas"
)
if ($WithOptional) { $repos += @("neo4j-contrib/ms-graphrag-neo4j","langfuse/langfuse") }
"" | Out-File COMMITS.txt -Encoding utf8
foreach ($r in $repos) {
  $d = Split-Path $r -Leaf
  if (-not (Test-Path $d)) { git clone --depth 1 "https://github.com/$r.git" }
  $h = git -C $d rev-parse HEAD
  "$r $h" | Out-File COMMITS.txt -Append -Encoding utf8
}
Write-Host "Done. Commit hashes in third_party\COMMITS.txt (copy into THIRD_PARTY.md, add licenses)."
