# Data sources. Large repos use sparse checkout.
# Usage: .\scripts\clone_data.ps1 -Years 2024,2025
param([string[]]$Years = @("2024","2025"))
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path data\raw | Out-Null
Set-Location data\raw

# CVE records (one year is ~39k files / ~400 MB)
if (-not (Test-Path cvelistV5)) {
  git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git
}
Push-Location cvelistV5
git sparse-checkout set ($Years | ForEach-Object { "cves/$_" })
Pop-Location

# CISA KEV (small)
if (-not (Test-Path kev-data)) { git clone --depth 1 https://github.com/cisagov/kev-data.git }

# MITRE ATT&CK enterprise only (repo is >1 GB because of old versions)
if (-not (Test-Path attack-stix-data)) {
  git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data.git
}
Push-Location attack-stix-data
git sparse-checkout set --no-cone enterprise-attack/enterprise-attack.json
Pop-Location

# CAPEC (STIX 2.1 file includes CWE + ATT&CK ids)
if (-not (Test-Path cti)) {
  git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre/cti.git
}
Push-Location cti
git sparse-checkout set --no-cone capec/2.1/stix-capec.json
Pop-Location

# CWE (not on GitHub). URL not verified from this environment; if it fails,
# download manually from https://cwe.mitre.org/data/downloads.html into data\raw\cwe\
New-Item -ItemType Directory -Force -Path cwe | Out-Null
if (-not (Test-Path cwe\cwec_latest.xml.zip)) {
  try {
    Invoke-WebRequest -Uri https://cwe.mitre.org/data/xml/cwec_latest.xml.zip -OutFile cwe\cwec_latest.xml.zip
    Expand-Archive -Path cwe\cwec_latest.xml.zip -DestinationPath cwe -Force
  } catch { Write-Warning "CWE download failed. Download manually (see comment above)." }
}
Write-Host "Data ready in data\raw\"
