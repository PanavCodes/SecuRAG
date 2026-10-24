#!/usr/bin/env bash
# Data sources. Large repos use sparse checkout.
# Usage: scripts/clone_data.sh 2024 2025
set -euo pipefail
if [ $# -eq 0 ]; then YEARS=(2024 2025); else YEARS=("$@"); fi
mkdir -p data/raw && cd data/raw

# CVE records (one year is ~39k files / ~400 MB)
if [ ! -d cvelistV5 ]; then
  git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git
fi
( cd cvelistV5 && git sparse-checkout set $(for y in "${YEARS[@]}"; do echo "cves/$y"; done) )

# CISA KEV (small)
[ -d kev-data ] || git clone --depth 1 https://github.com/cisagov/kev-data.git

# MITRE ATT&CK enterprise only (repo is >1 GB because of old versions)
if [ ! -d attack-stix-data ]; then
  git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data.git
fi
( cd attack-stix-data && git sparse-checkout set --no-cone enterprise-attack/enterprise-attack.json )

# CAPEC (STIX 2.1 file includes CWE + ATT&CK ids)
if [ ! -d cti ]; then
  git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre/cti.git
fi
( cd cti && git sparse-checkout set --no-cone capec/2.1/stix-capec.json )

# CWE (not on GitHub). URL not verified from this environment; if it fails,
# download manually from https://cwe.mitre.org/data/downloads.html into data/raw/cwe/
mkdir -p cwe
if [ ! -f cwe/cwec_latest.xml.zip ]; then
  curl -fL -o cwe/cwec_latest.xml.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip \
    && (cd cwe && unzip -o cwec_latest.xml.zip) \
    || echo "WARN: CWE download failed. Download manually (see comment above)."
fi
echo "Data ready in data/raw/"
