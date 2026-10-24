"""Sample inspection script to verify and log exact schema field paths."""

import json
from lxml import etree

def inspect_cwe():
    print("=" * 60)
    print("1. CWE XML Inspection (data/raw/cwe/cwec_v4.20.xml)")
    print("=" * 60)
    tree = etree.parse(r"data\raw\cwe\cwec_v4.20.xml")
    root = tree.getroot()
    count = 0
    sample_cwe = None
    for w in root.iter("{*}Weakness"):
        count += 1
        if w.get("ID") == "79":
            sample_cwe = w
    print(f"Total <Weakness> elements in XML: {count}")
    if sample_cwe is not None:
        print("Sample CWE-79 attributes:")
        print("  ID:", sample_cwe.get("ID"))
        print("  Name:", sample_cwe.get("Name"))
        print("  Abstraction:", sample_cwe.get("Abstraction"))
        desc = sample_cwe.findtext("{*}Description")
        print("  Description:", desc[:120] if desc else "None", "...")
        parents = [f"CWE-{rel.get('CWE_ID')}" for rel in sample_cwe.iter("{*}Related_Weakness") if rel.get("Nature") == "ChildOf"]
        print("  ChildOf Parents:", parents)
        capecs = [f"CAPEC-{ap.get('CAPEC_ID')}" for ap in sample_cwe.iter("{*}Related_Attack_Pattern")]
        print("  Related CAPECs:", capecs)

def inspect_capec():
    print("\n" + "=" * 60)
    print("2. CAPEC STIX Inspection (data/raw/cti/capec/2.1/stix-capec.json)")
    print("=" * 60)
    with open(r"data\raw\cti\capec\2.1\stix-capec.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    patterns = [o for o in data.get("objects", []) if o.get("type") == "attack-pattern"]
    print(f"Total attack-pattern objects: {len(patterns)}")
    for p in patterns:
        refs = {r.get("source_name", "").lower(): r.get("external_id") for r in p.get("external_references", [])}
        if "capec" in refs and refs["capec"] == "CAPEC-63":
            print("Sample CAPEC-63:")
            print("  id:", refs["capec"])
            print("  name:", p.get("name"))
            print("  description:", p.get("description", "")[:120], "...")
            print("  likelihood:", p.get("x_capec_likelihood_of_attack"))
            print("  severity:", p.get("x_capec_typical_severity"))
            cwe_refs = [r.get("external_id") for r in p.get("external_references", []) if r.get("source_name", "").lower() == "cwe"]
            attack_refs = [r.get("external_id") for r in p.get("external_references", []) if "attack" in r.get("source_name", "").lower()]
            print("  CWE links:", cwe_refs)
            print("  ATT&CK links:", attack_refs)
            break

def inspect_attack():
    print("\n" + "=" * 60)
    print("3. ATT&CK STIX Inspection (data/raw/attack-stix-data/enterprise-attack/enterprise-attack.json)")
    print("=" * 60)
    with open(r"data\raw\attack-stix-data\enterprise-attack\enterprise-attack.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    objects = data.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated")]
    tactics = [o for o in objects if o.get("type") == "x-mitre-tactic"]
    mitigations = [o for o in objects if o.get("type") == "course-of-action"]
    print(f"Active Techniques: {len(techniques)}, Tactics: {len(tactics)}, Mitigations: {len(mitigations)}")

if __name__ == "__main__":
    inspect_cwe()
    inspect_capec()
    inspect_attack()
