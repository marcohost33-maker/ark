from typing import Dict, Any, List

def validate_prov_min(doc: Dict[str, Any]) -> List[str]:
    neg: List[str] = []
    ents = {e.get("id") for e in doc.get("entities", []) if "id" in e}
    acts = {a.get("id") for a in doc.get("activities", []) if "id" in a}
    ags = {g.get("id") for g in doc.get("agents", []) if "id" in g}
    if not ents or not acts or not ags:
        neg.append("NEG.PROV.MISSING_CORE_NODE")
    gen_edges = [e for e in doc.get("edges", []) if e.get("type") == "wasGeneratedBy"]
    assoc_edges = [e for e in doc.get("edges", []) if e.get("type") == "wasAssociatedWith"]
    gen_count = {eid: 0 for eid in ents}
    for e in gen_edges:
        src, dst = e.get("src"), e.get("dst")
        if src not in ents or dst not in acts:
            neg.append("NEG.PROV.BROKEN_REF"); continue
        gen_count[src] += 1
    for eid, c in gen_count.items():
        if c != 1:
            neg.append("NEG.PROV.MISSING_GENERATION_EDGE")
    assoc_count = {aid: 0 for aid in acts}
    for e in assoc_edges:
        src, dst = e.get("src"), e.get("dst")
        if src not in acts or dst not in ags:
            neg.append("NEG.PROV.BROKEN_REF"); continue
        assoc_count[src] += 1
    for aid, c in assoc_count.items():
        if c < 1:
            neg.append("NEG.PROV.MISSING_ASSOCIATION_EDGE")
    return sorted(set(neg))
