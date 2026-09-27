from typing import Dict, Any, List

# PROV-DM direction, encoded as (src node kind, dst node kind) per edge type:
# wasGeneratedBy(entity, activity), used(activity, entity),
# wasAssociatedWith(activity, agent), wasDerivedFrom(generated, used entity).
EDGE_ENDPOINTS = {
    "wasGeneratedBy": ("entity", "activity"),
    "used": ("activity", "entity"),
    "wasAssociatedWith": ("activity", "agent"),
    "wasDerivedFrom": ("entity", "entity"),
}


def _node_ids(nodes: Any, neg: List[str]) -> List[Any]:
    ids = []
    for n in nodes if isinstance(nodes, list) else []:
        if isinstance(n, dict) and isinstance(n.get("id"), str) and n["id"]:
            ids.append(n["id"])
        else:
            neg.append("NEG.PROV.MISSING_ID")
    return ids


def validate_prov_min(doc: Dict[str, Any]) -> List[str]:
    neg: List[str] = []
    ent_ids = _node_ids(doc.get("entities", []), neg)
    act_ids = _node_ids(doc.get("activities", []), neg)
    agt_ids = _node_ids(doc.get("agents", []), neg)
    all_ids = ent_ids + act_ids + agt_ids
    if len(set(all_ids)) != len(all_ids):
        neg.append("NEG.PROV.DUPLICATE_ID")
    ents, acts, ags = set(ent_ids), set(act_ids), set(agt_ids)
    if not ents or not acts or not ags:
        neg.append("NEG.PROV.MISSING_CORE_NODE")
    kinds = {"entity": ents, "activity": acts, "agent": ags}
    gen_count = {eid: 0 for eid in ents}
    assoc_count = {aid: 0 for aid in acts}
    for e in doc.get("edges", []):
        etype = e.get("type") if isinstance(e, dict) else None
        if not isinstance(etype, str) or etype not in EDGE_ENDPOINTS:
            neg.append("NEG.PROV.UNKNOWN_EDGE_TYPE")
            continue
        src_kind, dst_kind = EDGE_ENDPOINTS[etype]
        src, dst = e.get("src"), e.get("dst")
        if not isinstance(src, str) or not isinstance(dst, str) \
                or src not in kinds[src_kind] or dst not in kinds[dst_kind]:
            neg.append("NEG.PROV.BROKEN_REF")
            continue
        if etype == "wasGeneratedBy":
            gen_count[src] += 1
        elif etype == "wasAssociatedWith":
            assoc_count[src] += 1
    for eid, c in gen_count.items():
        if c != 1:
            neg.append("NEG.PROV.MISSING_GENERATION_EDGE")
    for aid, c in assoc_count.items():
        if c < 1:
            neg.append("NEG.PROV.MISSING_ASSOCIATION_EDGE")
    return sorted(set(neg))
