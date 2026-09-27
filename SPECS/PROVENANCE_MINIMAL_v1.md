# PROVENANCE_MINIMAL_v1
Version: 1.0.5
Status: DRAFT

Minimal graph:
Nodes: Entity, Activity, Agent
Edges: wasGeneratedBy, used, wasAssociatedWith, wasDerivedFrom

Minimum constraints:
- each emitted entity has exactly one wasGeneratedBy edge
- each activity has at least one wasAssociatedWith edge
- referenced node IDs must exist

Edge direction (PROV-DM; `src` is the subject of the relation):

| Edge | src | dst |
|---|---|---|
| wasGeneratedBy | Entity | Activity |
| used | Activity | Entity |
| wasAssociatedWith | Activity | Agent |
| wasDerivedFrom | Entity (generated) | Entity (used) |

The reference constraint applies to **every** edge type. Violations:
- `NEG.PROV.BROKEN_REF` — an endpoint is missing or has the wrong node kind
- `NEG.PROV.UNKNOWN_EDGE_TYPE` — edge type outside the four above
- `NEG.PROV.DUPLICATE_ID` — the same id names more than one node
- `NEG.PROV.MISSING_ID` — a node without a non-empty string id
