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
