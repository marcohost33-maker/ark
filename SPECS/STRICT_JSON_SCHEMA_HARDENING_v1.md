# STRICT_JSON_SCHEMA_HARDENING_v1
Version: 1.0.5
Status: DRAFT

Recommended hardening rules:
- additionalProperties: false on closed objects
- minLength/minItems where sensible
- enum for constrained strings
- format: date-time for timestamps
- use JSON Schema 2020-12 consistently
