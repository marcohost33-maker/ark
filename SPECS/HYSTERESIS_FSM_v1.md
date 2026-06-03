# HYSTERESIS_FSM_v1
Version: 1.0.5
Status: DRAFT

State machine:
- OUT -> IN when s >= theta + delta
- IN -> OUT when s <= theta - delta
- otherwise hold state

Recommended semantics:
- t_start = first in-state sample
- t_end = last in-state sample
- t_enter_detected / t_exit_detected may be stored separately
