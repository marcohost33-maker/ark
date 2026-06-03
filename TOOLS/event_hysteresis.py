from dataclasses import dataclass
from typing import Iterable, List

@dataclass(frozen=True)
class EventWindow:
    t_start: float
    t_end: float
    t_enter_detected: float | None
    t_exit_detected: float | None
    confidence: float
    reason: str
    support_count: int

def hysteresis_windows(t_grid: Iterable[float], score: Iterable[float], threshold: float, delta: float, min_support: int=2, min_duration: float=0.0) -> List[EventWindow]:
    ts = list(t_grid); ss = list(score)
    if len(ts) != len(ss):
        raise ValueError("t_grid and score length mismatch")
    state = "OUT"; start_idx = None; windows: List[EventWindow] = []
    for i, s in enumerate(ss):
        if state == "OUT":
            if s >= threshold + delta:
                state = "IN"; start_idx = i; enter_i = i
        else:
            if s <= threshold - delta:
                end_idx = max(start_idx, i - 1)
                support = end_idx - start_idx + 1
                duration = ts[end_idx] - ts[start_idx]
                if support >= min_support and duration >= min_duration:
                    windows.append(EventWindow(ts[start_idx], ts[end_idx], ts[enter_i], ts[i], min(1.0, support / max(min_support,1)), "hysteresis_fsm", support))
                state = "OUT"; start_idx = None
    if state == "IN" and start_idx is not None:
        end_idx = len(ts)-1
        support = end_idx - start_idx + 1
        duration = ts[end_idx] - ts[start_idx]
        if support >= min_support and duration >= min_duration:
            windows.append(EventWindow(ts[start_idx], ts[end_idx], ts[start_idx], None, min(1.0, support / max(min_support,1)), "hysteresis_fsm", support))
    return windows
