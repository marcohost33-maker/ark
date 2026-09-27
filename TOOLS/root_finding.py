from dataclasses import dataclass
from typing import Callable, Optional, Tuple
from scipy.optimize import root_scalar

ROOT_ALLOWED_METHODS = {"bisect", "brentq", "brenth", "ridder", "toms748"}

@dataclass(frozen=True)
class RootResult:
    root: Optional[float]
    converged: bool
    iterations: int
    method: str
    message: str

def find_root_bracketed(g: Callable[[float], float], bracket: Tuple[float,float], method: str="brentq", xtol: float=1e-10, rtol: float=1e-8, maxiter: int=100) -> RootResult:
    if method not in ROOT_ALLOWED_METHODS:
        return RootResult(None, False, 0, method, "unknown method")
    a,b = bracket
    ga, gb = g(a), g(b)
    if ga == 0.0:
        return RootResult(a, True, 0, method, "exact root at a")
    if gb == 0.0:
        return RootResult(b, True, 0, method, "exact root at b")
    if ga * gb > 0.0:
        return RootResult(None, False, 0, method, "no sign change bracket")
    try:
        sol = root_scalar(g, bracket=[a,b], method=method, xtol=xtol, rtol=rtol, maxiter=maxiter)
        return RootResult(sol.root if sol.converged else None, bool(sol.converged), int(getattr(sol,'iterations',0) or 0), method, str(getattr(sol,'flag','')))
    except Exception as e:
        return RootResult(None, False, 0, method, f"exception: {e}")
