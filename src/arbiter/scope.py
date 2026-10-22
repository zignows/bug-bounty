"""Scope model — the validated source of truth for what is in bounds.

This is plain, immutable data. It carries no behavior that reaches the
network; the policy engine (see policy.py) reads it to make allow/deny
decisions. A scope is authored by the operator (a human) from the
program's published rules and loaded here. Recovered/untrusted content
must never be able to construct or mutate a Scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import os


@dataclass(frozen=True)
class Limits:
    """Technical ceilings enforced by the control plane's budget governor."""

    max_cost_usd: float = 2.0
    max_requests_per_second: float = 1.0
    max_concurrency: int = 2
    max_duration_seconds: int = 1800        # 30 min
    max_iterations: int = 20
    # stop conditions
    consecutive_error_limit: int = 5
    unexpected_effect_limit: int = 3

    def __post_init__(self) -> None:
        for name in (
            "max_cost_usd", "max_requests_per_second", "max_concurrency",
            "max_duration_seconds", "max_iterations",
            "consecutive_error_limit", "unexpected_effect_limit",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"Limits.{name} must be > 0")


@dataclass(frozen=True)
class Scope:
    name: str
    allowed_hosts: tuple[str, ...] = ()          # exact or "*.example.com"
    excluded_hosts: tuple[str, ...] = ()         # explicit out-of-scope
    allowed_schemes: tuple[str, ...] = ("https",)
    allowed_ports: tuple[int, ...] = (443,)
    # third-party assets that appear on in-scope pages but must NOT be tested
    third_party_denylist: tuple[str, ...] = ()
    limits: Limits = field(default_factory=Limits)
    # passive == read/observe only. Active testing is opt-in per host,
    # granted by a human, and is never the default.
    passive_only: bool = True
    notes: str = ""

    def with_active_testing(self) -> "Scope":
        """Return a copy with passive_only cleared.

        Intended to be called only by the control plane after an explicit
        human approval gate for a specific engagement. Kept explicit so the
        transition out of passive mode is always a deliberate, auditable act.
        """
        return replace(self, passive_only=False)


def _as_tuple(value) -> tuple:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def from_dict(data: dict) -> Scope:
    if "name" not in data or not str(data["name"]).strip():
        raise ValueError("scope requires a non-empty 'name'")
    limits_data = data.get("limits") or {}
    if not isinstance(limits_data, dict):
        raise ValueError("'limits' must be a mapping")
    limits = Limits(**limits_data)
    return Scope(
        name=str(data["name"]),
        allowed_hosts=tuple(str(h).lower() for h in _as_tuple(data.get("allowed_hosts"))),
        excluded_hosts=tuple(str(h).lower() for h in _as_tuple(data.get("excluded_hosts"))),
        allowed_schemes=tuple(str(s).lower() for s in _as_tuple(data.get("allowed_schemes")) ) or ("https",),
        allowed_ports=tuple(int(p) for p in _as_tuple(data.get("allowed_ports"))) or (443,),
        third_party_denylist=tuple(str(h).lower() for h in _as_tuple(data.get("third_party_denylist"))),
        limits=limits,
        passive_only=bool(data.get("passive_only", True)),
        notes=str(data.get("notes", "")),
    )


def load_scope(path: str) -> Scope:
    """Load a scope from a .json file (stdlib) or .yaml/.yml (needs PyYAML).

    JSON works with no third-party dependency. YAML is supported only when
    PyYAML is installed; it is treated as an optional convenience.
    """
    ext = os.path.splitext(path)[1].lower()
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    if ext in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "PyYAML is required to load a .yaml scope; use a .json scope "
                "or install pyyaml."
            ) from exc
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("scope file must contain a mapping at the top level")
    return from_dict(data)
