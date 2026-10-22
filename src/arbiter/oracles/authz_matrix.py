"""Authorization matrix — the deterministic oracle for IDOR / broken object
authorization and, more broadly, access-control logic.

Idea (from the design): the operator declares identities (A, B, anon, ...)
and, per resource, the *intended* access — what each identity SHOULD be
able to reach. The Recon/Validator layers supply the *observed* access.
A finding is a cell where observed != intended. The matrix itself is the
evidence; no RFC and no model opinion decides it — the differential does.

This module is pure and offline: it models intent, compares it against
observations, and emits violations. It never performs requests; observed
access is passed in.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Intent(str, Enum):
    ALLOWED = "ALLOWED"   # this identity SHOULD be able to access the resource
    DENIED = "DENIED"     # this identity should NOT be able to access it


class Observed(str, Enum):
    ALLOWED = "ALLOWED"   # the identity was in fact able to access it
    DENIED = "DENIED"     # access was in fact refused
    UNKNOWN = "UNKNOWN"   # not tested / inconclusive


class ViolationKind(str, Enum):
    # intent DENIED but observed ALLOWED == unauthorized access (IDOR/BOLA)
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"
    # intent ALLOWED but observed DENIED == functional bug, not a security win
    UNEXPECTED_DENIAL = "UNEXPECTED_DENIAL"


@dataclass(frozen=True)
class Identity:
    id: str
    label: str = ""


@dataclass(frozen=True)
class Resource:
    id: str
    description: str = ""


@dataclass(frozen=True)
class Violation:
    identity_id: str
    resource_id: str
    intent: Intent
    observed: Observed
    kind: ViolationKind

    @property
    def is_security(self) -> bool:
        return self.kind is ViolationKind.UNAUTHORIZED_ACCESS


class AuthorizationMatrix:
    """Declared intent of who should reach what. Built by the operator."""

    def __init__(self) -> None:
        self._identities: dict[str, Identity] = {}
        self._resources: dict[str, Resource] = {}
        self._intent: dict[tuple[str, str], Intent] = {}

    def add_identity(self, identity: Identity) -> Identity:
        self._identities[identity.id] = identity
        return identity

    def add_resource(self, resource: Resource) -> Resource:
        self._resources[resource.id] = resource
        return resource

    def set_intent(self, identity_id: str, resource_id: str, intent) -> None:
        if identity_id not in self._identities:
            raise KeyError(f"unknown identity: {identity_id!r} (add_identity first)")
        if resource_id not in self._resources:
            raise KeyError(f"unknown resource: {resource_id!r} (add_resource first)")
        self._intent[(identity_id, resource_id)] = Intent(intent)

    def get_intent(self, identity_id: str, resource_id: str) -> Intent | None:
        return self._intent.get((identity_id, resource_id))

    def identities(self) -> tuple[Identity, ...]:
        return tuple(self._identities.values())

    def resources(self) -> tuple[Resource, ...]:
        return tuple(self._resources.values())

    def intents(self) -> tuple[tuple[str, str, Intent], ...]:
        return tuple((i, r, v) for (i, r), v in self._intent.items())


def _coerce_observed(value) -> Observed:
    if isinstance(value, Observed):
        return value
    return Observed(str(value))


def find_violations(
    matrix: AuthorizationMatrix,
    observations: dict[tuple[str, str], Observed],
) -> list[Violation]:
    """Compare declared intent against observed access.

    `observations` maps (identity_id, resource_id) -> Observed. Cells with
    no observation, or an UNKNOWN observation, are skipped (untested, never
    a finding). Results are sorted deterministically, security-relevant
    violations first.
    """
    out: list[Violation] = []
    for identity_id, resource_id, intent in matrix.intents():
        observed = _coerce_observed(
            observations.get((identity_id, resource_id), Observed.UNKNOWN)
        )
        if observed is Observed.UNKNOWN:
            continue
        if intent is Intent.DENIED and observed is Observed.ALLOWED:
            out.append(Violation(identity_id, resource_id, intent, observed,
                                  ViolationKind.UNAUTHORIZED_ACCESS))
        elif intent is Intent.ALLOWED and observed is Observed.DENIED:
            out.append(Violation(identity_id, resource_id, intent, observed,
                                  ViolationKind.UNEXPECTED_DENIAL))
    out.sort(key=lambda v: (0 if v.is_security else 1, v.identity_id, v.resource_id))
    return out


def security_violations(violations: list[Violation]) -> list[Violation]:
    return [v for v in violations if v.is_security]


def to_evidence_content(violation: Violation) -> str:
    """Render a violation as DIFFERENTIAL evidence content for the store."""
    return (
        f"authz differential: identity={violation.identity_id} "
        f"resource={violation.resource_id} "
        f"intended={violation.intent.value} observed={violation.observed.value} "
        f"-> {violation.kind.value}"
    )
