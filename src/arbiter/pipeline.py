"""Analysis pipeline — the wiring that makes the offline pieces cohere.

It ingests observations, runs the oracles over them, records each oracle's
factual statement as evidence, and emits deduplicated **leads** (facts for
the operator's triage — not confirmed, not scored, not AI-written). Turning
a lead into a confirmed, CVSS-scored Finding happens only after validation
(active, human-gated); see finding.py.

Deterministic and offline: it drives nothing on the network; it consumes
already-captured exchanges and operator-declared matrices/flows.
"""

from __future__ import annotations

from dataclasses import dataclass

from .evidence import EvidenceKind, EvidenceStore
from .ingest import CapturedExchange, exchange_to_evidence
from .memory import FindingMemory, signature
from .oracles import protocol, reflected
from .oracles.authz_matrix import AuthorizationMatrix, find_violations
from .oracles.authz_matrix import to_evidence_content as authz_evidence
from .oracles.business_invariant import Flow, check_flow
from .oracles.business_invariant import to_evidence_content as invariant_evidence


@dataclass(frozen=True)
class Lead:
    oracle: str
    detail: str
    evidence_id: str
    signature: str


class AnalysisPipeline:
    def __init__(self, evidence_store: EvidenceStore | None = None,
                 memory: FindingMemory | None = None) -> None:
        self.evidence = evidence_store or EvidenceStore()
        self.memory = memory or FindingMemory()

    def _emit(self, oracle: str, detail: str, kind: EvidenceKind,
              source: str, scope: str = "") -> Lead | None:
        ev = self.evidence.record(kind, source=source, content=detail,
                                  summary=detail[:80])
        sig = signature(oracle, detail, scope)
        if not self.memory.register(sig):
            return None      # duplicate — already surfaced
        return Lead(oracle=oracle, detail=detail, evidence_id=ev.id, signature=sig)

    def analyze_exchange(self, ex: CapturedExchange) -> list[Lead]:
        exchange_to_evidence(ex, self.evidence)   # record the raw exchange too
        leads: list[Lead] = []
        for pf in protocol.check_exchange(ex):
            lead = self._emit("protocol", protocol.to_evidence_content(pf),
                              EvidenceKind.OBSERVATION, "oracle:protocol", ex.url)
            if lead:
                leads.append(lead)
        for rf in reflected.check_reflections(ex):
            lead = self._emit("reflected-xss", reflected.to_evidence_content(rf),
                              EvidenceKind.OBSERVATION, "oracle:reflected", ex.url)
            if lead:
                leads.append(lead)
        return leads

    def analyze_authz(self, matrix: AuthorizationMatrix, observations) -> list[Lead]:
        leads: list[Lead] = []
        for v in find_violations(matrix, observations):
            if not v.is_security:
                continue                 # functional-only mismatches are not leads
            lead = self._emit("authz", authz_evidence(v),
                              EvidenceKind.DIFFERENTIAL, "oracle:authz", v.resource_id)
            if lead:
                leads.append(lead)
        return leads

    def analyze_flow(self, flow: Flow, invariants) -> list[Lead]:
        leads: list[Lead] = []
        for viol in check_flow(flow, invariants):
            lead = self._emit("business-invariant", invariant_evidence(viol),
                              EvidenceKind.DIFFERENTIAL, "oracle:invariant")
            if lead:
                leads.append(lead)
        return leads
