"""Finding state machine (deterministic, no LLM involved).

The orchestrator may *advise* a transition, but only the control plane
applies one, and only if it is allowed here. Every applied transition is
expected to cite evidence; that enforcement lives in the control plane,
while this module defines which transitions are structurally legal.

Round limits (at most one MAIS_EVIDENCIA loop and one REVISAO_HUMANA)
are a control-plane policy, not encoded here; this module only answers
"is this transition shape legal at all?".
"""

from __future__ import annotations

from enum import Enum


class State(str, Enum):
    PROPOSTA = "PROPOSTA"
    MAIS_EVIDENCIA = "MAIS_EVIDENCIA"
    REJEITADA = "REJEITADA"
    APROVADA_PARA_VALIDACAO = "APROVADA_PARA_VALIDACAO"
    REVISAO_HUMANA = "REVISAO_HUMANA"
    CONFIRMADA = "CONFIRMADA"
    RELATORIO_PRONTO = "RELATORIO_PRONTO"


# Allowed transitions. Terminal states map to an empty set.
_ALLOWED: dict[State, frozenset[State]] = {
    State.PROPOSTA: frozenset({
        State.REJEITADA,
        State.MAIS_EVIDENCIA,
        State.REVISAO_HUMANA,
        State.APROVADA_PARA_VALIDACAO,
    }),
    State.MAIS_EVIDENCIA: frozenset({
        State.PROPOSTA,
        State.REVISAO_HUMANA,
        State.REJEITADA,
    }),
    State.REVISAO_HUMANA: frozenset({
        State.APROVADA_PARA_VALIDACAO,
        State.REJEITADA,
    }),
    State.APROVADA_PARA_VALIDACAO: frozenset({
        State.CONFIRMADA,
        State.MAIS_EVIDENCIA,
        State.REVISAO_HUMANA,
        State.REJEITADA,
    }),
    State.CONFIRMADA: frozenset({State.RELATORIO_PRONTO}),
    State.REJEITADA: frozenset(),
    State.RELATORIO_PRONTO: frozenset(),
}

INITIAL = State.PROPOSTA


def can_transition(current: State, nxt: State) -> bool:
    """Return True if moving current -> nxt is structurally legal."""
    return nxt in _ALLOWED[current]


def allowed_transitions(current: State) -> frozenset[State]:
    return _ALLOWED[current]


def is_terminal(state: State) -> bool:
    return len(_ALLOWED[state]) == 0
