"""Tests for the finding state machine."""

import unittest

from arbiter.states import (
    INITIAL,
    State,
    allowed_transitions,
    can_transition,
    is_terminal,
)


class StateMachine(unittest.TestCase):
    def test_initial_is_proposta(self):
        self.assertEqual(INITIAL, State.PROPOSTA)

    def test_happy_path(self):
        self.assertTrue(can_transition(State.PROPOSTA, State.APROVADA_PARA_VALIDACAO))
        self.assertTrue(can_transition(State.APROVADA_PARA_VALIDACAO, State.CONFIRMADA))
        self.assertTrue(can_transition(State.CONFIRMADA, State.RELATORIO_PRONTO))

    def test_cannot_skip_to_confirmada(self):
        self.assertFalse(can_transition(State.PROPOSTA, State.CONFIRMADA))

    def test_cannot_report_without_confirmation(self):
        self.assertFalse(can_transition(State.APROVADA_PARA_VALIDACAO, State.RELATORIO_PRONTO))

    def test_rejeitada_is_terminal(self):
        self.assertTrue(is_terminal(State.REJEITADA))
        self.assertEqual(allowed_transitions(State.REJEITADA), frozenset())

    def test_relatorio_pronto_is_terminal(self):
        self.assertTrue(is_terminal(State.RELATORIO_PRONTO))

    def test_human_review_can_approve_or_reject_only(self):
        self.assertEqual(
            allowed_transitions(State.REVISAO_HUMANA),
            frozenset({State.APROVADA_PARA_VALIDACAO, State.REJEITADA}),
        )

    def test_every_state_has_a_transition_entry(self):
        for s in State:
            # must not raise
            allowed_transitions(s)

    def test_no_transition_targets_unknown_state(self):
        for s in State:
            for target in allowed_transitions(s):
                self.assertIsInstance(target, State)


if __name__ == "__main__":
    unittest.main()
