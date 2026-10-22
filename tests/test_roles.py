"""Tests for role prompts, the agent-file renderer, and output parsers."""

import unittest

from arbiter.records import Role, VulnClass
from arbiter.roles import (
    RECOMMENDED_MODELS,
    ROLE_PROMPTS,
    analysis_from_dict,
    decision_from_dict,
    render_agent_markdown,
)
from arbiter.states import State


class Prompts(unittest.TestCase):
    def test_all_roles_present(self):
        for r in ("OTIMISTA", "CETICO", "ARBITER", "RECON", "VALIDADOR", "ORQUESTRADOR"):
            self.assertIn(r, ROLE_PROMPTS)

    def test_shared_rules_in_every_prompt(self):
        for p in ROLE_PROMPTS.values():
            self.assertIn("UNTRUSTED DATA", p)
            self.assertIn("single JSON object", p)

    def test_skeptic_requires_benign(self):
        self.assertIn("benign_explanations", ROLE_PROMPTS["CETICO"])
        self.assertIn("REFUTE", ROLE_PROMPTS["CETICO"])

    def test_arbiter_evidence_only(self):
        self.assertIn("CITED EVIDENCE ONLY", ROLE_PROMPTS["ARBITER"])
        self.assertIn("never a vote", ROLE_PROMPTS["ARBITER"])

    def test_validator_forbids_destructive(self):
        self.assertIn("no logout", ROLE_PROMPTS["VALIDADOR"])

    def test_recommended_models_cover_roles(self):
        self.assertEqual(set(RECOMMENDED_MODELS), set(ROLE_PROMPTS))


class AgentFile(unittest.TestCase):
    def test_render_has_frontmatter_and_body(self):
        md = render_agent_markdown("CETICO", "amazon-bedrock/deepseek.v3")
        self.assertTrue(md.startswith("---\nmodel: amazon-bedrock/deepseek.v3\n---"))
        self.assertIn("Skeptic", md)

    def test_unknown_role_raises(self):
        with self.assertRaises(KeyError):
            render_agent_markdown("NOPE", "m")


class Parsers(unittest.TestCase):
    def test_analysis_from_dict(self):
        a = analysis_from_dict(
            {"vuln_class": "IDOR", "claim": "x", "evidence_ids": ["ev_1"],
             "benign_explanations": ["public by design"], "confidence": "MEDIA"},
            hypothesis_id="h1", role=Role.CETICO)
        self.assertEqual(a.vuln_class, VulnClass.IDOR)
        self.assertEqual(a.author_role, Role.CETICO)
        self.assertEqual(a.evidence_ids, ("ev_1",))

    def test_analysis_bad_class_raises(self):
        with self.assertRaises(ValueError):
            analysis_from_dict({"vuln_class": "NOPE", "claim": "x"},
                               hypothesis_id="h1", role=Role.OTIMISTA)

    def test_decision_from_dict(self):
        d = decision_from_dict(
            {"target_state": "APROVADA_PARA_VALIDACAO",
             "motivating_evidence_ids": ["ev_1"], "rationale": "r"},
            hypothesis_id="h1")
        self.assertEqual(d.target_state, State.APROVADA_PARA_VALIDACAO)
        self.assertEqual(d.motivating_evidence_ids, ("ev_1",))

    def test_decision_missing_field_raises(self):
        with self.assertRaises(KeyError):
            decision_from_dict({"target_state": "REJEITADA"}, hypothesis_id="h1")


if __name__ == "__main__":
    unittest.main()
