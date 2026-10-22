"""Tests for the knowledge layer."""

import unittest

from arbiter.knowledge import (
    KnowledgeKind,
    KnowledgeStore,
    Provenance,
    RequirementLevel,
    ReportKnowledge,
    SpecAssertion,
    TRUST_UNTRUSTED,
    make_report_knowledge,
    make_spec_assertion,
    render_for_prompt,
    validate_entry,
)
from arbiter.records import VulnClass

PROV = Provenance(
    source_url="https://example.com/reports/1",
    source_name="example",
    date="2025-01-01",
    license="CC-BY-4.0",
    retrieved_at="2026-01-01T00:00:00+00:00",
)


def _report(curated=True, title="cross-user object access"):
    return make_report_knowledge(
        VulnClass.IDOR,
        title,
        PROV,
        root_cause="object id trusted from the client without an ownership check",
        observable_signals=("same object id returns data for a different account",),
        false_positives=("resource is public by design",),
        impact="read another user's record",
        tags=["idor", "authz"],
        curated=curated,
    )


def _spec():
    return make_spec_assertion(
        "RFC9110 §15.4",
        RequirementLevel.MUST,
        "A redirect target is determined by the Location header field.",
        topic="redirect",
        provenance=Provenance(source_url="https://www.rfc-editor.org/rfc/rfc9110",
                              license="IETF Trust"),
        tags=["redirect", "http"],
    )


class EntryBasics(unittest.TestCase):
    def test_report_is_untrusted(self):
        self.assertEqual(_report().trust, TRUST_UNTRUSTED)

    def test_spec_is_untrusted(self):
        self.assertEqual(_spec().trust, TRUST_UNTRUSTED)

    def test_report_id_content_addressed(self):
        self.assertEqual(_report().id, _report().id)

    def test_spec_curated_by_default(self):
        self.assertTrue(_spec().curated)

    def test_report_not_curated_by_default(self):
        r = make_report_knowledge(VulnClass.IDOR, "t", PROV, root_cause="rc")
        self.assertFalse(r.curated)


class Validation(unittest.TestCase):
    def test_requires_license(self):
        bad = make_report_knowledge(
            VulnClass.IDOR, "t",
            Provenance(source_url="https://x/y"),  # no license
            root_cause="rc",
        )
        res = validate_entry(bad)
        self.assertFalse(res.ok)
        self.assertTrue(any("license" in p for p in res.problems))

    def test_requires_source_url(self):
        bad = make_report_knowledge(
            VulnClass.IDOR, "t",
            Provenance(source_url="", license="MIT"),
            root_cause="rc",
        )
        self.assertFalse(validate_entry(bad).ok)

    def test_report_needs_root_cause(self):
        bad = make_report_knowledge(VulnClass.IDOR, "t", PROV)  # no root cause
        res = validate_entry(bad)
        self.assertFalse(res.ok)
        self.assertTrue(any("root_cause" in p for p in res.problems))

    def test_good_entry_passes(self):
        self.assertTrue(validate_entry(_report()).ok)


class StoreQuery(unittest.TestCase):
    def setUp(self):
        self.store = KnowledgeStore()

    def test_dedup_idempotent(self):
        self.store.add(_report())
        self.store.add(_report())
        self.assertEqual(len(self.store), 1)

    def test_curated_only_default_hides_uncurated(self):
        self.store.add(_report(curated=False))
        self.assertEqual(self.store.query(vuln_class=VulnClass.IDOR), [])

    def test_curated_served(self):
        self.store.add(_report(curated=True))
        got = self.store.query(vuln_class=VulnClass.IDOR)
        self.assertEqual(len(got), 1)

    def test_query_by_kind(self):
        self.store.add(_report(curated=True))
        self.store.add(_spec())
        specs = self.store.query(kind=KnowledgeKind.NORMATIVE_SPEC)
        self.assertEqual(len(specs), 1)
        self.assertIsInstance(specs[0], SpecAssertion)

    def test_query_by_tag(self):
        self.store.add(_report(curated=True))
        self.assertEqual(len(self.store.query(tags=["authz"])), 1)
        self.assertEqual(len(self.store.query(tags=["nope"])), 0)

    def test_uncurated_visible_when_requested(self):
        self.store.add(_report(curated=False))
        got = self.store.query(vuln_class=VulnClass.IDOR, curated_only=False)
        self.assertEqual(len(got), 1)


class Rendering(unittest.TestCase):
    def test_report_render_is_knowledge_not_just_url(self):
        text = render_for_prompt(_report())
        self.assertIn("root cause:", text)
        self.assertIn("object id trusted", text)   # the distilled knowledge
        self.assertIn("untrusted", text)           # labeled as untrusted

    def test_spec_render_has_clause_and_level(self):
        text = render_for_prompt(_spec())
        self.assertIn("RFC9110", text)
        self.assertIn("MUST", text)


if __name__ == "__main__":
    unittest.main()
