# Knowledge layer

Two kinds of knowledge, both **untrusted data** (never instructions, never
able to change scope/policy):

- **Normative specs** (RFC / WHATWG) → citable `MUST/SHOULD` assertions.
  Used mainly by the Skeptic to confirm or **refute** protocol claims.
- **Disclosed reports** → distilled examples used to **generate
  hypotheses and questions**, never to copy-and-run payloads.

Shape and store live in `src/arbiter/knowledge.py`.

## Distilled fields (per disclosed report)

Extract, do not dump: `vuln_class`, `preconditions`, `root_cause`,
`observable_signals`, `supporting_evidence`, `impact`, `false_positives`,
`mitigation`, plus `provenance` (source URL, date, license) and `tags`.

Retrieval returns these **distilled fields**, not a bare URL — the source
is carried only as a citation. (This is the fix for naive RAG, which
returns links instead of knowledge.)

## Curation gate

`curated = False` by default for reports. Only curated entries are served
for hypothesis generation (`query(..., curated_only=True)`). Rationale:
quality > volume — a large unvetted corpus mostly adds noise. Vet, then
flag `curated = True`.

## Ingesting `reddelexc/hackerone-reports`

Planned as a **separate, later step**, gated on open decision #4
(license + dedup) in `docs/DESIGN.md`. Not done yet. The intended parser
will:

1. Read the corpus **selectively** (by vuln class / relevance), never
   shipping the whole corpus to a model.
2. Distill each example into the fields above (a small model or rules),
   attaching provenance (source URL + date) and a `dedup` key.
3. Record entries as **uncurated**; promote to `curated` only after a
   quality pass.
4. Respect **license and provenance** before any redistribution
   (`validate_entry` refuses entries without source URL + license).

Until that step is approved, the store simply holds hand-added, vetted
entries. Nothing here fetches the network.
