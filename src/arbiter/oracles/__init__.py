"""Oracles — deterministic confirmation criteria per vulnerability class.

An oracle answers, as mechanically as possible, "is this observed behavior
a real finding?" so confirmation does not rest on an LLM's opinion. The
first oracle here is the authorization matrix for IDOR / broken object
authorization. Others (client-side AST checks, CVSS scoring, business
invariants) arrive in later steps. Nothing here touches the network.
"""
