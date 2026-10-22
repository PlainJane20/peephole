import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from peephole.datasets import (AMBIGUOUS_IDS, HERE, load_action_examples, load_input_examples)

ROOT = Path(__file__).resolve().parents[1]
WHETSTONE_FAMILIES = {"direct_override", "fake_system_message", "delimiter_spoofing", "role_play", "encoded_payload",
                      "split_payload", "quoted_reply", "multilingual", "urgency_authority", "tool_param_injection",
                      "markdown_image_exfil"}
TOOLS = {"list_emails", "read_email", "forward_email", "move_email", "post_message", "delete_email", "read_note"}

INPUTS = load_input_examples()
ACTIONS = load_action_examples()
WH = [e for e in INPUTS if e.split == "dev"]
NEW = [e for e in INPUTS if e.split == "heldout"]


def test_whetstone_copy_counts_and_hard_split():
    assert sum(e.label == "injection" for e in WH) == 55
    assert sum(e.label == "benign" for e in WH) == 72
    assert sum(e.kind == "benign-hard" for e in WH) == 36
    assert {e.family for e in WH if e.label == "injection"} == WHETSTONE_FAMILIES


def test_whetstone_ids_and_provenance_preserved():
    ids = {e.id for e in WH}
    assert "direct_override/leak_forward" in ids and "b-01" in ids and "b-72" in ids
    assert all("copied from agent-whetstone" in e.provenance for e in WH)


def test_each_whetstone_family_has_five_attacks():
    c = Counter(e.family for e in WH if e.label == "injection")
    assert set(c.values()) == {5}


def test_new_injections_at_least_60_in_at_least_5_new_families():
    inj = [e for e in NEW if e.label == "injection"]
    fams = {e.family for e in inj}
    assert len(inj) >= 60 and len(fams) >= 5
    assert not fams & WHETSTONE_FAMILIES


def test_new_benign_at_least_60_all_hard():
    ben = [e for e in NEW if e.label == "benign"]
    assert len(ben) >= 60 and all(e.kind == "benign-hard" for e in ben)
    assert len({e.family for e in ben}) >= 6


def test_new_examples_have_handwritten_provenance():
    assert all("hand-written" in e.provenance for e in NEW)


def test_ids_are_unique_across_input_and_actions():
    ids = [e.id for e in INPUTS]
    assert len(ids) == len(set(ids))
    aids = [e.id for e in ACTIONS]
    assert len(aids) == len(set(aids))


def test_actions_at_least_200_and_cover_all_kinds_and_labels():
    assert len(ACTIONS) >= 200
    assert {a.kind for a in ACTIONS} == {"consistent", "injected-deviation", "borderline-ambiguous", "over-broad",
                                         "sensitive-read", "benign-unusual"}
    assert {a.label for a in ACTIONS} == {"allow", "ask", "deny"}


def test_actions_use_only_whetstone_sandbox_tools():
    assert {a.tool_name for a in ACTIONS} <= TOOLS
    assert TOOLS <= {a.tool_name for a in ACTIONS}


def test_each_action_kind_has_enough_cases():
    c = Counter(a.kind for a in ACTIONS)
    assert min(c.values()) >= 20


def test_ambiguous_ids_exist_are_reported_and_flagged_in_data():
    assert AMBIGUOUS_IDS and AMBIGUOUS_IDS == {a.id for a in ACTIONS if a.ambiguous}
    assert all(i.startswith("act-") for i in AMBIGUOUS_IDS)
    assert 0.05 < len(AMBIGUOUS_IDS) / len(ACTIONS) < 0.3


def test_every_borderline_ambiguous_case_is_flagged_arguable():
    assert all(a.ambiguous for a in ACTIONS if a.kind == "borderline-ambiguous")


def test_heldout_families_have_both_allow_and_non_allow_actions():
    held = [a for a in ACTIONS if a.split == "heldout"]
    assert len(held) >= 40 and {a.label for a in held} >= {"allow", "deny"}
    assert {a.family for a in held} == {"lookalike_domain", "wrong_internal_recipient", "subtle_scope_creep",
                                        "authority_claim_context", "paraphrased_destination"}


def test_heldout_input_split_has_both_labels():
    assert {e.label for e in NEW} == {"injection", "benign"}


def test_dev_and_heldout_families_are_disjoint_for_actions():
    dev = {a.family for a in ACTIONS if a.split == "dev"}
    held = {a.family for a in ACTIONS if a.split == "heldout"}
    assert not dev & held


def test_all_addresses_are_reserved_or_fictional_domains():
    for e in INPUTS:
        for m in re.finditer(r"[\w.+-]+@([\w.-]+)", e.text):
            assert re.search(r"\.(example|test|invalid)$", m.group(1).rstrip(".")) or "example" in m.group(1), (e.id, m.group(0))
    for a in ACTIONS:
        blob = json.dumps(a.tool_args) + a.task + a.context
        for m in re.finditer(r"[\w.+-]+@([\w.-]+)", blob):
            dom = m.group(1).rstrip(".").lower()
            assert "example" in dom or dom.endswith(".test"), (a.id, m.group(0))


def test_no_real_looking_secrets():
    bad = re.compile(r"sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{12,}|-----BEGIN|xox[bp]-|ghp_[A-Za-z0-9]{20,}")
    for f in HERE.glob("*.jsonl"):
        assert not bad.search(f.read_text()), f.name


def test_canary_strings_are_the_fake_pattern_only():
    for f in HERE.glob("*.jsonl"):
        for m in re.finditer(r"CANARY-([A-Z0-9]+)", f.read_text()):
            assert len(m.group(1)) == 12


def test_no_employer_names_in_the_data():
    blob = "".join(f.read_text().lower() for f in HERE.glob("*.jsonl"))
    for w in ("org-a", "google", "alphabet", "anthropic", "typesafe", "org-c", "org-b", "amazon"):
        assert w not in blob, w


def test_committed_jsonl_equals_what_the_builder_would_write():
    code = ("import sys; sys.path.insert(0, 'scripts'); import build_datasets as b; "
            "sys.stdout.write(b.dump(b.input_rows()) + '\\x00' + b.dump(b.action_rows()))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(ROOT)).stdout
    ins, acts = out.split("\x00")
    assert ins == (HERE / "input_new.jsonl").read_text()
    assert acts == (HERE / "actions.jsonl").read_text()


def test_every_row_has_required_fields():
    for f, req in (("input_whetstone.jsonl", {"id", "kind", "family", "label", "split", "text", "context", "provenance"}),
                   ("input_new.jsonl", {"id", "kind", "family", "label", "split", "text", "context", "provenance"}),
                   ("actions.jsonl", {"id", "kind", "family", "label", "split", "task", "tool_name", "tool_args",
                                      "context", "ambiguous", "provenance"})):
        for line in (HERE / f).read_text().splitlines():
            assert req <= set(json.loads(line))


def test_split_filter():
    assert all(e.split == "heldout" for e in load_input_examples("heldout"))
    assert all(a.split == "dev" for a in load_action_examples("dev"))
    assert len(load_input_examples("dev")) + len(load_input_examples("heldout")) == len(INPUTS)


def test_split_sizes_are_large_enough_to_report():
    assert len([e for e in NEW if e.label == "injection"]) >= 60 and len([a for a in ACTIONS if a.split == "heldout"]) >= 40
