from __future__ import annotations

from aurmanager.cli import _select_rules
from aurmanager.rules import ALL_RULES


def test_select_rules_default_is_all_rules():
    assert _select_rules(None, None) == list(ALL_RULES)


def test_select_rules_selects_known_id():
    assert [r.rule_id for r in _select_rules("RCE001", None)] == ["RCE001"]


def test_select_rules_rejects_unknown_id():
    assert _select_rules("BOGUS999", None) is None


def test_select_rules_rejects_empty_after_stripping():
    # Regression: "," (or any all-comma/whitespace value) used to strip down to
    # an empty id list, pass the vacuous `all(...)` check, and silently select
    # zero rules instead of erroring -- a full scanner bypass via the CLI.
    assert _select_rules(",", None) is None
    assert _select_rules(" , ,", None) is None
