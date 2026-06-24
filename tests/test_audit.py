"""
test_audit.py — Layer 6 (Structured Audit) behavior spec.

Written test-first (TDD). Defines the append-only, tamper-evident audit log:
a 9-field JSON-Lines base schema + SHA-256 content hashes (write events) + a
per-entry hash chain (seq / prev_hash / entry_hash) that verify() validates and
that detects edits / inserts / deletes / reorders. Fail-open by default;
tamper-EVIDENT, not tamper-proof (see docs/AUDIT_SCHEMA.md).

Author: esoteric1entity, AI-Assisted
License: Apache-2.0
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_shield import audit

BASE_FIELDS = ("ts", "actor", "role", "session", "machine",
               "action", "target", "outcome", "details")


def _entries(p: Path):
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


# ----------------------------------------------------------- core record contract
def test_record_appends_one_jsonl_entry_with_base_fields(tmp_path):
    log = audit.AuditLog(path=tmp_path / "audit.jsonl")
    log.record(action="bash_guard.check", target="rm -rf /", outcome="deny")

    entries = _entries(tmp_path / "audit.jsonl")
    assert len(entries) == 1
    e = entries[0]
    for field in BASE_FIELDS:
        assert field in e, f"missing base field: {field}"
    assert e["action"] == "bash_guard.check"
    assert e["target"] == "rm -rf /"
    assert e["outcome"] == "deny"


# ----------------------------------------------------------- hash chain
GENESIS = "0" * 64


def test_chain_links_and_increments(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    log.record(action="a", target="t1", outcome="allow")
    log.record(action="b", target="t2", outcome="deny")
    log.record(action="c", target="t3", outcome="ask")

    es = _entries(tmp_path / "a.jsonl")
    assert [e["seq"] for e in es] == [1, 2, 3]
    assert es[0]["prev_hash"] == GENESIS
    # each prev_hash links to the prior entry's entry_hash
    assert es[1]["prev_hash"] == es[0]["entry_hash"]
    assert es[2]["prev_hash"] == es[1]["entry_hash"]
    for e in es:
        assert len(e["entry_hash"]) == 64
        int(e["entry_hash"], 16)  # valid hex


def test_verify_passes_on_clean_log(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    for i in range(5):
        log.record(action="x", target=f"t{i}", outcome="allow")

    result = log.verify()
    assert result.ok is True
    assert result.count == 5
    assert result.broken_at is None


def test_verify_on_empty_log_is_ok(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    result = log.verify()
    assert result.ok is True
    assert result.count == 0


# ----------------------------------------------------------- tamper detection
def _rewrite(p: Path, lines: list[str]) -> None:
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_log(tmp_path: Path, n: int = 4):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(n):
        log.record(action="x", target=f"t{i}", outcome="allow")
    return log, p


def test_verify_detects_edit(tmp_path):
    log, p = _make_log(tmp_path)
    lines = p.read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[1])
    e["outcome"] = "deny"  # attacker edits a field but can't fix the stored hash
    lines[1] = json.dumps(e)
    _rewrite(p, lines)
    r = log.verify()
    assert r.ok is False
    assert r.broken_at == 2


def test_verify_detects_deletion(tmp_path):
    log, p = _make_log(tmp_path)
    lines = p.read_text(encoding="utf-8").splitlines()
    del lines[1]
    _rewrite(p, lines)
    assert log.verify().ok is False


def test_verify_detects_insertion(tmp_path):
    log, p = _make_log(tmp_path)
    lines = p.read_text(encoding="utf-8").splitlines()
    lines.insert(1, lines[0])  # inject a forged (duplicate) line
    _rewrite(p, lines)
    assert log.verify().ok is False


def test_verify_detects_reorder(tmp_path):
    log, p = _make_log(tmp_path)
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    _rewrite(p, lines)
    assert log.verify().ok is False


# ----------------------------------------------------------- write events + content hashes
def test_record_write_adds_content_sha256_fields(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    log.record_write(target="/x/.env", outcome="allow",
                     content_before=b"old", content_after=b"new")

    e = _entries(tmp_path / "a.jsonl")[0]
    for field in BASE_FIELDS:
        assert field in e, f"missing base field: {field}"
    assert e["content_sha256_before"] == hashlib.sha256(b"old").hexdigest()
    assert e["content_sha256_after"] == hashlib.sha256(b"new").hexdigest()
    assert e["action"] == "write"   # default action for a write event
    assert e["target"] == "/x/.env"
    assert e["outcome"] == "allow"


def test_record_write_null_content_when_absent(tmp_path):
    # e.g. a blocked write that never produced before/after bytes
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    log.record_write(target="/x/.env", outcome="deny")

    e = _entries(tmp_path / "a.jsonl")[0]
    assert e["content_sha256_before"] is None
    assert e["content_sha256_after"] is None


def test_record_write_accepts_str_content(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    log.record_write(target="/x", outcome="allow",
                     content_before="old", content_after="new")

    e = _entries(tmp_path / "a.jsonl")[0]
    assert e["content_sha256_before"] == hashlib.sha256(b"old").hexdigest()
    assert e["content_sha256_after"] == hashlib.sha256(b"new").hexdigest()


def test_general_non_write_record_has_no_content_fields(tmp_path):
    # general preset (default): a non-write event is exactly the 9 base fields
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    log.record(action="bash_guard.check", target="ls", outcome="allow")

    e = _entries(tmp_path / "a.jsonl")[0]
    assert "content_sha256_before" not in e
    assert "content_sha256_after" not in e


def test_chain_stays_valid_across_mixed_events(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    log.record(action="a", target="t1", outcome="allow")
    log.record_write(target="/x", outcome="allow", content_before=b"1", content_after=b"2")
    log.record(action="b", target="t3", outcome="deny")

    r = log.verify()
    assert r.ok is True
    assert r.count == 3


# ----------------------------------------------------------- fail-open / never-raises
def test_record_never_raises_on_unwritable_path_fail_open(tmp_path):
    # path points at a directory → open(..., "a") cannot succeed on any OS
    d = tmp_path / "is_a_dir"
    d.mkdir()
    log = audit.AuditLog(path=d)
    result = log.record(action="x", target="t", outcome="allow")
    assert result is None  # fail-open flag; the guarded operation must not see an exception


def test_record_write_never_raises_fail_open(tmp_path):
    d = tmp_path / "is_a_dir"
    d.mkdir()
    log = audit.AuditLog(path=d)
    assert log.record_write(target="t", outcome="allow", content_before=b"x") is None


def test_record_never_raises_on_unserializable_details_fail_open(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    result = log.record(action="x", target="t", outcome="allow", details={"bad": object()})
    assert result is None
    assert not p.exists() or p.read_text(encoding="utf-8") == ""  # nothing partial written


# A non-finite float in details used
# to be written as a bare NaN/Infinity token — invalid JSON that breaks every
# parser of the log. allow_nan=False now makes it raise (caught by _append:
# fail-open drops the entry), so every line on disk is strict-parseable.
def test_record_emits_only_parseable_json_on_non_finite(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    assert log.record(action="ok", target="t", outcome="allow") is not None  # one valid line
    # Non-finite details must NOT produce a bare NaN/Infinity line:
    assert log.record(action="bad", target="t", outcome="allow", details={"v": float("nan")}) is None
    assert log.record(action="bad", target="t", outcome="allow", details={"v": float("inf")}) is None
    assert log.record(action="bad", target="t", outcome="allow", details={"v": float("-inf")}) is None

    def _reject(tok):  # parse_constant fires only for NaN / Infinity / -Infinity
        raise AssertionError(f"non-finite JSON constant written to audit log: {tok}")

    text = p.read_text(encoding="utf-8")
    for line in text.splitlines():
        json.loads(line, parse_constant=_reject)   # must not raise — strict JSON only
    assert text.count("\n") == 1                    # the 3 non-finite entries were dropped


def test_fail_closed_raises_audit_write_error(tmp_path):
    d = tmp_path / "is_a_dir"
    d.mkdir()
    log = audit.AuditLog(path=d, fail_mode="closed")
    with pytest.raises(audit.AuditWriteError):
        log.record(action="x", target="t", outcome="allow")


def test_invalid_fail_mode_rejected_at_construction(tmp_path):
    with pytest.raises(ValueError):
        audit.AuditLog(path=tmp_path / "a.jsonl", fail_mode="halt")


def test_creates_missing_parent_dirs(tmp_path):
    log = audit.AuditLog(path=tmp_path / "nested" / "deep" / "audit.jsonl")
    e = log.record(action="x", target="t", outcome="allow")
    assert e is not None
    assert (tmp_path / "nested" / "deep" / "audit.jsonl").exists()


# ----------------------------------------------------------- compliance presets
def test_general_preset_defaults(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")  # general is the default
    assert log.preset == "general"
    assert log.retention_days == 90
    assert log.fail_mode == "open"


def test_healthcare_preset_defaults(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl", preset="healthcare")
    assert log.retention_days == 365
    assert log.fail_mode == "closed"  # "no action without an audit record" by default


def test_biotech_preset_matches_healthcare(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl", preset="biotech")
    assert log.retention_days == 365
    assert log.fail_mode == "closed"


def test_healthcare_non_write_carries_null_content_fields(tmp_path):
    # healthcare = 11 fields always: a non-write event still carries the two
    # content-hash slots (null), so every row has a uniform shape
    log = audit.AuditLog(path=tmp_path / "a.jsonl", preset="healthcare")
    log.record(action="bash_guard.check", target="ls", outcome="allow")

    e = _entries(tmp_path / "a.jsonl")[0]
    assert e["content_sha256_before"] is None
    assert e["content_sha256_after"] is None


def test_explicit_fail_mode_overrides_preset(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl", preset="healthcare", fail_mode="open")
    assert log.fail_mode == "open"


def test_invalid_preset_rejected_at_construction(tmp_path):
    with pytest.raises(ValueError):
        audit.AuditLog(path=tmp_path / "a.jsonl", preset="hipaa")


# ----------------------------------------------------------- CLI --verify (exit 0/1/2)
def _seed(tmp_path, n=3):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(n):
        log.record(action="x", target=f"t{i}", outcome="allow")
    return p


def test_cli_verify_intact_returns_0(tmp_path):
    p = _seed(tmp_path)
    assert audit.main(["--verify", str(p)]) == 0


def test_cli_verify_tampered_returns_1(tmp_path):
    p = _seed(tmp_path)
    lines = p.read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[1])
    e["outcome"] = "deny"
    lines[1] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert audit.main(["--verify", str(p)]) == 1


def test_cli_verify_missing_returns_2(tmp_path):
    assert audit.main(["--verify", str(tmp_path / "nope.jsonl")]) == 2


def test_cli_verify_unreadable_dir_returns_2(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    assert audit.main(["--verify", str(d)]) == 2


def test_cli_module_entry_subprocess(tmp_path):
    # proves `python -m agent_shield.audit --verify <path>` actually runs
    p = _seed(tmp_path, n=2)
    pkg_root = Path(audit.__file__).resolve().parent.parent
    r = subprocess.run(
        [sys.executable, "-m", "agent_shield.audit", "--verify", str(p)],
        cwd=pkg_root, capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "intact" in r.stdout.lower()


# =================================================================== Tier-1 anchor
# ----- Group A: off-by-default seam (anchor adds zero behavior unless attached) -----
def test_anchor_defaults_to_none_off(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    assert log.anchor is None


def test_record_with_no_anchor_returns_identical_entry_shape(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    e = log.record(action="x", target="t", outcome="allow")
    assert e is not None
    assert set(e) == set(BASE_FIELDS) | {"seq", "prev_hash", "entry_hash"}
    assert log.verify().ok is True


def test_anchor_none_creates_no_anchor_artifacts(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")
    files = {p.name for p in tmp_path.iterdir()}
    assert files == {"a.jsonl"}  # anchor never wrote anything


# ----- anchor test helpers -----
class CollectorShipper:
    """Records every head it is handed, in order."""

    def __init__(self):
        self.heads = []

    def __call__(self, head):
        self.heads.append(head)


class RaisingShipper:
    def __init__(self, exc=None):
        self.exc = exc or RuntimeError("anchor boom")
        self.calls = 0

    def __call__(self, head):
        self.calls += 1
        raise self.exc


class FlakyShipper:
    """Fails its first `fail_times` calls, then collects."""

    def __init__(self, fail_times=1):
        self.fail_times = fail_times
        self.calls = 0
        self.heads = []

    def __call__(self, head):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("flaky anchor")
        self.heads.append(head)


class FakeClock:
    """Deterministic monotonic clock for cadence tests (no real sleep)."""

    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def _sysexit_shipper(head):
    sys.exit(1)


# ----- Anchor config validation -----
def test_anchor_rejects_negative_every_n():
    with pytest.raises(ValueError):
        audit.Anchor(every_n=-1)


def test_anchor_rejects_negative_every_minutes():
    with pytest.raises(ValueError):
        audit.Anchor(every_minutes=-5)


def test_anchor_rejects_zero_cadence_with_shipper():
    """A sink with both triggers disabled would silently turn anchoring off."""
    with pytest.raises(ValueError):
        audit.Anchor(every_n=0, every_minutes=0, shipper=lambda head: None)


def test_anchor_rejects_zero_cadence_with_local_path():
    with pytest.raises(ValueError):
        audit.Anchor(every_n=0, every_minutes=0, local_path=Path("/tmp/anchor.jsonl"))


def test_anchor_allows_zero_cadence_when_no_sink():
    """An Anchor without a sink is a deliberate no-op, so zero cadence is fine."""
    a = audit.Anchor(every_n=0, every_minutes=0)
    assert a.local_path is None
    assert a.shipper is None


# ----- Group B: head shape + shipper handoff -----
def test_shipper_receives_head_on_trigger(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=collector))
    log.record(action="x", target="t", outcome="allow")
    assert len(collector.heads) == 1
    assert isinstance(collector.heads[0], audit.AnchorHead)


def test_head_has_only_seq_entry_hash_ts(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=collector))
    log.record(action="x", target="t", outcome="allow")
    names = {f.name for f in dataclasses.fields(collector.heads[0])}
    assert names == {"seq", "entry_hash", "ts"}


def test_head_values_match_written_entry(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=collector))
    e = log.record(action="x", target="t", outcome="allow")
    head = collector.heads[0]
    assert head.seq == e["seq"]
    assert head.entry_hash == e["entry_hash"]   # entry's OWN stored hash (chain tip), not a re-hash
    assert head.ts == e["ts"]                   # copied, not re-clocked


def test_head_carries_no_pii(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=collector))
    log.record(action="x", target="/home/alice/.ssh/id_rsa", outcome="allow",
               actor="alice@corp.example", session="sek-SECRET-123",
               details={"ssn": "000-00-0000"})
    head_json = json.dumps(dataclasses.asdict(collector.heads[0]))
    for sentinel in ("alice@corp.example", "/home/alice/.ssh/id_rsa", "sek-SECRET-123", "000-00-0000"):
        assert sentinel not in head_json


# ----- Group C: count cadence -----
def test_count_cadence_ships_on_exact_nth_not_before(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=3, every_minutes=0, shipper=collector))
    log.record(action="a", target="t1", outcome="allow")
    log.record(action="b", target="t2", outcome="allow")
    assert collector.heads == []        # not before the 3rd
    log.record(action="c", target="t3", outcome="allow")
    assert len(collector.heads) == 1
    assert collector.heads[0].seq == 3


def test_count_cadence_resets_after_firing(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=3, every_minutes=0, shipper=collector))
    for i in range(6):
        log.record(action="x", target=f"t{i}", outcome="allow")
    assert [h.seq for h in collector.heads] == [3, 6]


def test_count_cadence_derives_from_disk_seq_restart_safe(tmp_path):
    p = tmp_path / "a.jsonl"
    collector = CollectorShipper()
    log1 = audit.AuditLog(path=p,
                          anchor=audit.Anchor(every_n=100, every_minutes=0, shipper=collector))
    for i in range(50):
        log1.record(action="x", target=f"t{i}", outcome="allow")
    assert collector.heads == []                       # 50 < 100
    # NEW instance, same path + same cadence; fresh in-memory baseline
    log2 = audit.AuditLog(path=p,
                          anchor=audit.Anchor(every_n=100, every_minutes=0, shipper=collector))
    for i in range(50):                                # on-disk seq 51..100
        log2.record(action="y", target=f"u{i}", outcome="allow")
    assert len(collector.heads) == 1
    assert collector.heads[0].seq == 100               # baseline derives from on-disk seq


def test_count_cadence_counts_record_and_record_write_equally(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=2, every_minutes=0, shipper=collector))
    log.record(action="a", target="t", outcome="allow")                  # seq 1
    log.record_write(target="/x", outcome="allow", content_after=b"y")   # seq 2 -> fires
    assert len(collector.heads) == 1
    assert collector.heads[0].seq == 2


# ----- Group D: time cadence (injected clock) -----
def test_time_cadence_does_not_ship_before_interval(tmp_path):
    collector = CollectorShipper()
    fc = FakeClock(0.0)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=0, every_minutes=15, shipper=collector, clock=fc))
    log.record(action="x", target="t", outcome="allow")   # seeds baseline at t=0
    fc.advance(14 * 60)
    log.record(action="y", target="u", outcome="allow")
    assert collector.heads == []


def test_time_cadence_ships_when_interval_elapsed(tmp_path):
    collector = CollectorShipper()
    fc = FakeClock(0.0)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=0, every_minutes=15, shipper=collector, clock=fc))
    log.record(action="x", target="t", outcome="allow")   # seed t=0
    fc.advance(15 * 60)
    log.record(action="y", target="u", outcome="allow")
    assert len(collector.heads) == 1


def test_time_cadence_resets_baseline_after_firing(tmp_path):
    collector = CollectorShipper()
    fc = FakeClock(0.0)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=0, every_minutes=15, shipper=collector, clock=fc))
    log.record(action="s", target="t", outcome="allow")   # seed t=0
    fc.advance(15 * 60)
    log.record(action="a", target="t", outcome="allow")   # fires at t=900
    fc.advance(14 * 60)
    log.record(action="b", target="t", outcome="allow")   # only 14 min since last -> no fire
    assert len(collector.heads) == 1
    fc.advance(1 * 60)
    log.record(action="c", target="t", outcome="allow")   # now 15 min since last -> fire
    assert len(collector.heads) == 2


def test_time_cadence_disabled_when_every_minutes_zero(tmp_path):
    collector = CollectorShipper()
    fc = FakeClock(0.0)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=100, every_minutes=0, shipper=collector, clock=fc))
    log.record(action="x", target="t", outcome="allow")
    fc.advance(10000 * 60)                                 # huge jump must NOT trigger (time disabled)
    log.record(action="y", target="u", outcome="allow")
    assert collector.heads == []


# ----- Group E: whichever-first -----
def test_count_fires_first_when_count_reached_before_time(tmp_path):
    collector = CollectorShipper()
    fc = FakeClock(0.0)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=3, every_minutes=15, shipper=collector, clock=fc))
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")   # clock unmoved -> count wins
    assert [h.seq for h in collector.heads] == [3]


def test_time_fires_first_when_time_elapsed_before_count(tmp_path):
    collector = CollectorShipper()
    fc = FakeClock(0.0)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=100, every_minutes=15, shipper=collector, clock=fc))
    log.record(action="x", target="t", outcome="allow")   # seed t=0 (seq 1)
    fc.advance(15 * 60)
    log.record(action="y", target="u", outcome="allow")   # seq 2: time fires before count(100)
    assert len(collector.heads) == 1
    assert collector.heads[0].seq == 2


# ----- Group F: default cadence (never per-event) -----
def test_defaults_n100_t15_single_record_ships_nothing(tmp_path):
    collector = CollectorShipper()
    log = audit.AuditLog(path=tmp_path / "a.jsonl", anchor=audit.Anchor(shipper=collector))
    log.record(action="x", target="t", outcome="allow")
    assert collector.heads == []          # never anchors on a single event


def test_defaults_ship_only_after_100_records(tmp_path):
    collector = CollectorShipper()
    fc = FakeClock(0.0)                    # frozen clock isolates count from the 15-min default
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(shipper=collector, clock=fc))
    for i in range(99):
        log.record(action="x", target=f"t{i}", outcome="allow")
    assert collector.heads == []
    log.record(action="x", target="t99", outcome="allow")   # the 100th
    assert len(collector.heads) == 1
    assert collector.heads[0].seq == 100


# ----- Group G: built-in local-path shipper + BYO precedence -----
def test_local_path_shipper_writes_head_line_on_trigger(tmp_path):
    anchor_file = tmp_path / "anchor.jsonl"
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(local_path=anchor_file, every_n=1, every_minutes=0))
    e = log.record(action="x", target="t", outcome="allow")
    lines = [l for l in anchor_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["seq"] == e["seq"]
    assert rec["entry_hash"] == e["entry_hash"]
    assert rec["ts"] == e["ts"]


def test_local_path_multiple_anchors_append_not_overwrite(tmp_path):
    anchor_file = tmp_path / "anchor.jsonl"
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(local_path=anchor_file, every_n=1, every_minutes=0))
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")
    recs = [json.loads(l) for l in anchor_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert [r["seq"] for r in recs] == [1, 2, 3]   # appended in order, not overwritten


def test_local_path_file_is_separate_from_main_log(tmp_path):
    main = tmp_path / "a.jsonl"
    anchor_file = tmp_path / "anchor.jsonl"
    log = audit.AuditLog(path=main,
                         anchor=audit.Anchor(local_path=anchor_file, every_n=1, every_minutes=0))
    log.record(action="x", target="t", outcome="allow")
    assert anchor_file != main
    assert all("anchored_at" not in e for e in _entries(main))   # main log untouched by anchoring


def test_byo_shipper_wins_over_local_path(tmp_path):
    collector = CollectorShipper()
    anchor_file = tmp_path / "anchor.jsonl"
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(local_path=anchor_file, shipper=collector,
                                             every_n=1, every_minutes=0))
    log.record(action="x", target="t", outcome="allow")
    assert len(collector.heads) == 1       # explicit shipper used
    assert not anchor_file.exists()         # local_path NOT written


# ----- Group H: fail-open / never-raises -----
def test_record_returns_entry_when_shipper_raises(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=RaisingShipper()))
    e = log.record(action="x", target="t", outcome="allow")
    assert e is not None
    assert e["seq"] == 1


def test_shipper_exception_does_not_propagate_and_warns_stderr(tmp_path, capsys):
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=RaisingShipper()))
    log.record(action="x", target="t", outcome="allow")   # must not raise
    assert "anchor" in capsys.readouterr().err.lower()


def test_main_log_intact_after_shipper_failure(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p,
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=RaisingShipper()))
    log.record(action="audited-op", target="t", outcome="allow")
    assert log.verify().ok is True
    assert "audited-op" in [e["action"] for e in _entries(p)]


def test_local_path_shipper_failure_is_also_fail_open(tmp_path):
    d = tmp_path / "anchor_is_a_dir"
    d.mkdir()
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(local_path=d, every_n=1, every_minutes=0))
    e = log.record(action="x", target="t", outcome="allow")
    assert e is not None
    assert log.anchor_gap is True


def test_anchor_fail_open_even_in_fail_closed_mode(tmp_path):
    d = tmp_path / "anchor_is_a_dir"
    d.mkdir()
    # MAIN log writable; only the ANCHOR target is broken -> record must still SUCCEED
    log = audit.AuditLog(path=tmp_path / "a.jsonl", fail_mode="closed",
                         anchor=audit.Anchor(local_path=d, every_n=1, every_minutes=0))
    e = log.record(action="x", target="t", outcome="allow")
    assert e is not None                # no AuditWriteError from an anchor hiccup
    assert log.anchor_gap is True


def test_shipper_calling_sys_exit_does_not_kill_record(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=_sysexit_shipper))
    e = log.record(action="x", target="t", outcome="allow")   # SystemExit must be swallowed
    assert e is not None


# ----- Group I: gap flag + tamper-evident gap marker + retry -----
def test_shipper_failure_sets_anchor_gap_flag(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=RaisingShipper()))
    log.record(action="x", target="t", outcome="allow")
    assert log.anchor_gap is True


def test_successful_ship_clears_anchor_gap(tmp_path):
    flaky = FlakyShipper(fail_times=1)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=flaky))
    log.record(action="x", target="t", outcome="allow")   # fails -> gap set
    assert log.anchor_gap is True
    log.record(action="y", target="u", outcome="allow")   # retry succeeds -> gap cleared
    assert log.anchor_gap is False


def test_failed_anchor_writes_error_marker_into_main_log(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p,
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=RaisingShipper()))
    log.record(action="x", target="t", outcome="allow")
    markers = [e for e in _entries(p) if e["action"] == "audit.anchor"]
    assert len(markers) == 1
    assert markers[0]["outcome"] == "error"
    assert log.verify().ok is True        # the gap marker is itself inside the tamper-evident chain


def test_gap_marker_is_reentrancy_guarded_no_recursion(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p,
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=RaisingShipper()))
    log.record(action="x", target="t", outcome="allow")
    markers = [e for e in _entries(p) if e["action"] == "audit.anchor"]
    assert len(markers) == 1              # marker write did not recurse into another anchor


def test_missed_anchor_retried_on_next_cadence(tmp_path):
    flaky = FlakyShipper(fail_times=1)
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=flaky))
    log.record(action="x", target="t", outcome="allow")   # 1st trigger fails (baseline not advanced)
    assert flaky.heads == []
    log.record(action="y", target="u", outcome="allow")   # re-attempt succeeds
    assert len(flaky.heads) == 1


# ----- Group J: local-path hazards -----
def test_local_path_creates_missing_parent_dirs(tmp_path):
    anchor_file = tmp_path / "nested" / "deep" / "anchor.jsonl"
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(local_path=anchor_file, every_n=1, every_minutes=0))
    log.record(action="x", target="t", outcome="allow")
    assert anchor_file.exists()


# ----- Group K: "never phones home" egress guarantee (AST-enforced, not substring grep) -----
_PKG_DIR = Path(audit.__file__).resolve().parent          # agent_shield/
_SHIELD_ROOT = _PKG_DIR.parent                            # the package repo root
_PKG_PY = sorted(_PKG_DIR.glob("*.py"))
_BANNED_IMPORT_ROOTS = {"urllib", "http", "httpx", "requests", "aiohttp",
                        "ftplib", "smtplib", "ssl", "asyncio", "subprocess", "ctypes"}
_BANNED_SOCKET_ATTRS = {"socket", "connect", "connect_ex", "bind", "sendto",
                        "send", "sendall", "create_connection"}
_BANNED_OS_ATTRS = {"system", "popen", "execv", "execve", "execvp", "execvpe",
                    "execl", "execlp", "execle", "execlpe",
                    "spawnv", "spawnve", "spawnl", "spawnle",
                    "spawnvp", "spawnvpe", "spawnlp", "spawnlpe",
                    "posix_spawn", "posix_spawnp"}
_BANNED_BUILTINS = {"eval", "exec", "__import__"}
_IMPORTLIB_DYNAMIC_ATTRS = {"import_module"}
_IMPORTLIB_UTIL_DYNAMIC_ATTRS = {"spec_from_file_location", "module_from_spec"}


def _root(name: str) -> str:
    return name.split(".")[0]


def _egress_offenders(source: str, name: str = "<src>") -> list[str]:
    """AST scan for any network / native-exec / dynamic-code egress capability —
    alias- and from-import-robust. A naive `socket.<attr>` / root-only scan misses
    `import socket as s; s.connect(...)`, `from socket import create_connection`,
    `subprocess`, `os.system`, `import os as o; o.system(...)`, `__import__(...)`,
    and `importlib.import_module(...)`. This is a best-effort lint, NOT a sandbox.
    `socket.gethostname`, ordinary `os` use, and read-only `importlib.metadata` are
    intentionally allowed.
    """
    tree = ast.parse(source, filename=name)
    offenders: list[str] = []
    socket_names: set[str] = set()              # local names bound to the socket module
    from_socket_banned: set[str] = set()        # names imported FROM socket that are egress attrs
    os_names: set[str] = set()                  # local names bound to the os module
    from_os_banned: set[str] = set()            # names imported FROM os that are banned attrs
    importlib_names: set[str] = set()           # local names bound to importlib
    from_importlib_banned: set[str] = set()     # names imported FROM importlib that are dynamic loaders
    importlib_util_names: set[str] = set()      # local names bound to importlib.util
    importlib_util_direct: set[str] = set()     # names imported directly FROM importlib.util

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                root = _root(a.name)
                if root in _BANNED_IMPORT_ROOTS:
                    offenders.append(f"{name}: import {a.name}")
                if root == "socket":
                    socket_names.add(a.asname or root)
                if root == "os":
                    os_names.add(a.asname or _root(a.name))
                if a.name == "importlib" or a.name.startswith("importlib."):
                    local = a.asname or a.name
                    if a.name == "importlib":
                        importlib_names.add(local)
                    elif a.name == "importlib.util":
                        importlib_util_names.add(local)
        elif isinstance(node, ast.ImportFrom):
            root = _root(node.module or "")
            if root in _BANNED_IMPORT_ROOTS:
                offenders.append(f"{name}: from {node.module} import ...")
            if root == "socket":
                for a in node.names:
                    if a.name in _BANNED_SOCKET_ATTRS:
                        from_socket_banned.add(a.asname or a.name)
            if node.module == "os":
                for a in node.names:
                    if a.name in _BANNED_OS_ATTRS:
                        from_os_banned.add(a.asname or a.name)
            # importlib.metadata and importlib.util are allowed as imports; only
            # dynamic loaders (import_module, spec_from_file_location) are banned.
            if node.module == "importlib":
                for a in node.names:
                    if a.name == "import_module":
                        from_importlib_banned.add(a.asname or a.name)
                    elif a.name == "util":
                        importlib_util_names.add(a.asname or a.name)
            elif node.module == "importlib.util":
                for a in node.names:
                    if a.name in _IMPORTLIB_UTIL_DYNAMIC_ATTRS:
                        importlib_util_direct.add(a.asname or a.name)

    def _is_local_agent_shield_import(node: ast.Call) -> bool:
        """PEP-562 lazy submodule loading is intentional, not an egress vector.

        Recognizes both a literal ``"agent_shield." + name`` BinOp (used in
        ``__init__.py`` so the linter can see the concrete prefix) and a plain
        constant module name.
        """
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.startswith("agent_shield.")
        if isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            left = first.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str):
                return left.value.startswith("agent_shield.")
        return False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if isinstance(fn, ast.Attribute):
            base_name = ""
            if isinstance(fn.value, ast.Name):
                base_name = fn.value.id
            elif isinstance(fn.value, ast.Attribute) and isinstance(fn.value.value, ast.Name):
                # chained: importlib.util.<attr>
                base_name = f"{fn.value.value.id}.{fn.value.attr}"
            if base_name in socket_names and fn.attr in _BANNED_SOCKET_ATTRS:
                offenders.append(f"{name}: {base_name}.{fn.attr}(...)")
            elif base_name in os_names and fn.attr in _BANNED_OS_ATTRS:
                offenders.append(f"{name}: {base_name}.{fn.attr}(...)")
            elif base_name in importlib_names and fn.attr in _IMPORTLIB_DYNAMIC_ATTRS:
                if not _is_local_agent_shield_import(node):
                    offenders.append(f"{name}: {base_name}.{fn.attr}(...)")
            elif base_name in importlib_util_names and fn.attr in _IMPORTLIB_UTIL_DYNAMIC_ATTRS:
                offenders.append(f"{name}: {base_name}.{fn.attr}(...)")
            elif (
                base_name == "importlib.util"
                and "importlib" in importlib_names
                and fn.attr in _IMPORTLIB_UTIL_DYNAMIC_ATTRS
            ):
                # ``import importlib`` makes ``importlib.util`` reachable; catch the
                # chained dynamic loader call without requiring a separate util import.
                offenders.append(f"{name}: importlib.util.{fn.attr}(...)")
        elif isinstance(fn, ast.Name):
            if fn.id in from_socket_banned:
                offenders.append(f"{name}: {fn.id}(...) (from socket)")
            elif fn.id in from_os_banned:
                offenders.append(f"{name}: {fn.id}(...) (from os)")
            elif fn.id in from_importlib_banned:
                if not _is_local_agent_shield_import(node):
                    offenders.append(f"{name}: {fn.id}(...) (from importlib)")
            elif fn.id in importlib_util_direct:
                offenders.append(f"{name}: {fn.id}(...) (from importlib.util)")
            elif fn.id in _BANNED_BUILTINS:
                offenders.append(f"{name}: {fn.id}(...)")
    return offenders


def test_no_egress_in_shipped_package():
    """'never phones home', enforced: no shipped module imports a network/native-exec
    library or calls a socket-connect / os.system / eval-family egress vector. AST-based
    and alias/from-import-robust (best-effort lint, not a sandbox). gethostname is allowed."""
    offenders: list[str] = []
    for py in _PKG_PY:
        offenders += _egress_offenders(py.read_text(encoding="utf-8"), py.name)
    assert offenders == [], f"egress in shipped package breaks 'never phones home': {offenders}"


def test_record_works_with_sockets_disabled(tmp_path, monkeypatch):
    import socket as _socket

    def _boom(*a, **k):
        raise OSError("network disabled in test")

    monkeypatch.setattr(_socket, "socket", _boom)
    anchor_file = tmp_path / "anchor.jsonl"
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(local_path=anchor_file, every_n=1, every_minutes=0))
    e = log.record(action="x", target="t", outcome="allow")
    assert e is not None             # shipped path used only the filesystem, never a socket
    assert anchor_file.exists()


def test_anchor_has_no_url_endpoint_parameter():
    names = {f.name for f in dataclasses.fields(audit.Anchor)}
    for forbidden in ("url", "endpoint", "webhook", "host", "port"):
        assert forbidden not in names   # the sole remote seam is the user-supplied shipper


def test_audit_schema_doc_exists():
    assert (_SHIELD_ROOT / "docs" / "AUDIT_SCHEMA.md").exists(), (
        "docs/AUDIT_SCHEMA.md is referenced by audit.py but missing"
    )


def test_doc_says_never_phones_home_and_tamper_evident_not_proof():
    readme = (_SHIELD_ROOT / "README.md").read_text(encoding="utf-8")
    schema = (_SHIELD_ROOT / "docs" / "AUDIT_SCHEMA.md").read_text(encoding="utf-8")
    blob = (readme + "\n" + schema).lower()
    assert "never phones home" in blob
    assert "tamper-evident" in blob
    assert "tamper-proof" in blob        # in the honest "not tamper-proof" statement
    assert "tamper-resistant" in blob
    assert "same volume" in blob or "independent" in blob   # the independence caveat


# ----- Group M: capstone — the tamper-RESISTANCE payoff -----
def test_anchor_file_verifiable_against_main_log(tmp_path):
    main = tmp_path / "a.jsonl"
    anchor_file = tmp_path / "anchor.jsonl"
    log = audit.AuditLog(path=main,
                         anchor=audit.Anchor(local_path=anchor_file, every_n=1, every_minutes=0))
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")
    main_by_seq = {e["seq"]: e["entry_hash"] for e in _entries(main)}
    anchor_recs = [json.loads(l) for l in anchor_file.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert anchor_recs
    for rec in anchor_recs:
        assert main_by_seq[rec["seq"]] == rec["entry_hash"]   # head matches main log at that seq


def test_anchor_detects_main_log_rewrite_from_genesis(tmp_path):
    main = tmp_path / "a.jsonl"
    anchor_file = tmp_path / "anchor.jsonl"
    log = audit.AuditLog(path=main,
                         anchor=audit.Anchor(local_path=anchor_file, every_n=1, every_minutes=0))
    for i in range(3):
        log.record(action="real", target=f"t{i}", outcome="allow")
    anchored = [json.loads(l) for l in anchor_file.read_text(encoding="utf-8").splitlines() if l.strip()]

    # Attacker rewrites the main log from genesis with an internally-valid chain.
    main.unlink()
    forged = audit.AuditLog(path=main)  # no anchor
    for i in range(3):
        forged.record(action="forged", target=f"t{i}", outcome="allow")
    assert forged.verify().ok is True   # tamper-EVIDENT alone CANNOT catch a full rewrite

    forged_by_seq = {e["seq"]: e["entry_hash"] for e in _entries(main)}
    divergence = [r["seq"] for r in anchored if forged_by_seq.get(r["seq"]) != r["entry_hash"]]
    assert divergence, "external anchor failed to detect a full-genesis rewrite"


# ===== Review fixes ===================================================================
# ----- Fix A: anchor exception discipline — host-safe (Exception+SystemExit) but
#       operator-interruptible (KeyboardInterrupt propagates) -----
def _systemexit_clock():
    raise SystemExit(3)


def test_anchor_clock_systemexit_does_not_escape_fail_open(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0,
                                             shipper=CollectorShipper(), clock=_systemexit_clock))
    e = log.record(action="x", target="t", outcome="allow")   # SystemExit from clock must not escape
    assert e is not None


def test_anchor_clock_systemexit_does_not_escape_fail_closed(tmp_path):
    log = audit.AuditLog(path=tmp_path / "a.jsonl", fail_mode="closed",
                         anchor=audit.Anchor(every_n=1, every_minutes=0,
                                             shipper=CollectorShipper(), clock=_systemexit_clock))
    e = log.record(action="x", target="t", outcome="allow")   # must NOT raise AuditWriteError either
    assert e is not None


def test_anchor_shipper_keyboardinterrupt_propagates(tmp_path):
    def ki_shipper(head):
        raise KeyboardInterrupt

    log = audit.AuditLog(path=tmp_path / "a.jsonl",
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=ki_shipper))
    with pytest.raises(KeyboardInterrupt):                     # operator Ctrl-C must still abort
        log.record(action="x", target="t", outcome="allow")


def test_main_log_durable_even_when_keyboardinterrupt_propagates(tmp_path):
    p = tmp_path / "a.jsonl"

    def ki_shipper(head):
        raise KeyboardInterrupt

    log = audit.AuditLog(path=p, anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=ki_shipper))
    with pytest.raises(KeyboardInterrupt):
        log.record(action="x", target="t", outcome="allow")
    assert len(_entries(p)) == 1   # the audited record landed (durable) before the interrupt


# ----- Fix B/C: append robustness on a corrupt/torn tail -----
def test_append_after_stripped_trailing_newline_verifies_ok(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    log.record(action="a", target="t1", outcome="allow")
    log.record(action="b", target="t2", outcome="allow")
    raw = p.read_text(encoding="utf-8")
    assert raw.endswith("\n")
    p.write_text(raw.rstrip("\n"), encoding="utf-8")   # torn flush / external tool dropped final newline
    audit.AuditLog(path=p).record(action="c", target="t3", outcome="allow")
    assert audit.AuditLog(path=p).verify().ok is True  # no concatenation; all 3 parse + chain
    assert len(_entries(p)) == 3


def test_append_after_torn_partial_tail_chains_from_last_good(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    log.record(action="a", target="t1", outcome="allow")
    e2 = log.record(action="b", target="t2", outcome="allow")
    with open(p, "a", encoding="utf-8") as f:          # simulate a crash mid-append
        f.write('{"action": "partial-tor')
    e3 = audit.AuditLog(path=p).record(action="c", target="t3", outcome="allow")
    assert e3["seq"] == 3                               # no genesis reset, no duplicate seq=1
    assert e3["prev_hash"] == e2["entry_hash"]          # chains from the last GOOD entry
    last_line = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()][-1]
    assert json.loads(last_line)["seq"] == 3            # new entry on its own line, not welded


# ----- Fix D: persistent-failure gap markers coalesce to one per streak -----
def test_persistent_anchor_failure_coalesces_gap_markers(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p,
                         anchor=audit.Anchor(every_n=1, every_minutes=0, shipper=RaisingShipper()))
    for i in range(5):
        log.record(action="op", target=f"t{i}", outcome="allow")
    markers = [e for e in _entries(p) if e["action"] == "audit.anchor"]
    assert len(markers) == 1        # one marker per failure-streak, not one per failed attempt
    assert log.anchor_gap is True


# ----- Fix E: egress guard hardened against alias / from-import / native-exec bypasses -----
def test_egress_scan_flags_aliased_socket_connect():
    assert _egress_offenders("import socket as s\ns.connect(('evil', 80))")


def test_egress_scan_flags_from_import_socket_create_connection():
    assert _egress_offenders("from socket import create_connection\ncreate_connection(('e', 80))")


def test_egress_scan_flags_subprocess_and_os_system():
    assert _egress_offenders("import subprocess\nsubprocess.run(['curl', 'http://x'])")
    assert _egress_offenders("import os\nos.system('curl http://x')")


def test_egress_scan_allows_legit_socket_and_os_use():
    assert _egress_offenders("import socket\nsocket.gethostname()") == []
    assert _egress_offenders("import os\nos.environ.get('X')\nx = os.SEEK_END") == []


def test_egress_scan_flags_os_alias_and_from_import():
    assert _egress_offenders("import os as o\no.system('evil')")
    assert _egress_offenders("from os import system, popen\nsystem('evil')")
    assert _egress_offenders("from os import system as run\nrun('evil')")


def test_egress_scan_flags_dynamic_import_vectors():
    assert _egress_offenders("__import__('evil')")
    assert _egress_offenders("import importlib\nimportlib.import_module('evil')")
    assert _egress_offenders("from importlib import import_module\nimport_module('evil')")
    assert _egress_offenders("import importlib.util\nimportlib.util.spec_from_file_location('x', '/tmp/evil.py')")
    assert _egress_offenders("from importlib.util import spec_from_file_location\nspec_from_file_location('x', '/tmp/evil.py')")
    # ``import importlib`` alone makes ``importlib.util`` reachable.
    assert _egress_offenders("import importlib\nimportlib.util.spec_from_file_location('x', '/tmp/evil.py')")


def test_egress_scan_allows_local_agent_shield_import_module():
    # PEP-562 lazy submodule loading intentionally uses importlib.import_module.
    # Both a plain constant and a "agent_shield." + name BinOp must be whitelisted.
    assert _egress_offenders("import importlib\nimportlib.import_module('agent_shield.bash_guard')") == []
    assert _egress_offenders("def __getattr__(name):\n    import importlib\n    return importlib.import_module('agent_shield.' + name)") == []


def test_egress_scan_allows_importlib_metadata():
    # The package uses importlib.metadata.version() for version resolution; that
    # is read-only and must not be flagged.
    assert _egress_offenders("from importlib.metadata import version\nversion('agent-shield')") == []
    assert _egress_offenders("import importlib.metadata\nimportlib.metadata.version('agent-shield')") == []


# ----- Fix F: mutation-killing regression tests for under-covered branches -----
def test_verify_detects_broken_prev_hash_link(tmp_path):
    # Graft a row: bogus prev_hash but a VALID recomputed entry_hash and intact seq,
    # so ONLY the prev_hash chain-link check can catch it (isolates that branch).
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(4):
        log.record(action="x", target=f"t{i}", outcome="allow")
    lines = p.read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[1])
    e["prev_hash"] = "f" * 64
    e["entry_hash"] = audit._hash_entry({k: v for k, v in e.items() if k != "entry_hash"})
    lines[1] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = log.verify()
    assert r.ok is False
    assert r.reason == "broken chain link"
    assert r.broken_at == 2


def test_verify_reason_and_broken_at_for_edit(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")
    lines = p.read_text(encoding="utf-8").splitlines()
    e = json.loads(lines[1])
    e["outcome"] = "deny"
    lines[1] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = log.verify()
    assert r.ok is False
    assert r.reason == "entry hash mismatch"
    assert r.broken_at == 2


def test_verify_reason_and_broken_at_for_deletion(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(4):
        log.record(action="x", target=f"t{i}", outcome="allow")
    lines = p.read_text(encoding="utf-8").splitlines()
    del lines[1]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = log.verify()
    assert r.ok is False
    assert r.reason == "seq out of order"
    assert r.broken_at == 2


def test_verify_detects_unparseable_line(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[1] = "{ this is not valid json"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = log.verify()
    assert r.ok is False
    assert r.broken_at == 2
    assert r.reason == "unparseable line"


def test_noop_anchor_warns_once_and_never_raises(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    # Anchor attached with NEITHER shipper NOR local_path -> no-op (never network, never raise)
    log = audit.AuditLog(path=p, anchor=audit.Anchor(every_n=1, every_minutes=0))
    for i in range(3):
        assert log.record(action="x", target=f"t{i}", outcome="allow") is not None
    assert capsys.readouterr().err.lower().count("no-op") == 1   # warn-once across records
    assert log.verify().ok is True
    assert {f.name for f in tmp_path.iterdir()} == {"a.jsonl"}   # no anchor artifact created


def test_base_field_defaults_when_env_unset(tmp_path, monkeypatch):
    for var in ("AGENT_SHIELD_ACTOR", "AGENT_SHIELD_ROLE", "AGENT_SHIELD_SESSION", "AGENT_SHIELD_MACHINE"):
        monkeypatch.delenv(var, raising=False)
    e = audit.AuditLog(path=tmp_path / "a.jsonl").record(action="x", target="t", outcome="allow")
    assert e["actor"] == "agent"
    assert e["role"] == "unknown"
    assert e["session"] == ""
    assert e["machine"]   # non-empty (socket.gethostname)


def test_env_fallback_and_caller_override(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SHIELD_ACTOR", "envactor")
    log = audit.AuditLog(path=tmp_path / "a.jsonl")
    assert log.record(action="x", target="t", outcome="allow")["actor"] == "envactor"      # env fallback
    assert log.record(action="x", target="t", outcome="allow", actor="callerwins")["actor"] == "callerwins"


# ----- Round-2 regression fixes: the tail cache must not outrun on-disk reality -----
def test_cache_invalidated_on_external_truncation(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")
    open(p, "w", encoding="utf-8").close()   # external copytruncate of a live writer's file
    e = log.record(action="after-rotate", target="t", outcome="allow")
    assert e["seq"] == 1                       # fresh start, NOT a stale seq=4 onto an empty file
    assert e["prev_hash"] == audit.GENESIS
    assert log.verify().ok is True             # no false TAMPER


def test_cache_invalidated_on_external_deletion(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    for i in range(3):
        log.record(action="x", target=f"t{i}", outcome="allow")
    p.unlink()
    e = log.record(action="after-delete", target="t", outcome="allow")
    assert e["seq"] == 1
    assert e["prev_hash"] == audit.GENESIS
    assert log.verify().ok is True


def test_warm_instance_torn_tail_does_not_weld(tmp_path):
    p = tmp_path / "a.jsonl"
    log = audit.AuditLog(path=p)
    log.record(action="a", target="t1", outcome="allow")
    e2 = log.record(action="b", target="t2", outcome="allow")
    with open(p, "a", encoding="utf-8") as f:   # a torn partial line appears under the LIVE writer
        f.write('{"action": "partial-tor')
    e3 = log.record(action="c", target="t3", outcome="allow")   # SAME warm instance (stale cache)
    assert e3["seq"] == 3
    assert e3["prev_hash"] == e2["entry_hash"]   # chains from last good, not from a phantom
    last_line = [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()][-1]
    assert json.loads(last_line)["seq"] == 3     # on its own line — not welded onto the fragment


# ----- Option A: opt-in remote-anchoring recipe (BYO-shipper) + risk guide -----
def test_remote_anchor_recipe_builds_correct_request():
    import importlib.util
    recipe = _SHIELD_ROOT / "examples" / "remote_anchor_shipper.py"
    assert recipe.exists()
    spec = importlib.util.spec_from_file_location("_recipe_remote_anchor", recipe)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # importing must NOT make any network call
    head = audit.AnchorHead(seq=7, entry_hash="a" * 64, ts="2026-06-14T00:00:00+00:00")
    req = mod.build_anchor_request("https://notary.example/anchor", head)
    assert req.full_url == "https://notary.example/anchor"
    assert req.get_method() == "POST"
    assert json.loads(req.data.decode("utf-8")) == {
        "seq": 7, "entry_hash": "a" * 64, "ts": "2026-06-14T00:00:00+00:00"}
    assert req.get_header("Content-type") == "application/json"


def test_remote_anchoring_guide_exists_with_risk_disclosures():
    guide = _SHIELD_ROOT / "docs" / "REMOTE_ANCHORING.md"
    assert guide.exists()
    text = guide.read_text(encoding="utf-8").lower()
    for phrase in ("bring your own shipper", "never phones home", "independent", "synchronous"):
        assert phrase in text, f"risk guide missing disclosure: {phrase}"


# Pin the HONEST tamper-evidence
# limitation the docs now state — verify() proves internal chain consistency only;
# it CANNOT detect a from-genesis (or from-last-anchor) rewrite into a fresh, valid
# chain. That is exactly why external anchoring exists, and why the unanchored tail
# (everything since the last anchor) is forgeable. The doc note in AUDIT_SCHEMA.md
# ("Blind spot — the unanchored tail") must stay true; this test fails if verify()
# ever starts (incorrectly) claiming to detect a genesis rewrite on its own.
def test_verify_cannot_detect_full_genesis_rewrite(tmp_path):
    log, p = _make_log(tmp_path, 4)
    assert log.verify().ok is True

    # Attacker forges a completely fresh, internally-valid chain elsewhere…
    forged = audit.AuditLog(path=tmp_path / "forged.jsonl")
    for i in range(4):
        forged.record(action="x", target=f"FORGED{i}", outcome="allow")
    forged_text = (tmp_path / "forged.jsonl").read_text(encoding="utf-8")

    # …and overwrites the real log with it. The CONTENT is fabricated, but the
    # hash chain is internally consistent, so local verify() still passes — only
    # an external anchor (a head copied out of the attacker's reach) catches this.
    p.write_text(forged_text, encoding="utf-8")
    r = log.verify()
    assert r.ok is True, "verify() is tamper-EVIDENT, not tamper-resistant: a genesis rewrite is undetectable by verify() alone"
    assert r.count == 4
    assert "FORGED0" in p.read_text(encoding="utf-8")
