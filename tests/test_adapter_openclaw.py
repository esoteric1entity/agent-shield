"""G4: the OpenClaw before_tool_call adapter maps the neutral core -> BeforeToolCallResult."""
import io
import json

from agent_shield.adapters import openclaw
from agent_shield._result import GuardResult


def _bash_event(cmd: str) -> dict:
    return {"toolName": "bash", "params": {"command": cmd}}


def test_decide_command_denies_destructive():
    assert openclaw.decide(_bash_event("rm -rf /")).decision == "deny"


def test_decide_command_allows_safe():
    assert openclaw.decide(_bash_event("ls -la")).decision == "allow"


def test_decide_path_from_derived_paths():
    event = {"toolName": "write_file", "params": {}, "derivedPaths": ["/home/user/.claude/settings.json"]}
    assert openclaw.decide(event).decision == "deny"


def test_extract_non_dict_params_does_not_raise():
    # "params" is truthy but not a dict — _extract must fail open, not raise.
    assert openclaw._extract({"params": "not-a-dict"}) == (None, None)
    assert openclaw._extract({"params": ["x"]}) == (None, None)


def test_decide_non_dict_params_allows():
    assert openclaw.decide({"toolName": "Bash", "params": "x"}).decision == "allow"


def test_format_deny_is_terminal_block():
    resp = openclaw.format_response(GuardResult("deny", "destructive command"))
    assert resp == {"block": True, "blockReason": "destructive command"}


def test_format_ask_is_require_approval():
    resp = openclaw.format_response(GuardResult("ask", "confirm this"))
    approval = resp["requireApproval"]
    assert approval["description"] == "confirm this"
    assert approval["severity"] == "warning"
    assert approval["allowedDecisions"] == ["allow-once", "deny"]


def test_format_allow_is_empty():
    assert openclaw.format_response(GuardResult("allow", "")) == {}


def test_main_reads_event_and_emits_block(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_bash_event("rm -rf /"))))
    rc = openclaw.main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["block"] is True


def test_main_unparseable_is_allow(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("not json{{"))
    rc = openclaw.main([])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {}


def test_main_oversize_input_asks(monkeypatch, capsys):
    from agent_shield import bash_guard
    huge = "x" * (bash_guard._MAX_READ_BYTES + 1)
    monkeypatch.setattr("sys.stdin", io.StringIO(huge))
    rc = openclaw.main([])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert "requireApproval" in out  # oversize -> conservative ask, not a trusted parse


def test_main_normal_event_still_allows(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"toolName": "bash", "params": {"command": "ls -la"}})))
    rc = openclaw.main([])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {}
