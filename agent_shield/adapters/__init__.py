"""Per-harness adapters: translate a harness event <-> the neutral decision core.

The decision logic lives in the harness-free core (bash_guard.check_command,
write_guard.check_path, ...). Each adapter is a thin, stateless translation layer.
"""
