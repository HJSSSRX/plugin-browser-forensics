from __future__ import annotations

"""browser-forensics Cell — tests."""

from plugin import BrowserForensicsPlugin


def test_plugin_registers_tools():
    plugin = BrowserForensicsPlugin()
    tools = plugin.register_tools()
    assert len(tools) >= 1
    assert all(t.name for t in tools)
    assert all(t.domain for t in tools)
    assert all(t.risk_level in ("LOW", "MEDIUM", "HIGH") for t in tools)


def test_plugin_metadata():
    plugin = BrowserForensicsPlugin()
    assert plugin.name == "browser-forensics"
    assert plugin.version
    assert plugin.domain == "forensics"
